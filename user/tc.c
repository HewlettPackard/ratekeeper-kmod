/*
 * Copyright (c) 2015 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <errno.h>
#include <fcntl.h>

#include "util.h"
#include "tc.h"
#include "ifcache.h"

extern struct ifcache *ifcache_root;

extern FILE *RKLOGFILE;

/* rtnl & htb rate table calculation functions */
#include <linux/pkt_sched.h>
#include <net/if.h>
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static struct sockaddr_nl tc_nladdr;
static int                tc_sock;
static double             tick_usec;
static int                tc_ifindex = 0; /* ifindex of iface with htb
					   * classes that throttle
					   * vnics. ifb2 by default */
void tc_setup() {
	FILE *fp;
	unsigned clock_res;
	unsigned t2us;
	unsigned us2t;

	/* rate table calc parameters */
	fp = fopen("/proc/net/psched", "r");
	if (fp == NULL)
		eexit("could not get psched values");

	if (fscanf(fp, "%08x%08x%08x", &t2us, &us2t, &clock_res) != 3)
		eexit("could not get psched values");
	fclose(fp);

	tick_usec = ((double)t2us / us2t) *
		((double)clock_res / 1000000.0);

	/* nladdr for  */
	memset(&tc_nladdr, 0, sizeof(tc_nladdr));
	tc_nladdr.nl_family = AF_NETLINK;
	tc_nladdr.nl_pid    = 0;
	tc_nladdr.nl_groups = 0;

	/* open rtnl socket */
	if ((tc_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
		eexit("could not open rtnl sock");

	if (bind(tc_sock,(struct sockaddr*)&tc_nladdr,sizeof(tc_nladdr)) < 0)
		eexit("could not bind rtnl sock");

	if (fcntl(tc_sock, F_SETFD, fcntl(tc_sock,F_GETFD,0)|O_NONBLOCK) < 0)
		eexit("could not set tc_sock to nonblock mode");
}

static void tc_add_rtattr(struct nlmsghdr *n, int type, void *data, int attr_len)
{
	struct rtattr *rta;
	int len = RTA_LENGTH(attr_len);

	rta = (void*) NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, attr_len);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

static inline unsigned tc_xmittime(unsigned rate, unsigned size)
{
	return ((unsigned)(1000000*(double)size/rate))*tick_usec;
}

static int tc_calc_rtab(struct tc_ratespec *r, __u32 *rtab, unsigned mtu)
{
	int i;
	int cell_log = 0;

	/* cell_log specify rtable pkt resolution, default to 8 pkts
	 * with mtu = 1500bytes */
	while ((mtu >> cell_log) > 255)
		cell_log++;

	for (i=0; i<256; i++)
		rtab[i] = tc_xmittime(r->rate, (i + 1) << cell_log);

	r->cell_align = -1;
	r->cell_log   = cell_log;
	return cell_log;
}

/* End: rtnl & htb rate table calculation functions */

/* TC control */
/* Qdisc management functions */
static int qdisc_exists(char *nic, char *qdisc_name, unsigned int h_major,
                        unsigned int h_minor)
{
	char handle[16];

	if (h_minor == 0)
		sprintf(handle, "%x: ", h_major);
	else
		sprintf(handle, "%x:%x", h_major, h_minor);

	return (prun(qdisc_name, handle,"tc qdisc show dev %s", nic));
}

static void tc_qdisc_add_htb(char *nic)
{
    run("tc qdisc add dev %s root handle 1: htb default 0 r2q 1000", nic);
}


static void tc_qdisc_add_ingress(char *nic)
{
    run("tc qdisc add dev %s ingress", nic);
}

static void tc_qdisc_del(char *nic, long h_major)
{
	char handle[16];

	if (h_major != 0xFFFF)
		sprintf(handle, "root");
	else
		sprintf(handle, "ingress");

	run("tc qdisc del dev %s %s", nic, handle);
}

/* Class management functions */
static int class_exists(char *nic, char *class_name, unsigned int h_major,
                        unsigned int h_minor)
{
	char handle[16];

	/* This function is only used to check if a leaf class exist, and
	   leaf classes are identified using the vlan_id with a 0x8000 mask */
	h_minor = 0x8000 | (0xFFF & h_minor);
	sprintf(handle, "%x:%x", h_major, h_minor);

	return(prun(class_name, handle, "tc class show dev %s", nic));
}


/* This function creates both the main htb class and leaf htb classes,
   which are related to one of the vms. The parent_id determines if
   this is a leaf class or not. Leaf classes are assigned classids
   using the vlan_id with a 0x8000 mask */
static void tc_class_add(char *nic, int min, int max, int class_id,
                         int parent_id, struct tc_options *tco)
{
	/* If parent id is not 0, then this * class
	 * is the main htb class and should not be
	 * considered as a leaf class  */
	if (parent_id != 0)
		class_id = 0x8000 | (0xFFF & class_id);

	run("tc class add dev %s parent 1:%x classid 1:%x "
	    "htb rate %dmbit ceil %dmbit burst %dkb cburst %dkb"
	    " mtu 12000",
	    nic, parent_id, class_id, min, max, tco->burst, tco->burst);
}

static void tc_class_change(char *nic, int min, int max, int vlan_id,
                            struct tc_options *tco)
{
	run("tc class change dev %s classid 1:%x htb rate %dmbit "
	    "ceil %dmbit burst %dkb cburst %dkb"
	    " mtu 12000", 
	    nic, 0x8000 | (0xFFF & vlan_id),
	    min, max, tco->burst, tco->burst);
}

static void tc_root_class_change(char *nic, int min, int max, int classid,
                                 struct tc_options *tco)
{
	run("tc class change dev %s classid 1:%x htb rate %dmbit "
	    "ceil %dmbit burst %dkb cburst %dkb" 
	    " mtu 12000", 
	    nic, classid,
	    min, max, tco->burst, tco->burst);
}

static void tc_class_change_kbit(char *nic, int min, int max, int vlan_id,
                                 struct tc_options *tco)
{
	run("tc class change dev %s classid 1:%x htb rate %dkbit "
	    "ceil %dkbit burst %dkb cburst %dkb"
	    " mtu 12000", 
	    nic, 0x8000 | (0xFFF & vlan_id),
	    min, max, tco->burst, tco->burst);
}

static void tc_class_del(char *nic, int vlan_id)
{
	run("tc class del dev %s classid 1:%x", nic, 0x8000 | (0xFFF & vlan_id));
}

/* Filter management functions */

static int filter_exists_fw(char *nic, unsigned int vlan_id)
{
	char filterid[32];

	sprintf(filterid, "1:%x", 0x8000 | (0xFFF & vlan_id));
	return (prun("fw", filterid, "tc filter show dev %s", nic));
}

static void tc_filter_add_redirect_vnic(char *nic_from,
					char *nic_to,
					int vlan_id)
{
	run("tc filter add dev %s parent FFFF: proto all prio 255 "
	    "handle 800::%x u32 match u32 0 0 "
        //"action mirred egress intercept dev lo " /*MARIO*/
	    "action xt -j MARK --set-mark %d "
	    "action mirred egress redirect dev %s",
	    nic_from, 0xFFF & vlan_id, vlan_id, nic_to);
}

static void tc_filter_add_redirect(char *nic_from, char *nic_to,
                                   unsigned int parent, int vlan_id)
{
	if (parent == 0xFFFF)
		/* The rule "intercept dev lo" will prevent RK from
		 * stealing this pkt here.  This should only happen at
		 * VM ingress */
		run("tc filter add dev %s parent FFFF: proto all prio 255 "
			"handle 800::%x u32 match u32 0 0 "
			//"action mirred egress intercept dev lo "  /*MARIO*/
			"action xt -j MARK --set-mark %d "
			"action mirred egress redirect dev %s",
			nic_from, 0xFFF & vlan_id, vlan_id, nic_to);
	else
		run("tc filter add dev %s parent %x: proto all prio 255 "
			"handle 800::%x u32 match u32 0 0 "
			"action mirred egress intercept dev lo "  /*MARIO*/
			"action xt -j MARK --set-mark %d "
			"action mirred egress redirect dev %s",
			nic_from, parent, 0xFFF & vlan_id, vlan_id, nic_to);
}

/* u32 filter identifiers follows the format hhh:hhh:hhh where 'h' is
 * a hexadecimal number. The first 6 hexa values are assigned
 * automatically by the kernel, and are 800:0. The last 3 values are
 * used as the vlan identifier. The flowid is used to redirect pkts to
 * classes, and its value must match a classid of one htb leaf
 * class. */
static void tc_filter_add_fw(char *nic, int  vlan_id)
{
	run("tc filter add dev %s proto all prio 255 parent 1: "
		"handle %d  fw classid 1:%x",
		nic, vlan_id, 0x8000 | (0xFFF & vlan_id));
}

static void tc_filter_add_intercept(char *vnic)
{
	run("tc filter add dev %s proto all prio 255 parent 1: u32 "
		"match u32 0 0 flowid 1:1 "
		"action mirred egress intercept dev %s"
		, vnic, vnic);
}

static void tc_filter_del_fw(char *nic, int vlan_id)
{
    run("tc filter del dev %s proto all prio 255 parent 1: "
        " handle %d fw", nic, vlan_id);
}

/* Get current speed of an network interface  */
int get_nic_speed(char *nic)
{
	int sock;
	struct ifreq ifr;
	struct ethtool_cmd edata;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0))  < 0)
		return -1;

	strncpy(ifr.ifr_name, nic, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char*)&edata;

	edata.cmd = ETHTOOL_GSET;

	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
		edata.speed = -1;
	close(sock);
	return edata.speed;
}

/* Get hwaddr of an network interface  */
int get_nic_hwaddr(char *nic, char *mac)
{
	int sock, ret;
	struct ifreq ifr;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0))  < 0)
		return -1;

	strncpy(ifr.ifr_name, nic, sizeof(ifr.ifr_name));

	if ((ret = ioctl(sock, SIOCGIFHWADDR, &ifr)) >= 0)
		memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(sock);
	return (ret < 0);
}


static int configure_ifb(void)
{
	run("modprobe ifb numifbs=4");
	run("ifconfig ifb0 up");
	run("ifconfig ifb1 up");
	run("ifconfig ifb2 up");
	run("ifconfig ifb3 up");
	return (prun("ifb0:", "UP", "ip link") &&
		prun("ifb1:", "UP", "ip link") &&
		prun("ifb2:", "UP", "ip link") &&
		prun("ifb3:", "UP", "ip link"));
}

#ifdef RK_USE_TNIC
/* Configure rate controllers and rate meters that handle local
 * (server) traffic. */
static void tc_vnic_set(char *vnic, int ifindex, int max,
			int link_max, struct tc_options *tco)
{
	/* VM Ingress */
	if (qdisc_exists(vnic, "htb", 1, 0))
		tc_qdisc_del(vnic, 1);
	tc_qdisc_add_htb(vnic);
	tc_class_add(vnic, max, max, 1, 0, tco);
	tc_filter_add_intercept(vnic);

	/* VM Egress */
	if (qdisc_exists(vnic, "ingress", 0xFFFF, 0))
		tc_qdisc_del(vnic, 0xFFFF);
	tc_qdisc_add_ingress(vnic);
	tc_filter_add_redirect_vnic(vnic, "ifb2", ifindex);

	/* Root */
	if (!qdisc_exists("ifb2", "htb", 1, 0)) {
		tc_qdisc_add_htb("ifb2");
		tc_class_add("ifb2", link_max, link_max, 1, 0, tco);
	}

	/* Leaf */
	if (!class_exists("ifb2", "htb", 1, ifindex))
		tc_class_add("ifb2", max, max, ifindex, 1, tco);
	else
		tc_class_change("ifb2", max, max, ifindex, tco);

	if (!filter_exists_fw("ifb2", ifindex))
		tc_filter_add_fw("ifb2", ifindex);
}

#else
static void tc_vnic_notnic_set(char *vnic, int ifindex, int min, int max,
			       int link_max, struct tc_options *tco)
{
	/* VM Ingress */
	if (qdisc_exists(vnic, "htb", 1, 0))
		tc_qdisc_del(vnic, 1);
	tc_qdisc_add_htb(vnic);
	tc_filter_add_redirect(vnic, "ifb3", 1, ifindex);


	if (!qdisc_exists("ifb3", "htb", 1, 0)) {
		tc_qdisc_add_htb("ifb3");
		tc_class_add("ifb3", link_max, link_max, 1, 0, tco);
	}

	if (!class_exists("ifb3", "htb", 1, ifindex))
		tc_class_add("ifb3", min, max, ifindex, 1, tco);
	else
		tc_class_change("ifb3", min, max, ifindex, tco);

	if (!filter_exists_fw("ifb3", ifindex))
		tc_filter_add_fw("ifb3", ifindex);

	/* VM Egress */
	if (qdisc_exists(vnic, "ingress", 0xFFFF, 0))
		tc_qdisc_del(vnic, 0xFFFF);
	tc_qdisc_add_ingress(vnic);
	tc_filter_add_redirect_vnic(vnic, "ifb2", ifindex);

	if (!qdisc_exists("ifb2", "htb", 1, 0)) {
		tc_qdisc_add_htb("ifb2");
		tc_class_add("ifb2", link_max, link_max, 1, 0, tco);
	}

	if (!class_exists("ifb2", "htb", 1, ifindex))
		tc_class_add("ifb2", min, max, ifindex, 1, tco);
	else
		tc_class_change("ifb2", min, max, ifindex, tco);

	if (!filter_exists_fw("ifb2", ifindex))
		tc_filter_add_fw("ifb2", ifindex);
}
#endif


/**
 * Set vnic rate using rtnl message.
 *
 * @vnic   : vnic name
 * @ifindex: vnic ifindex
 * @rate   : target rate, in mbps
 * @tco    : global tc options
 */
static inline void tc_vnic_set_rate_kbit(char *vnic, int ifindex, int min, int rate,
                                         struct tc_options *tco)
{
	if (rate < min) {
		min = rate;
 	}
	if (class_exists("ifb2", "htb", 1, ifindex)) {
	     tc_class_change_kbit("ifb2", min, rate, ifindex, tco);
	     return;
	}

	return;

	/* The following code to change the rate rtnl is correct and
	 * it changes the rate correctly when invoked. The problem
	 * with it is that the following call of epoll_wait returns -1
	 * and set errno to EBADF. TODO: Why!? This code has nothing
	 * to do with epoll. Maybe the iov calls have (?). The task
	 * here is to understand what is the happening and how this
	 * code affects epoll. */

	static struct {
		struct nlmsghdr n;
		struct tcmsg    t;
		char            data[1024];
		/* data is composed by a couple of rtattrs that won't
		 * change, but because rtattr structure can change and
		 * because of byte alignment in different kernels, I'm
		 * computing the set of rtattrs everytime using
		 * tc_add_rtattr */
	} r;
	static struct iovec iov = {
		.iov_base = (void*) &r.n,
	};
	static struct msghdr msg = {
		.msg_name = &tc_nladdr,
		.msg_namelen = sizeof(tc_nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct tc_htb_opt cl_opt; /* htb class parameters */
	struct rtattr *tc_rtattr;
	unsigned rtab[256], ctab[256];
	int ret;

	if (tc_ifindex <= 0)
		tc_ifindex = if_nametoindex("ifb2");

	/* RTNL attributes */
	r.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	r.n.nlmsg_flags = NLM_F_REQUEST;
	r.n.nlmsg_type  = RTM_NEWTCLASS;

	/* Qdisc/tc attributes  */
	r.t.tcm_handle  = 0x10000 | ((0xFFF & ifindex)|0x8000);
	r.t.tcm_parent  = 0x10001;      /* the parent class is always 1:1 */
	r.t.tcm_ifindex = tc_ifindex;   /* need to get ifb2 ifindex */
	r.t.tcm_family  = AF_NETLINK;

	/* Compute rate info */
	memset(&cl_opt, 0, sizeof(cl_opt));
	rate *= 125; /* convert rate from kbit/s to bytes/s */
	cl_opt.rate.rate = cl_opt.ceil.rate = rate;
	cl_opt.buffer = cl_opt.cbuffer = tc_xmittime(rate, tco->burst * 1024);

	tc_calc_rtab(&cl_opt.rate, rtab, 1500);
	tc_calc_rtab(&cl_opt.ceil, ctab, 1500);

	/* Assembling nlmsg with rtnl_attrs */
	tc_add_rtattr(&r.n, TCA_KIND, "htb", 4);
	tc_rtattr = (void*) NLMSG_TAIL(&r.n);
	tc_add_rtattr(&r.n, TCA_OPTIONS, NULL, 0);
	tc_add_rtattr(&r.n, TCA_HTB_PARMS, &cl_opt, sizeof(cl_opt));
	tc_add_rtattr(&r.n, TCA_HTB_RTAB, rtab, 256*sizeof(unsigned));
	tc_add_rtattr(&r.n, TCA_HTB_CTAB, ctab, 256*sizeof(unsigned));
	tc_rtattr->rta_len = (void *) NLMSG_TAIL(&r.n) - (void *) tc_rtattr;

	/* Sending nlmsg */
	iov.iov_len  = r.n.nlmsg_len;


	while (((ret = sendmsg(tc_sock, &msg, 0)) < 0) && errno == EAGAIN);
	if (ret < 0)
		eexit("could not send rtnl msg"); /* TODO: treat this
						   * error instead of
						   * exitting */
}

#ifdef RK_USE_TNIC
static void tc_vnic_unset(char *vnic, int ifindex)
{
	fprintf(RKLOGFILE, "tc_vnic_unset %s %d\n", vnic, ifindex);
	if (qdisc_exists(vnic, "htb", 1, 0))
		tc_qdisc_del(vnic, 1);
	if (qdisc_exists(vnic, "ingress", 0xFFFF, 0))
		tc_qdisc_del(vnic, 0xFFFF);
	if (class_exists("ifb2", "htb", 1, ifindex)) {
		tc_filter_del_fw("ifb2", ifindex);
		tc_class_del("ifb2", ifindex);
	}
}

#else
static void tc_vnic_notnic_unset(char *vnic, int ifindex)
{
	fprintf(RKLOGFILE, "tc_vnic_unset %s %d\n", vnic, ifindex);
	if (qdisc_exists(vnic, "htb", 1, 0))
		tc_qdisc_del(vnic, 1);
	if (qdisc_exists(vnic, "ingress", 0xFFFF, 0))
		tc_qdisc_del(vnic, 0xFFFF);
	if (class_exists("ifb2", "htb", 1, ifindex)) {
		tc_filter_del_fw("ifb2", ifindex);
		tc_class_del("ifb2", ifindex);
	}
	if (class_exists("ifb3", "htb", 1, ifindex)) {
		tc_filter_del_fw("ifb3", ifindex);
		tc_class_del("ifb3", ifindex);
	}
}
#endif

/* Configure rate controllers and rate meters that handle
 * remote (network) traffic. This method  */
static void tc_tnic_set(char *tnic, int min, int max, int vlan_id,
                        struct tc_options *tco)
{
	/* Egress */
	if (qdisc_exists(tnic, "htb", 1, 0))
		tc_qdisc_del(tnic, 1);
	tc_qdisc_add_htb(tnic);
	tc_filter_add_redirect(tnic, "ifb0", 1, vlan_id);

	if (!qdisc_exists("ifb0", "htb", 1, 0)) {
		tc_qdisc_add_htb("ifb0");
		tc_class_add("ifb0", max, max, 1, 0, tco);
	}
	if (!class_exists("ifb0", "htb", 1, vlan_id))
		tc_class_add("ifb0", min, max, vlan_id, 1, tco);
	else
		tc_class_change("ifb0", min, max, vlan_id, tco);
	if (!filter_exists_fw("ifb0", vlan_id))
		tc_filter_add_fw("ifb0", vlan_id);

	/* Ingress */
	if (qdisc_exists(tnic, "ingress", 0xFFFF, 0))
		tc_qdisc_del(tnic, 0xFFFF);
	tc_qdisc_add_ingress(tnic);
	tc_filter_add_redirect(tnic, "ifb1", 0xFFFF, vlan_id);

	if (!qdisc_exists("ifb1", "htb", 1, 0)) {
		tc_qdisc_add_htb("ifb1");
		tc_class_add("ifb1", max, max, 1, 0, tco);
	}
	if (!class_exists("ifb1", "htb", 1, vlan_id))
		tc_class_add("ifb1", min, max, vlan_id, 1, tco);
	else
		tc_class_change("ifb1", min, max, vlan_id, tco);
	if (!filter_exists_fw("ifb1", vlan_id))
		tc_filter_add_fw("ifb1", vlan_id);
}

#ifdef RK_USE_TNIC
static void tc_tnic_unset(int vlan_id)
{
	fprintf(RKLOGFILE, "tc_tnic_unset %d\n", vlan_id);
	/* Do not remove tnic redirect, because other VMs might be using it */

	/* Engress */
	if (filter_exists_fw("ifb0", vlan_id))
		tc_filter_del_fw("ifb0", vlan_id);
	if (class_exists("ifb0", "htb", 1, vlan_id))
		tc_class_del("ifb0", vlan_id);
	if (class_exists("ifb0", "htb", 1, vlan_id))
		tc_class_del("ifb0", vlan_id);

	/* Ingress */
	if (filter_exists_fw("ifb1", vlan_id))
		tc_filter_del_fw("ifb1", vlan_id);
	if (class_exists("ifb1", "htb", 1, vlan_id))
		tc_class_del("ifb1", vlan_id);
	if (class_exists("ifb1", "htb", 1, vlan_id))
		tc_class_del("ifb1", vlan_id);
}
#endif

void tc_update_ifbs(int link_max, struct tc_options *vnic_tco, struct tc_options *tnic_tco) {

	if (qdisc_exists("ifb0", "htb", 1, 0)) {
		tc_root_class_change("ifb0", link_max, link_max, 1, tnic_tco);
	}
	if (qdisc_exists("ifb1", "htb", 1, 0)) {
		tc_root_class_change("ifb1", link_max, link_max, 1, tnic_tco);
	}
	if (qdisc_exists("ifb2", "htb", 1, 0)) {
		tc_root_class_change("ifb2", link_max, link_max, 1, vnic_tco);
	}
	if (qdisc_exists("ifb3", "htb", 1, 0)) {
		tc_root_class_change("ifb3", link_max, link_max, 1, vnic_tco);
	}
}

#ifdef RK_USE_TNIC
void tc_update_tnic(struct rktnic *tnic, int link_max)
{
	int min;
	char tnic_name[IFNAMSIZ];

	if (!ifcache_index_to_name(tnic->ifindex, tnic_name))
		return -1;
	
	if (tnic->ti.min >= 0)
		min = tnic->ti.min;
	else
		min = 0;

	tc_default_options(&tnic->tco, link_max);
	tc_tnic_set(tnic_name, min, link_max, tnic->vnet_id, &tnic->tco);
}
#endif

/* Returns 0 if RCs were removed, returns 1 otherwise */
#ifdef RK_USE_TNIC
int tc_set(struct rkvnic *vnic, int link_max)
{
	int min, max, vnet_id;
	char vnic_name[IFNAMSIZ], tnic_name[IFNAMSIZ];
	struct rktnic *tnic = vnic->tnic;
 
	if (!configure_ifb())
		eexit("could not configure the ifb module");

	min      = vnic->ti.min;
	max      = vnic->ti.max;
	vnet_id  = tnic->vnet_id;

	/* TODO: lookup table for name resolution */
	if (!ifcache_index_to_name(vnic->ifindex, vnic_name) ||
	    !ifcache_index_to_name(tnic->ifindex, tnic_name))
		return -1;

	/* TNIC ceil will always be LINE RATE */
	/* if MIN > 0 and MAX > 0 => ok */
	/* if MIN = -1 and MAX = -1 => No control (remove RCs) */
	/* if MAX == -1 => remove RC from VNIC, still can have MIN on TNIC */
	/* if MIN == -1 => no MIN, set MIN to 0 (best effort), still can have MAX */
	if (min >= 0 || max >= 0) {
		if (min == -1)
			min = 0;
		/* fprintf(RKLOGFILE, "setting MIN=%d and MAX=%d for iface
		 * %s\n", min, max, vnic); */
		tc_vnic_set(vnic_name, vnic->ifindex, max, link_max, &vnic->tco);
		tc_tnic_set(tnic_name, min, link_max, vnet_id, &tnic->tco);
	}
	if (min == -1 && max == -1) {
		/* fprintf(RKLOGFILE, "removing RCs for iface %s\n", vnic); */
		tc_vnic_unset(vnic_name, vnic->ifindex);
		tc_tnic_unset(vnet_id);
		return 0;
	}
	return 1;
}

#else

int tc_set(struct rkvnic *vnic, int link_max)
{
	int min, max, vnet_id;
	char vnic_name[IFNAMSIZ], tnic_name[IFNAMSIZ];
 
	if (!configure_ifb())
		eexit("could not configure the ifb module");

	min      = vnic->ti.min;
	max      = vnic->ti.max;
	vnet_id  = vnic->vnet_id;

	/* TODO: lookup table for name resolution */
	if (!ifcache_index_to_name(vnic->ifindex, vnic_name))
		return -1;

	/* TNIC ceil will always be LINE RATE */
	/* if MIN > 0 and MAX > 0 => ok */
	/* if MIN = -1 and MAX = -1 => No control (remove RCs) */
	/* if MAX == -1 => remove RC from VNIC, still can have MIN on TNIC */
	/* if MIN == -1 => no MIN, set MIN to 0 (best effort), still can have MAX */
	if (min >= 0 || max >= 0) {
		if (min == -1)
			min = 0;
		/* fprintf(RKLOGFILE, "setting MIN=%d and MAX=%d for iface
		 * %s\n", min, max, vnic); */
		tc_vnic_notnic_set(vnic_name, vnic->ifindex, min, max, link_max, &vnic->tco);
	}
	if (min == -1 && max == -1) {
		/* fprintf(RKLOGFILE, "removing RCs for iface %s\n", vnic); */
		tc_vnic_notnic_unset(vnic_name, vnic->ifindex);
		return 0;
	}
	return 1;
}

#endif

void tc_set_rate(struct rkvnic *vnic)
{
	char vnic_name[IFNAMSIZ];

	if (!ifcache_index_to_name(vnic->ifindex, vnic_name))
		return;
	tc_vnic_set_rate_kbit(vnic_name, vnic->ifindex, 1000 * vnic->ti.min,
	                      vnic->rl_rate_kbit, &vnic->tco);
}

inline void tc_default_options(struct tc_options *tco, int max)
{
	if (tco->burst == 0) {
		tco->burst = max/2;
		if (tco->burst == 0)
			tco->burst = 1 << 10;
	}
	if (tco->mtu == 0)
		tco->mtu = 65;
	/* TODO: set queue size */
	if (tco->qsize == 0)
		tco->qsize = tco->mtu * 100;

	/* 64 KB burst */
	tco->burst = 64;
}


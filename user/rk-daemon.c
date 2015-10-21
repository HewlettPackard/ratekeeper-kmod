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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#include <net/ethernet.h>       /* for ether_header */

#include "../include/messaging_user.h"
#include "util.h"
#include "tc.h"
#include "rkvif.h"
#include "rkinc.h"
#include "ifcache.h"

#define ms(tv)             (tv.tv_sec*1000 + tv.tv_nsec/1000000)
#define mbps2bypus(s)      (s*0.125)
#define bypus2mbps(s)      (s/0.125)

/* fd of log file */
FILE *RKLOGFILE;

struct ifcache *ifcache_root = NULL;

/* rk-daemon monitored sockets */
enum {
	KERNEL_SOCK,
	RKCONFIG_SOCK,
	__RK_MAX_SOCKS,
};

struct rkd_msghandler {
	int            family_id;
	int            epoll_fd;
	int            socks[__RK_MAX_SOCKS];
	struct nl_sock *libnl_sock;
	char           mac[ETH_ALEN];        /* Source mac addr on
					      * feedback messages */
} mh;

static struct nla_policy rk_attr_policy[__RK_ATTR_MAX] = {
	[RK_ATTR_IFINDEX]       = { .type = NLA_U32 },
	[RK_ATTR_MONITOR_INDEX] = { .type = NLA_U32 },
	[RK_ATTR_RATE]          = { .type = NLA_U32 },
	[RK_ATTR_LIMIT]         = { .type = NLA_U32 },
	[RK_ATTR_PID]           = { .type = NLA_U32 },
	[RK_ATTR_STATS]         = { .type = NLA_UNSPEC },
	[RK_ATTR_RC]            = { .type = NLA_U32 },
	[RK_ATTR_INSTANCES]     = { .type = NLA_U32 },
	[RK_ATTR_CONGESTION_SEVERITY] = { .type = NLA_U32 },
	[RK_ATTR_SIZE_STATS]    = { .type = NLA_U32 },
	[RK_ATTR_IS_TNIC]       = { .type = NLA_U32 },
};

struct rkvnic *vnic_root   = NULL;
struct rktnic *tnic_root   = NULL;
struct rkinc  *rki_root    = NULL;

/* Ratekeeper daemon options */

/* max link rate used on TC rate limiters */
static int    rk_max_allocation = 1000;  /* In mbit/s */
/* max link rate used on RK kernel rate monitoring
   rk_highmark > rk_max_allocation such that we have some 
   headroom to detect misbevahing traffic */
static int    rk_highmark       = 1050;  /* In mbit/s */

/* vnic MAX rate multiplier used to program vnic rate monitor */
/* ensures there is a headroom. */
static double rk_vnic_headroom_factor = 1.05;

static int    rk_interval       = 500;   /* In miliseconds */
static int    rk_increase_kbit  = 40000; /* In kbps/interval */
static float  rk_decrease       = 0.05;  /* 0-1 range */
static int    rk_daemonize      = 1;

/* Number of instances available in the kernel */
static int    mon_instances = 16;

static int  kernel_setup();
static int  rkconfig_setup();
static int  epoll_setup();

static void usage();
static void parse_args(int argc, char **argv);

/* Call backs */
static int  rkd_kernel_cb(struct nl_msg *msg, void *arg);
static int  rkd_rkconfig_cb(int sock);

/* Helper functions to parse messages sent to and recv from rkconfig */
static int  rkdata2rkvif(struct rkdata *rkd, struct rkvnic *vnic);
static int  rkvif2rkdata(struct rkvnic *vnic, struct rkdata *rkd);

/* Increase and decrease functions */
static void rkd_increase_fn();
static void rkd_decrease_fn(int ifindex, unsigned int severity);

static int rkd_fb_send(int tnic_ifindex, unsigned char *dst_mac, unsigned int severity);
static void rkd_handle_congestion(int ifindex, unsigned int severity, unsigned char *mac);

/* Rate limiters and monitors management functions */
static int  rkd_set(struct rkvnic *vnic);
static void rkd_update_stats(char *buf, unsigned int size_stats);
static int  rkd_monitor_ctl(genl_command cmd, int p1, int p2, int p3);

static int  rkmsg_reply(int sock, struct sockaddr_in *to, rkd_rc rc);

static inline int rkd_monitor_set(int ifindex, int limit, int is_tnic);

int main(int argc, char **argv)
{
	struct epoll_event e[__RK_MAX_SOCKS];
	int ready, i, err;
	pid_t pid, sid;
	int wait;
	struct timespec now, prev;

	if (argc < 2)
		usage();
	parse_args(argc, argv);

	/* Creating the daemon subprocess */
	if (rk_daemonize) {
		pid = fork();
		if (pid < 0) eexit("Could not create daemon process");
		if (pid > 0) exit(0);
		umask(0);
		sid = setsid();
		if (sid < 0) eexit("Could not create a new session");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		RKLOGFILE = fopen("/var/log/ratekeeper", "w");
	}
	else
		RKLOGFILE = stdout;

	if (!RKLOGFILE) eexit("Could not open ratekeeper log file");
	tc_setup();

	memset(&mh, 0, sizeof(mh));
	if (kernel_setup())
		goto out;

	if (rkconfig_setup())
		goto rkconfig_err;

	if (epoll_setup() != 0)
		goto epoll_err;

	if (!rk_max_allocation && (rk_max_allocation = get_nic_speed(argv[1])) < 0)
		eexit("Could not get link speed of pnic to set up the "
		      "default max_allocation");
	if (get_nic_hwaddr(argv[1], mh.mac))
		eexit("Could not get pnic hw addr");

	/* the default headrooom for the vnic is 5% */
	rk_vnic_headroom_factor = 1.05;
	
	/* In the link, use the same headroom as in the vnic */  
	rk_highmark = rk_max_allocation * rk_vnic_headroom_factor;

	//fprintf(RKLOGFILE, "Ratekeeper: max_allocation = %d Mb/s , "
	//	"highmark = %d Mb/s vnic_headroom_factor=%lf\n", 
	//	rk_max_allocation, rk_highmark, rk_vnic_headroom_factor);
	//fflush(RKLOGFILE);

	wait = rk_interval;
	clock_gettime(CLOCK_MONOTONIC, &prev);
    	//fprintf(RKLOGFILE, "Before main rk-daemon loop...\n");
	//fflush(RKLOGFILE);
	while ((ready = epoll_wait(mh.epoll_fd, e, __RK_MAX_SOCKS, wait)) >= 0) {

		for (i = 0; i < ready; i++) {
			switch (e[i].data.u32) {

			case KERNEL_SOCK:
                		//fprintf(RKLOGFILE, "Kernel Sock call!\n");
                		//fflush(RKLOGFILE);
				if ((err = nl_recvmsgs_default(mh.libnl_sock)) < 0)
					WARN2("kernelsock recv err %d, errno %d\n",
						err, errno);
				break;

			case RKCONFIG_SOCK:
                		//fprintf(RKLOGFILE, "User Sock call!\n");
                		//fflush(RKLOGFILE);
				if ((err = rkd_rkconfig_cb(mh.socks[RKCONFIG_SOCK])) < 0)
					WARN2("rkconfigsock recv err %d, errno %d\n",
					      err, errno);
				break;

			default:
				WARN1("unknown sock %d returned by epoll\n",
				      e[i].data.u32);
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		wait = rk_interval - (ms(now)-ms(prev));
		if (wait <= 0) {
			wait = rk_interval;
			rkd_increase_fn();
			memcpy(&prev, &now, sizeof(struct timespec));
		}
	}
    	//fprintf(RKLOGFILE, "After main rk-daemon loop...");
	//fflush(RKLOGFILE);

	WARN("exiting...\n");
	close(mh.epoll_fd);
epoll_err:
	if (mh.socks[RKCONFIG_SOCK] > 0)
		close(mh.socks[RKCONFIG_SOCK]);
rkconfig_err:
	if (mh.socks[KERNEL_SOCK] > 0)
		close(mh.socks[KERNEL_SOCK]);
out:
	/* fclose(RKLOGFILE); */
	return 0;
}

#ifdef RK_USE_TNIC
static int rkd_rkconfig_cb(int sock)
{
	char buf[256];
	int err, rkmsglen;
	struct rkdata *rkd;
	struct rkmsg_limits *limits;
	int vnic_ifindex, tnic_ifindex;
	struct rkvnic *vnic;
	struct rktnic *tnic;
	struct sockaddr_in from;
	struct rkmsg_header *rkmsghdr;
	socklen_t len = sizeof(struct sockaddr_in);

	while ((err = recvfrom(sock, buf, 256, MSG_DONTWAIT,
			       (struct sockaddr *)&from, &len)) > 0) {
		rkmsghdr = (void *) buf;
		switch (ntohl(rkmsghdr->cmd)) {

		case RKMSG_SET:
			rkd = (void *) buf + sizeof(struct rkmsg_header);
			vnic_ifindex = ifcache_name_to_index(rkd->vnic);
			tnic_ifindex = ifcache_name_to_index(rkd->tnic);
			if ( (vnic_ifindex <= 0 ) || (tnic_ifindex <= 0 ) ){
				rkmsg_reply(sock, &from, RK_RC_ERR_IF);
				break;
			}
			vnic = rkvnic_find(vnic_ifindex, &vnic_root);
			tnic = rktnic_find(tnic_ifindex, &tnic_root);

			if ( vnic == NULL ) {     /* new vnic */
				vnic = rkvnic_add(vnic_ifindex, &vnic_root);
				if ( tnic == NULL )
					tnic = rktnic_add(tnic_ifindex, &tnic_root);
				/* add tnic ref count and link tnic to vnic */
				rk_tnic_get(tnic, vnic);
			} else {                  /* update existing vnic */
				/* tnic must exist and must be the same we used before */
				if ( (tnic == NULL) || (tnic != vnic->tnic) ) {
					rkmsg_reply(sock, &from, RK_RC_ERR_IF);
					break;
				}
				/* decrement previous vnic min rate from tnic */
				/* as we are going to add the new rate or remove
				   the vnic */
				rktnic_rate_dec(tnic, vnic->ti.min);
			}

			rkdata2rkvif(rkd, vnic);

			/* update tnic guarantee: it is the sum of guarantees of the 
			   associated vnics */
			if ( vnic->ti.min > 0 )
				rktnic_rate_inc(tnic, vnic->ti.min);

			/* Set up RCs and monitor */
			if (!rkd_set(vnic))
				rkvnic_del(vnic->ifindex, &vnic_root, &tnic_root);

			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("sendto() error, errno %d\n", errno);
			}

			break;

		case RKMSG_GET:
			/* Update vnic_ti.current stats */
			rkd_monitor_ctl(RK_CMD_GET_STATS, 0, 0, 0);
			/* BUG: the kernel could have replied with
			 * other stuff than the stats that we
			 * requested. TODO: figure out a way to make
			 * sure the kernel sent us back the stats we
			 * requested. */
			/* The reply of a RKMSG_GET consists of a set
			 * of RKMSG_GET msgs carrying one rkdata each
			 * followed by one RKMSG_REPLY indicating the
			 * end of the set */
			rkd = (void *) buf + sizeof(struct rkmsg_header);
			rkmsglen = sizeof(struct rkmsg_header)+
				sizeof(struct rkdata);
			for (vnic = vnic_root; vnic != NULL; vnic = vnic->hh.next) {
				rkmsghdr->cmd = htonl(RKMSG_GET);
				rkvif2rkdata(vnic,rkd);
				if (sendto(sock,buf,rkmsglen,0,
					   (struct sockaddr *)&from,len)<0) {
					WARN1("rkd_rkconfig_cb: sendto() "
					      "error, errno %d\n", errno);
				}
			}
			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("rkd_rkconfig_cb: sendto() error, "
				      "errno %d\n", errno);
			}
			break;

		case RKMSG_LIMITS:
			limits = (void *) buf + sizeof(struct rkmsg_header);
			rk_highmark = ntohl(limits->highmark);
			rk_max_allocation = ntohl(limits->max_allocation);
			rk_vnic_headroom_factor = ntohl(limits->vnic_headroom) * 0.001 + 1.0;
			fprintf(RKLOGFILE, "Setting ratekeeper link: max_allocation = %d Mb/s, "
				"highmark = %d Mb/s\n", rk_max_allocation, rk_highmark);
			fprintf(RKLOGFILE, "Setting ratekeeper vnic headroom factor: =%lf\n", 
				rk_vnic_headroom_factor); 
			fflush(RKLOGFILE);

			/* When changing the link max_allocation we need to update all tnic 
			   leaf classes as their ceil should be set to the new value. */
			for (tnic = tnic_root; tnic; tnic = tnic->hh.next) {
				tc_update_tnic(tnic, rk_max_allocation);
			}

			/* We also need to update the root classes for all IFBs
			 * For that we need a tco value.
			 * For now we just pic the tco value of an arbitrary vnic/tnic */
			vnic = vnic_root;
			if ( vnic != NULL ) {
				tnic = vnic->tnic;
				tc_update_ifbs(rk_max_allocation, &vnic->tco, &tnic->tco);
			}
			
			/* Update accumulator rate monitor highmark threshold in the kernel*/
			rkd_monitor_set(ACC_IFINDEX, rk_highmark, 0);

			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("sendto() error, errno %d\n", errno);
			}

			break;
		default:
			WARN1("rkd_rkconfig_cb: invalid msg %d rec\n",
			      ntohl(rkmsghdr->cmd));
			continue;
		}
	}
	return (errno == EAGAIN) ? (0) : (err);
}

#else

static int rkd_rkconfig_cb(int sock)
{
	char buf[256];
	int err, rkmsglen;
	struct rkdata *rkd;
	struct rkmsg_limits *limits;
	int vnic_ifindex;
	struct rkvnic *vnic;
	struct sockaddr_in from;
	struct rkmsg_header *rkmsghdr;
	socklen_t len = sizeof(struct sockaddr_in);

	while ((err = recvfrom(sock, buf, 256, MSG_DONTWAIT,
			       (struct sockaddr *)&from, &len)) > 0) {
		rkmsghdr = (void *) buf;
		switch (ntohl(rkmsghdr->cmd)) {

		case RKMSG_SET:
			rkd = (void *) buf + sizeof(struct rkmsg_header);
			vnic_ifindex = ifcache_name_to_index(rkd->vnic);
			if (vnic_ifindex <= 0 ) {
				rkmsg_reply(sock, &from, RK_RC_ERR_IF);
				break;
			}
			vnic = rkvnic_find(vnic_ifindex, &vnic_root);

			if ( vnic == NULL ) {     /* new vnic */
				vnic = rkvnic_add(vnic_ifindex, &vnic_root);
			}

			rkdata2rkvif(rkd, vnic);

			/* Set up RCs and monitor */
			if (!rkd_set(vnic))
				rkvnic_del(vnic->ifindex, &vnic_root, &tnic_root);

			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("sendto() error, errno %d\n", errno);
			}

			break;

		case RKMSG_GET:
			/* Update vnic_ti.current stats */
			rkd_monitor_ctl(RK_CMD_GET_STATS, 0, 0, 0);
			/* BUG: the kernel could have replied with
			 * other stuff than the stats that we
			 * requested. TODO: figure out a way to make
			 * sure the kernel sent us back the stats we
			 * requested. */
			/* The reply of a RKMSG_GET consists of a set
			 * of RKMSG_GET msgs carrying one rkdata each
			 * followed by one RKMSG_REPLY indicating the
			 * end of the set */
			rkd = (void *) buf + sizeof(struct rkmsg_header);

			rkmsglen = sizeof(struct rkmsg_header)+
				sizeof(struct rkdata);
			for (vnic = vnic_root; vnic != NULL; vnic = vnic->hh.next) {
				rkmsghdr->cmd = htonl(RKMSG_GET);
				rkvif2rkdata(vnic,rkd);
				if (sendto(sock,buf,rkmsglen,0,
					   (struct sockaddr *)&from,len)<0) {
					WARN1("rkd_rkconfig_cb: sendto() "
					      "error, errno %d\n", errno);
				}
			}
			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("rkd_rkconfig_cb: sendto() error, "
				      "errno %d\n", errno);
			}
			break;

		case RKMSG_LIMITS:
			limits = (void *) buf + sizeof(struct rkmsg_header);
			rk_highmark = ntohl(limits->highmark);
			rk_max_allocation = ntohl(limits->max_allocation);
			rk_vnic_headroom_factor = ntohl(limits->vnic_headroom) * 0.001 + 1.0;
			fprintf(RKLOGFILE, "Setting ratekeeper link: max_allocation = %d Mb/s, "
				"highmark = %d Mb/s\n", rk_max_allocation, rk_highmark);
			fprintf(RKLOGFILE, "Setting ratekeeper vnic Max headroom factor: =%lf\n", 
				rk_vnic_headroom_factor); 
			fflush(RKLOGFILE);

			/* We also need to update the root classes for all IFBs
			 * For that we need a tco value.
			 * For now we just pic the tco value of an arbitrary vnic/tnic */
			vnic = vnic_root;
			if ( vnic != NULL ) {
				tc_update_ifbs(rk_max_allocation, &vnic->tco, &vnic->tco);
			}
			
			/* Update accumulator rate monitor highmark threshold in the kernel*/
			rkd_monitor_set(ACC_IFINDEX, rk_highmark, 0);

			if (rkmsg_reply(sock, &from, RK_RC_SUCCESS) < 0) {
				WARN1("sendto() error, errno %d\n", errno);
			}

			break;
		default:
			WARN1("rkd_rkconfig_cb: invalid msg %d rec\n",
			      ntohl(rkmsghdr->cmd));
			continue;
		}
	}
	return (errno == EAGAIN) ? (0) : (err);
}

#endif

static int epoll_setup()
{
	int i;

	mh.epoll_fd = epoll_create(__RK_MAX_SOCKS);
	if (mh.epoll_fd < 0)
		return -1;

	for (i = 0; i < __RK_MAX_SOCKS; i++) {
		struct epoll_event e;
		if (mh.socks[i] != 0) {
			e.events   = EPOLLIN;
			e.data.fd  = mh.socks[i];
			e.data.u32 = i;
			if (epoll_ctl(mh.epoll_fd, EPOLL_CTL_ADD, mh.socks[i], &e) < 0) {
				close(mh.epoll_fd);
				return -1;
			}
		}
	}
	return 0;
}

static int rkconfig_setup()
{
	struct sockaddr_in addr;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		eexit("could not open rkconfig socket");
	if (fcntl(sock, F_SETFD, fcntl(sock, F_GETFD, 0) | O_NONBLOCK) == -1)
		eexit("fcntl error");

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(RKCONFIG_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0)
		eexit("could not bind rkconfig socket");

	mh.socks[RKCONFIG_SOCK] = sock;
	return 0;
}

static int rkd_kernel_cb(struct nl_msg *msg, void *arg)
{

   	//fprintf(RKLOGFILE, "rkd_kernel_cb... init\n");
   	//fflush(RKLOGFILE);

	struct nlmsghdr *nlmsg = nlmsg_hdr(msg);
	struct nlattr *attrs[__RK_ATTR_MAX];
	struct genlmsghdr *genlmsg;
	unsigned int severity;
	unsigned char *mac;
	int ifindex;
	char rk_ifname[IF_NAMESIZE+1];
	unsigned int size_stats;

	if (!nlmsg) {
		WARN("rkd_kernel_cb: received an invalid message!");
		return NL_OK;
	}

	genlmsg_parse(nlmsg, 0, attrs, RK_ATTR_MAX, rk_attr_policy);
	genlmsg = nlmsg_data(nlmsg);
	DEBUGMSG(1, "Kernel says:\n");
	switch (genlmsg->cmd) {

	case RK_CMD_GET_STATS:
		DEBUGMSG(1, "  Stats sent\n");
		if (!attrs[RK_ATTR_SIZE_STATS])
			eexit("could not get size of stats vector");
		size_stats = nla_get_u32(attrs[RK_ATTR_SIZE_STATS]);
		if (attrs[RK_ATTR_STATS])
			rkd_update_stats(nla_get_string(attrs[RK_ATTR_STATS]), size_stats);
		break;

	case RK_CMD_GET_INSTANCES:
		DEBUGMSG(1, "  Instances sent\n");
		if (!attrs[RK_ATTR_INSTANCES])
			eexit("could not get number of instances");
		mon_instances = nla_get_u32(attrs[RK_ATTR_INSTANCES]);
		DEBUGMSG(1, "number of monitor instances available is %d\n", 
		      mon_instances);
		break;

	case RK_CMD_DAEMON_SETUP:
	case RK_CMD_SET_MONITOR:
	case RK_CMD_UNSET_MONITOR:
		if (attrs[RK_ATTR_RC])
			switch (nla_get_u32(attrs[RK_ATTR_RC])) {
			case RK_RC_SUCCESS:
				DEBUGMSG(1, "  Operation executed successfully\n");
				break;
			case RK_RC_MISSING_ATTR:
				DEBUGMSG(1, "  Attribute missing\n");
				break;
			case RK_RC_UNDEFINED:
				DEBUGMSG(1, "  Unhandled error\n");
				break;
			}
		break;

	case RK_CMD_THLD_EXCEEDED:
		if (attrs[RK_ATTR_IFINDEX] && attrs[RK_ATTR_CONGESTION_SEVERITY] && attrs[RK_ATTR_MAC] ) {
			ifindex = nla_get_u32(attrs[RK_ATTR_IFINDEX]);
			severity = nla_get_u32(attrs[RK_ATTR_CONGESTION_SEVERITY]);
			mac = (unsigned char *) nla_get_string(attrs[RK_ATTR_MAC]);
			rkd_handle_congestion(ifindex, severity, mac);
		} else {
			eexit("Missing attributes on threshold exceeded notification from ratekeeper kernel module");
		}
		break;

	case RK_CMD_FB_RECEIVED:
	    severity = 0;
		if (attrs[RK_ATTR_CONGESTION_SEVERITY]) {
		    severity = nla_get_u32(attrs[RK_ATTR_CONGESTION_SEVERITY]);
		}
		if (attrs[RK_ATTR_IFINDEX])
			    ifindex = nla_get_u32(attrs[RK_ATTR_IFINDEX]);
			rk_ifname[0] = 0;
			if_indextoname(ifindex, rk_ifname);
			fprintf(RKLOGFILE, "RK daemon received FB for interface %s (%d) with severity %u\n",
				rk_ifname, ifindex, severity);
			fflush(RKLOGFILE);
			rkd_decrease_fn(ifindex, severity);
		break;
	}
	if (DEBUG > 3) { nl_msg_dump(msg, stdout); }
	return NL_OK;
}

static int kernel_setup()
{
	struct nl_msg *msg;
	int err;

	mh.libnl_sock = nl_socket_alloc();

	/* Setting callbacks */
	nl_socket_modify_cb(mh.libnl_sock, NL_CB_VALID, NL_CB_CUSTOM,
			    rkd_kernel_cb, NULL);
	/* Debug invalid messages */
	nl_socket_modify_cb(mh.libnl_sock, NL_CB_INVALID, NL_CB_DEBUG,
			    NULL, NULL);

	/* Disabling SEQ number check, to recieve unsolicited congestion
	 * notifications from Kernel.  */
	nl_socket_disable_seq_check(mh.libnl_sock);

	genl_connect(mh.libnl_sock);
	mh.socks[KERNEL_SOCK] = nl_socket_get_fd(mh.libnl_sock);

	err = nl_socket_set_buffer_size(mh.libnl_sock, 2097152, 2097152);
	if (err < 0)
		eexit("could not set buffer size");

	nl_socket_set_nonblocking(mh.libnl_sock);

	mh.family_id = genl_ctrl_resolve(mh.libnl_sock, "ratekeeper");
	if (mh.family_id < 0)
		eexit("could not connect to ratekeeper kernel module");

	/* Sending PID to rk kernel modules */
	if ((msg = nlmsg_alloc()) == NULL) {
		close(mh.socks[KERNEL_SOCK]);
		return -1;
	}
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, mh.family_id, 0,
		    NLM_F_REQUEST, RK_CMD_DAEMON_SETUP, 1);
	nla_put_u32(msg, RK_ATTR_PID, getpid());
	nl_send_auto_complete(mh.libnl_sock, msg);
	nlmsg_free(msg);

	/* Get number of instances available */
	if ((msg = nlmsg_alloc()) == NULL) {
		close(mh.socks[KERNEL_SOCK]);
		return -1;
	}
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, mh.family_id, 0,
		    NLM_F_REQUEST, RK_CMD_GET_INSTANCES, 1);
	nl_send_auto_complete(mh.libnl_sock, msg);
	nlmsg_free(msg);

	nl_recvmsgs_default(mh.libnl_sock);

	return 0;
}

#ifdef RK_USE_TNIC
static int rkdata2rkvif(struct rkdata *rkd, struct rkvnic *vnic)
{
	struct rktnic *tnic;

	tnic = vnic->tnic;

	vnic->ti.min = ntohl(rkd->min);
	vnic->rl_rate_kbit = vnic->ti.min * 1000;
	vnic->ti.max = ntohl(rkd->max);
	vnic->fb_count    = 0;   /* Reset/initialize FB count */
	vnic->congestion_severity = 1;

	// TODO: If this is an existing tnic should we
	// check if there is a change in vnet_id and return error?
	tnic->vnet_id     = ntohl(rkd->vnet_id);

	vnic->tco.burst = ntohl(rkd->vnic_tco.burst);
	vnic->tco.qsize = ntohl(rkd->vnic_tco.qsize);
	vnic->tco.mtu = ntohl(rkd->vnic_tco.mtu);

	tnic->tco.burst = ntohl(rkd->tnic_tco.burst);
	tnic->tco.qsize = ntohl(rkd->tnic_tco.qsize);
	tnic->tco.mtu = ntohl(rkd->tnic_tco.mtu);

	/* Setting default values for Ratekeeper optional arguments */
	tc_default_options(&vnic->tco, vnic->ti.max);
	tc_default_options(&tnic->tco, rk_max_allocation);

	return 0;
}

#else
static int rkdata2rkvif(struct rkdata *rkd, struct rkvnic *vnic)
{

	vnic->ti.min = ntohl(rkd->min);
	vnic->rl_rate_kbit = vnic->ti.min * 1000;
	vnic->ti.max = ntohl(rkd->max);
	vnic->fb_count    = 0;   /* Reset/initialize FB count */
	vnic->congestion_severity = 1;

	vnic->vnet_id     = ntohl(rkd->vnet_id);

	vnic->tco.burst = ntohl(rkd->vnic_tco.burst);
	vnic->tco.qsize = ntohl(rkd->vnic_tco.qsize);
	vnic->tco.mtu = ntohl(rkd->vnic_tco.mtu);

	/* Setting default values for Ratekeeper optional arguments */
	tc_default_options(&vnic->tco, vnic->ti.max);

	return 0;
}
#endif

#ifdef RK_USE_TNIC
static int rkvif2rkdata(struct rkvnic *vnic, struct rkdata *rkd)
{
	struct rktnic *tnic = vnic->tnic;

	if (!if_indextoname(vnic->ifindex, rkd->vnic) ||
	    !if_indextoname(tnic->ifindex, rkd->tnic))
		return -1;

	rkd->min      = htonl(vnic->ti.min);
	rkd->max      = htonl(vnic->ti.max);
	rkd->vnet_id  = htonl(tnic->vnet_id);
	rkd->thput    = htonl(vnic->ti.current);
	rkd->fb_count = htonl(vnic->fb_count);

	rkd->vnic_tco.burst = htonl(vnic->tco.burst);
	rkd->vnic_tco.qsize = htonl(vnic->tco.qsize);
	rkd->vnic_tco.mtu = htonl(vnic->tco.mtu);

	rkd->tnic_tco.burst = htonl(tnic->tco.burst);
	rkd->tnic_tco.qsize = htonl(tnic->tco.qsize);
	rkd->tnic_tco.mtu = htonl(tnic->tco.mtu);

	return 0;
}

#else
static int rkvif2rkdata(struct rkvnic *vnic, struct rkdata *rkd)
{
	if (!if_indextoname(vnic->ifindex, rkd->vnic))
		return -1;

	rkd->min      = htonl(vnic->ti.min);
	rkd->max      = htonl(vnic->ti.max);
	rkd->vnet_id  = htonl(vnic->vnet_id);
	rkd->thput    = htonl(vnic->ti.current);
	rkd->fb_count = htonl(vnic->fb_count);

	rkd->vnic_tco.burst = htonl(vnic->tco.burst);
	rkd->vnic_tco.qsize = htonl(vnic->tco.qsize);
	rkd->vnic_tco.mtu = htonl(vnic->tco.mtu);

	rkd->tnic_tco.burst = htonl(vnic->tco.burst);
	rkd->tnic_tco.qsize = htonl(vnic->tco.qsize);
	rkd->tnic_tco.mtu = htonl(vnic->tco.mtu);

	return 0;
}
#endif

static int rkmsg_reply(int sock, struct sockaddr_in *to, rkd_rc rc)
{
	char buf[256];
	struct rkreply *rkr;
	socklen_t len = sizeof(struct sockaddr_in);
	struct rkmsg_header *rkmsghdr = (void*) buf;
	int rkmsglen = sizeof(struct rkmsg_header)+sizeof(struct rkreply);

	rkmsghdr->cmd = htonl(RKMSG_REPLY);
	rkr = (void *) buf + sizeof(struct rkmsg_header);
	rkr->rc = htonl(rc);

	return sendto(sock, buf, rkmsglen, 0, (struct sockaddr *) to, len);
}

static void usage() {
	printf("Usage: rk-daemon <pnic> [-t threshold (in mbps)]\n"
	       "                        [-i interval  (in ms)]\n"
	       "                        [-d decrease  (0-100%%)]\n"
	       "                        [-r increase (in mbps/interval)]\n");
	exit(1);
};

static void parse_args(int argc, char **argv)
{
	char *arg, *optarg, *err;
	unsigned long int optval;
	int   i = 2;

	for (;i < argc; i++) {
		arg = argv[i];
		if (arg[0] != '-') { usage(); }

 		if (arg[1] == 'D') {
			rk_daemonize = 0;
			i++;
			continue;
		}

		if (strlen(arg) > 2)
			optarg = arg+2;
		else if (i+1 < argc)
			optarg = argv[++i];
		else
			usage();

		optval = strtoul(optarg,&err,10);
		if (err == optarg)
			usage();

		if (arg[1] == 't' && optval > 0)
			rk_max_allocation = optval;
		else if (arg[1] == 'i' && optval > 0)
			rk_interval = optval;
		else if (arg[1] == 'r')
			rk_increase_kbit = optval * 1000;
		else if (arg[1] == 'd') {
			if (optval > 100) optval = 100;
			rk_decrease = (float)optval/100.0;
		}
		else
			usage();
	}
}

static void rkd_increase_fn()
{
	struct rkinc  *rki, *aux;
	struct rkvnic *vnic;
        unsigned int severity;
	unsigned int increase_step;
	char rk_ifname[IF_NAMESIZE+1];

	rkinc_foreach(rki, aux, &rki_root) {
		vnic = rki->vnic;
		/* compute rate increase amount based on congestion severity */
		if (vnic->congestion_severity < 1)
			severity = 1;
		else
			severity = vnic->congestion_severity;
		increase_step = rk_increase_kbit / severity;
		/* avoid rounding to zero */
		if (increase_step < 1)
			increase_step = 1;
		vnic->rl_rate_kbit += increase_step;
		
		rk_ifname[0] = 0;
		if_indextoname(vnic->ifindex, rk_ifname);
		DEBUGMSG(1, "RK: Increase for interface %s (%d) : %d (+ %d ) (sev=%d)\n",
			rk_ifname, vnic->ifindex, vnic->rl_rate_kbit, increase_step, severity);

		if (vnic->rl_rate_kbit >= (vnic->ti.max * 1000)) {
			vnic->rl_rate_kbit = vnic->ti.max * 1000;
			vnic->congestion_severity = 0;
			tc_set_rate(vnic);
			rkinc_del(rki, &rki_root);
		}
		else
			tc_set_rate(vnic);
	}
}

/* Given an ifindex, search the rkvif for a bucket associated with
 * this ifindex and add a rkinc entry in the data structure pointed
 * by rkinc_root */
static void rkd_decrease_fn(int ifindex, unsigned int severity)
{
	struct rkinc   rki;
	struct rkvnic *vnic = rkvnic_find(ifindex, &vnic_root);
	if (!vnic) {
		WARN1("rkd_decrease_fn: the kernel wants to throttle an "
		      "interface that is not in rkvif. Given ifindex: %d\n",
		      ifindex);
	}
	else {
		DEBUGMSG(1, "rkd_decrease_fn: decreasing %d\n", ifindex);
		vnic->rl_rate_kbit *= (1.0-rk_decrease);
		/* avoid setting rate to 0 */
		if (vnic->rl_rate_kbit < 1)
			vnic->rl_rate_kbit = 1;

		vnic->fb_count   += 1;
		vnic->congestion_severity = severity;
		rki.vnic          = vnic;
		rki.vnic_ifindex = vnic->ifindex;

		rkinc_add(&rki, &rki_root);
		tc_set_rate(vnic);
	}
}

static inline int rkd_monitor_set(int ifindex, int limit, int is_tnic)
{
	/* Threshold in the kernel is higher, to avoid false
	 * positive RK congestion feedbacks due to burstiness */
	if ( ifindex != ACC_IFINDEX  )
		limit *= rk_vnic_headroom_factor;
	return rkd_monitor_ctl(RK_CMD_SET_MONITOR, ifindex, limit, is_tnic);
}

static inline int rk_monitor_unset(int ifindex)
{
	return rkd_monitor_ctl(RK_CMD_UNSET_MONITOR, ifindex, 0, 0);
}

/* Given a rkvif, this function configures tc qdiscs/classes/filters
 * and rk kernel monitors according to the MIN and MAX attributes of
 * the rkvif structure. */
#ifdef RK_USE_TNIC
static int rkd_set(struct rkvnic *vnic)
{
	struct rktnic *tnic = vnic->tnic;
	if (tc_set(vnic, rk_max_allocation)) {
		rkd_monitor_set(vnic->ifindex, vnic->ti.max, 0);
		/* TODO: check return values */

		/* Q: Can MAX be higher than rk_threshold? */

		/* The tnic limit is the min rate. It won't trigger
		 * congestion notifications.  Just a reminder: the MON_ACC
		 * monitor (see kernel/monitor.c) will accumulate all the
		 * measurements of tnic monitors and notify the daemon
		 * if the total rate exceeds the link highmark and some
                 * tnic is not reaching its min rate */
		rkd_monitor_set(tnic->ifindex, tnic->ti.min, 1);

		return 1;
	}
	rk_monitor_unset(vnic->ifindex);
	fprintf(RKLOGFILE, "Removing vnic index %d from cache\n",
		vnic->ifindex);
	ifcache_del(vnic->ifindex);
	rk_monitor_unset(tnic->ifindex);
	fprintf(RKLOGFILE, "Removing tnic index %d from cache\n",
		tnic->ifindex);
	fflush(RKLOGFILE);
	ifcache_del(tnic->ifindex);
	return 0;
}

#else
static int rkd_set(struct rkvnic *vnic)
{
	if (tc_set(vnic, rk_max_allocation)) {
		/* TODO: check return values */
		rkd_monitor_set(vnic->ifindex, vnic->ti.max, 0);
		return 1;
	}
	rk_monitor_unset(vnic->ifindex);
	fprintf(RKLOGFILE, "Removing vnic index %d from cache\n",
		vnic->ifindex);
	ifcache_del(vnic->ifindex);
	fflush(RKLOGFILE);
	return 0;
}
#endif

/* TODO: change the arg list by a va_list */
static int rkd_monitor_ctl(genl_command cmd, int p1, int p2, int p3)
{
	struct nl_msg *msg;
	int ret;

	if ((msg = nlmsg_alloc()) == NULL)
		return -1;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, mh.family_id, 0,
		    NLM_F_REQUEST, cmd, 1);
	switch (cmd) {

	case RK_CMD_SET_MONITOR:
		nla_put_u32(msg, RK_ATTR_IFINDEX, p1);
		nla_put_u32(msg, RK_ATTR_LIMIT, (int)mbps2bypus(p2));
		nla_put_u32(msg, RK_ATTR_IS_TNIC, p3);
		break;

	case RK_CMD_UNSET_MONITOR:
		nla_put_u32(msg, RK_ATTR_IFINDEX, p1);
		break;

	case RK_CMD_GET_STATS:
	case RK_CMD_GET_INSTANCES:
		/* No attrs */
		break;

	default:
		WARN1("rkd_monitor_ctl: cmd %d unhandled\n", cmd);
	}
	if (DEBUG > 3) { nl_msg_dump(msg, stdout); }
	ret = nl_send_auto_complete(mh.libnl_sock, msg);
	nlmsg_free(msg);

	/* TODO: We shouldn't be calling this function here because the
	 * socket is asynchronous. We need another way to check if the
	 * kernel has provided an answer for the requests sent in this
	 * function */
	if (ret == 0)
		ret = nl_recvmsgs_default(mh.libnl_sock);

	return ret;
}

static void rkd_update_stats(char *buf, unsigned int size_stats)
{
	struct monitor_stats *ms;
	struct rkvnic *vnic;
	struct rktnic *tnic;
	int i;

	if ( size_stats >= mon_instances ) {
		eexit("Size of stats vector received from kernel is too LARGE");
	}

	for (i = 0; i < size_stats; i++) {
		ms = (struct monitor_stats *)buf + i;
		if (ms->ifindex == 0) { continue; }

		/* rkv = rkvif_find_i(ms->ifindex, &rkv_root); */
		/* if (rkv == NULL) { continue; } */

		/* TODO: rk-daemon design changed and we need another
		 * data structure with efficient lookup for 2 keys
		 * (vnic_ifindex and tnic_ifindex). A 2-key hash table
		 * would be an option. I'm doing linear search for
		 * now */
		vnic = rkvnic_find(ms->ifindex, &vnic_root);
		if ( vnic != NULL )  {
				vnic->ti.current = bypus2mbps(ms->rate);
				memcpy(&vnic->ti.mac, ms->mac, ETH_ALEN);
		} else {
			tnic = rktnic_find(ms->ifindex, &tnic_root);
			if ( tnic != NULL )  {
				tnic->ti.current = bypus2mbps(ms->rate);
				memcpy(&tnic->ti.mac, ms->mac, ETH_ALEN);
			}
		}
	}
}

/**
 * This function takes care sending a congestion
 * feedback to the specified mac addresses.
 *
 * @ifindex: the ifindex of the net_device where the congestion was
 *           detected
 *
 * @severity: severity of congestion as determined by the kernel.
 *
 * @mac: mac address of sender that will receive the feedback message
 *
 * It is called whenever the kernel notifies the daemon that a
 * net_device is congested. 
 */
static void rkd_handle_congestion(int ifindex, unsigned int severity, unsigned char *mac)
{
	//struct rkvnic *vnic;
	char rk_ifname[IF_NAMESIZE+1];

	//DEBUGMSG(1, "rkd_handle_congestion: ifindex %d  (DISABLED: no TNIC)\n", ifindex);

	rk_ifname[0] = 0;
	if_indextoname(ifindex, rk_ifname);

	fprintf(RKLOGFILE, "RK daemon sending FB for interface %s (%d) with severity %u\n",
		rk_ifname, ifindex, severity);
	fflush(RKLOGFILE);
    /* MARIO: replace tap interface name with qvb equivalent */
    if (rk_ifname[0] == 't' && rk_ifname[1] == 'a' && rk_ifname[2] == 'p') {
        rk_ifname[0] = 'q';
        rk_ifname[1] = 'v';
        rk_ifname[2] = 'b';

	    ifindex = if_nametoindex(rk_ifname);
    }

	fprintf(RKLOGFILE, "RK daemon sending FB via interface %s (%d) \n",
		rk_ifname, ifindex);
	fflush(RKLOGFILE);

	rkd_fb_send(ifindex, mac, severity);

	/* for vnics we need to find the associated tnic */
	/* since feedback messsages are sent through the tnic */
	//vnic = rkvnic_find(ifindex, &vnic_root);
    
	/* TODO: Need to find a WAY to send FEEDBACK when we don't have tnics */
    /*
	if (vnic) {
		rkd_fb_send(vnic->tnic->ifindex, mac, severity);
		return;
	} else {
		rkd_fb_send(ifindex, mac, severity);
	}
    */
}

int debug_counter = 0;
#define INT_DEBUG_COUNTER 20


/**
 * This function assembles and sends a feedback message
 *
 * @tnic_ifindex: ifindex of the tnic (tenant nic) interface,
 *                for the tenant that is exceeding its RX guaranteed,
 *                regardless if the exceeding rate is at the tnic or vnic.
 *
 * @severity: severity of congestion as determined by the kernel.
 *
 * @dst_mac: MAC address of the destination for the feedback message
 */

/* TODO: Need to find a WAY to send FEEDBAK=CK when we don't have tnics */
static int rkd_fb_send(int tnic_ifindex, unsigned char *dst_mac, unsigned int severity)
{
	struct ether_header *eth;
	struct timespec now;
	struct rkfb *f;
	int sock, ret;
	char buf[64];        // Must be at least sizeof(struct
			     // ether_header) + sizeof(struct rkfb)
	char rk_ifname[IF_NAMESIZE+1];

	eth     = (void *) buf;

	memcpy(eth->ether_dhost, dst_mac, ETH_ALEN);
	memcpy(eth->ether_shost, mh.mac,  ETH_ALEN);
	eth->ether_type = htons(ETH_P_RK);

	rk_ifname[0] = 0;
	if_indextoname(tnic_ifindex, rk_ifname);
	debug_counter++;
	fprintf(RKLOGFILE, "%s: Sending feedback to %02x:%02x:%02x:%02x:%02x:%02x (sev=%d)\n",
		rk_ifname, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], severity);
	if ((debug_counter % INT_DEBUG_COUNTER) == 0) {
		fflush(RKLOGFILE);
	}
	// Ratekeeper feedback payload
	f = (void *)eth + sizeof(struct ether_header);

	f->severity = htonl(severity);
	// unused fields in feedback message
	f->ifindex  = 0;
	f->thput    = 0;
	f->min      = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	f->time     = htonl(ms(now)); // for debugging

	sock = ifcache_index_to_sock(tnic_ifindex);

	if (sock <= 0) {
		WARN1("BUG: socket for tnic %d not open\n",tnic_ifindex);
		return -1;
	}

	ret = send(sock,buf,sizeof(struct ether_header)+sizeof(struct rkfb),0);
	if (ret < 0)
		WARN2("rkd_fb_send: send() error %d, errno %d\n", ret, errno);
	return ret;
}

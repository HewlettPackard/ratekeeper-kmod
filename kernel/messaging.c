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

#include <linux/version.h>

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#include "../include/messaging_kernel.h"
#include "../include/monitor.h"

/* Temporary storage for monitor statistics that is
   immediately copied to a netlink message.
   We use a static variable since this is too big for the stack.
*/
static struct monitor_stats stats[MON_INSTANCES-1];

struct rk_msghandler {
	struct genl_family family;
	u32                upcall_pid;
};

struct rk_msghandler mh = {
	.family = {
		.id      = GENL_ID_GENERATE,
		.hdrsize = 0,
		.name    = RK_FAMILY_NAME,
		.version = RK_FAMILY_VERSION,
		.maxattr = RK_ATTR_MAX,
	},
	.upcall_pid = 0,
};

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
	[RK_ATTR_MAC]           = { .type = NLA_UNSPEC },
};

static inline int genl_send(struct sk_buff *skb, struct genl_info *info)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(&init_net, skb, info->snd_portid);
#else
	return genlmsg_unicast(&init_net, skb, info->snd_pid);
#endif

}

static inline int genl_reply(struct genl_info *info, genl_rc rc)
{
	struct sk_buff *skb;
	struct genlmsghdr *genlmsg;

	if ((skb = genlmsg_new(RKMSG_U32_SIZE, GFP_KERNEL)) == NULL)
		return -1;
	genlmsg = genlmsg_put(skb, 0, info->snd_seq, &mh.family, 0,
						  info->genlhdr->cmd);
	nla_put_u32(skb, RK_ATTR_RC, rc);
	genlmsg_end(skb, genlmsg);

	return genl_send(skb, info);
}

static int rk_get_instances(struct sk_buff *rskb, struct genl_info *info)
{
	struct sk_buff *skb;
	struct genlmsghdr *genlmsg;

	if ((skb = genlmsg_new(RKMSG_U32_SIZE, GFP_KERNEL)) == NULL)
		return -1;
	genlmsg = genlmsg_put(skb, 0, info->snd_seq, &mh.family, 0,
						  info->genlhdr->cmd);
	nla_put_u32(skb, RK_ATTR_INSTANCES, monitor_get_instances());
	genlmsg_end(skb, genlmsg);

	return genl_send(skb, info);
}

static int rk_daemon_setup(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;

	na = info->attrs[RK_ATTR_PID];
	if (na && ((int *)nla_data(na))) {
		mh.upcall_pid = *((int *)nla_data(na));
		return genl_reply(info, RK_RC_SUCCESS);
	}
	return genl_reply(info, RK_RC_MISSING_ATTR);
}

static int rk_get_stats(struct sk_buff *rskb, struct genl_info *info)
{
	struct sk_buff *skb;
	struct genlmsghdr *genlmsg;
	struct monitor_stats *s;
	int i, len;

	/* Return stats of all monitors except the MON_ACC, which is the one
	 * that accumulates all the measurements */
	for (i = 1, s = &stats[i-1]; i < MON_INSTANCES; s++, i++) {
		monitor_get_stats(i, &s->ifindex, &s->rate, s->mac);
	}

	len = NLMSG_HDRLEN + GENL_HDRLEN + sizeof(struct nlattr) + sizeof(stats)
	  + sizeof(struct nlattr) + sizeof(unsigned int);
	if ((skb = genlmsg_new(len, GFP_KERNEL)) == NULL)
		return -1;
	genlmsg = genlmsg_put(skb, 0, info->snd_seq, &mh.family, 0,
						  info->genlhdr->cmd);
	nla_put_u32(skb, RK_ATTR_SIZE_STATS, MON_INSTANCES-1);
	nla_put(skb, RK_ATTR_STATS, sizeof(stats), (char *)stats);
	genlmsg_end(skb, genlmsg);

	return genl_send(skb, info);
}

static int rk_set_monitor(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na_ifindex, *na_limit, *na_istnic;
	int ifindex, limit, is_tnic;

	na_ifindex = info->attrs[RK_ATTR_IFINDEX];
	na_limit = info->attrs[RK_ATTR_LIMIT];
	na_istnic = info->attrs[RK_ATTR_IS_TNIC];

	if (na_ifindex && ((int *)nla_data(na_ifindex)) &&
	    na_limit && ((int *)nla_data(na_limit))     &&
	    na_istnic && ((int *)nla_data(na_istnic)) ) {
		ifindex = *((int *)nla_data(na_ifindex));
		limit   = *((int *)nla_data(na_limit));
		is_tnic = *((int *)nla_data(na_istnic));
		if (monitor_set(ifindex, limit, is_tnic) == MON_SET)
			return genl_reply(info, RK_RC_SUCCESS);
		printk(KERN_ALERT "RK: [ratekeeper]: could not set up the monitor instance ");
		return genl_reply(info, RK_RC_UNDEFINED);
	}
	return genl_reply(info, RK_RC_MISSING_ATTR);
}

static int rk_unset_monitor(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *na;
	int ifindex;

	na = info->attrs[RK_ATTR_IFINDEX];
	if (na && ((int *)nla_data(na))) {
		ifindex = *((int *)nla_data(na));
		if (monitor_unset(ifindex) == MON_UNSET)
			return genl_reply(info, RK_RC_SUCCESS);
		printk(KERN_ALERT "RK: [ratekeeper]: could not release the monitor instance");
		return genl_reply(info, RK_RC_UNDEFINED);
	}
	return genl_reply(info, RK_RC_MISSING_ATTR);
}

int rk_upcall_congestion(int ifindex, unsigned char *mac, u32 severity)
{
	struct genlmsghdr *genlmsg;
	struct sk_buff *skb;
	int len = NLMSG_HDRLEN + GENL_HDRLEN;
	int rc;

	if (!(mh.upcall_pid > 0 && ifindex >= 0))
		return -1;	/* TODO: define RK-specific errno */

	len += 4 * sizeof(struct nlattr) + 3 * sizeof(unsigned int) + 6;

	if ((skb = genlmsg_new(len, GFP_ATOMIC)) == NULL) {
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_new().");
		return -2;
	}
	genlmsg = genlmsg_put(skb, 0, 0, &mh.family, 0, RK_CMD_THLD_EXCEEDED);
	if ( genlmsg == NULL )
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_put().");

	rc = nla_put_u32(skb, RK_ATTR_IFINDEX, ifindex);
	if (rc !=0) 
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_IFINDEX.");

	rc =nla_put_u32(skb, RK_ATTR_CONGESTION_SEVERITY, severity);
	if (rc !=0) 
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_CONGESTION_SEVERITY.");

	rc = nla_put(skb, RK_ATTR_MAC, 6, (char *)mac);
	if (rc !=0) 
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_MAC.");

	genlmsg_end(skb, genlmsg);

	rc = genlmsg_unicast(&init_net, skb, mh.upcall_pid);
	if (rc !=0) 
		printk( KERN_ALERT "RK: [ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_unicast().");

	return rc;
}

/*
int rk_upcall_congestion(int ifindex, int rate, unsigned char *mac, u32 severity)
{
	struct monitor_stats *s;
	struct genlmsghdr *genlmsg;
	struct sk_buff *skb;
	u32 size_stats;
	int i, len = NLMSG_HDRLEN + GENL_HDRLEN;
	int rc;

	if (!(mh.upcall_pid > 0 && ifindex >= 0))
	  return -1;	// TODO: define RK-specific errno

	if (ifindex == 0) {	// MON_ACC
	  // Getting stats of all monitors except the MON_ACC
		for (i = 1, s = &stats[i-1]; i < MON_INSTANCES; s++, i++)
			monitor_get_stats(i, &s->ifindex, &s->rate, s->mac);
		size_stats=MON_INSTANCES-1;
	}
	else {			// Specific monitor, no locking
	  // needed, just send the values 
		stats[0].ifindex = ifindex;
		stats[0].rate     = rate;
		memcpy(&stats[0].mac, mac, 6);
		size_stats=1;
	}

	len +=
		sizeof(struct nlattr) + sizeof(stats) +
		3 * sizeof(struct nlattr) + 3 * sizeof(unsigned int);

	if ((skb = genlmsg_new(len, GFP_ATOMIC)) == NULL) {
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_new().");
		return -2;
	}
	genlmsg = genlmsg_put(skb, 0, 0, &mh.family, 0, RK_CMD_THLD_EXCEEDED);
	if ( genlmsg == NULL )
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_put().");

	rc = nla_put_u32(skb, RK_ATTR_IFINDEX, ifindex);
	if (rc !=0) 
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_IFINDEX.");

	rc =nla_put_u32(skb, RK_ATTR_CONGESTION_SEVERITY, severity);
	if (rc !=0) 
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_CONGESTION_SEVERITY.");
	rc = nla_put_u32(skb, RK_ATTR_SIZE_STATS, size_stats);
	if (rc !=0) 
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_SIZE_STAS.");
	rc = nla_put(skb, RK_ATTR_STATS, sizeof(stats), (char *)stats);
	if (rc !=0) 
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by nla_put() for RK_ATTR_STATS.");
	genlmsg_end(skb, genlmsg);

	rc = genlmsg_unicast(&init_net, skb, mh.upcall_pid);
	if (rc !=0) 
		printk( KERN_ALERT "[ratekeeper]: rk_upcall_congestion(): ERROR returned by genlmsg_unicast().");

	return rc;
}
*/

/* Ratekeeper upcall feedback received */
int rk_upcall_feedback(int ifindex, unsigned int severity)
{
	struct sk_buff *skb;
	struct genlmsghdr *genlmsg;
	int len = NLMSG_HDRLEN + GENL_HDRLEN;

	if (!(mh.upcall_pid > 0 && ifindex > 0))
		return -1;	/* TODO: define RK-specific errno */

	len += 2 * sizeof(struct nlattr) + 2 * sizeof(unsigned int);
	if ((skb = genlmsg_new(len, GFP_ATOMIC)) == NULL)
		return -2;
	genlmsg = genlmsg_put(skb, 0, 0, &mh.family, 0, RK_CMD_FB_RECEIVED);
	nla_put_u32(skb, RK_ATTR_IFINDEX, ifindex);
	nla_put_u32(skb, RK_ATTR_CONGESTION_SEVERITY, severity);
	genlmsg_end(skb, genlmsg);

	return genlmsg_unicast(&init_net, skb, mh.upcall_pid);
}

int __init messaging_init(void)
{
	int rc;

	static struct genl_ops rk_ops[5] = {
		{
			.cmd    = RK_CMD_DAEMON_SETUP,
			.flags  = GENL_ADMIN_PERM, /* Restricted */
			.policy = rk_attr_policy,
			.doit   = rk_daemon_setup,
		},
		{
			.cmd    = RK_CMD_SET_MONITOR,
			.flags  = GENL_ADMIN_PERM, /* Restricted */
			.policy = rk_attr_policy,
			.doit   = rk_set_monitor,
		},
		{
			.cmd    = RK_CMD_UNSET_MONITOR,
			.flags  = GENL_ADMIN_PERM, /* Restricted */
			.policy = rk_attr_policy,
			.doit   = rk_unset_monitor,
		},
		{
			.cmd    = RK_CMD_GET_STATS,
			.flags  = 0,              /* Anyone can retrieve stats */
			.policy = rk_attr_policy,
			.doit   = rk_get_stats
		},
		{
			.cmd    = RK_CMD_GET_INSTANCES,
			.flags  = 0,              /* Anyone can retrieve stats */
			.policy = rk_attr_policy,
			.doit   = rk_get_instances,
		},
	};

	//rc = genl_register_family_with_ops(&mh.family, rk_ops, 
	//				   ARRAY_SIZE(rk_ops));
	rc = genl_register_family_with_ops(&mh.family, rk_ops);
	return rc;
}

void __exit messaging_exit(void)
{
	genl_unregister_family(&mh.family);
}

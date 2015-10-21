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

#ifndef _RATEKEEPER_MESSAGING_H_
#define _RATEKEEPER_MESSAGING_H_

#ifdef __KERNEL__
#include <net/netlink.h>
#else
#include <netlink/attr.h>
#endif

/* Generic netlink family name and version */
#define RK_FAMILY_NAME        "ratekeeper"
#define RK_FAMILY_VERSION     1

/* List of commands accepted by rk genetlink family */
typedef enum {
  RK_CMD_UNSPEC,
  RK_CMD_DAEMON_SETUP,
  RK_CMD_SET_MONITOR,
  RK_CMD_UNSET_MONITOR,
  RK_CMD_GET_STATS,
  RK_CMD_GET_INSTANCES,
  RK_CMD_THLD_EXCEEDED,
  RK_CMD_FB_RECEIVED,
  __RK_CMD_MAX,
} genl_command;
#define RK_CMD_MAX            (__RK_CMD_MAX - 1)

/* List of attributes accepted by rk genetlink family */
typedef enum {
  RK_ATTR_UNSPEC,
  RK_ATTR_IFINDEX,
  RK_ATTR_MONITOR_INDEX,
  RK_ATTR_RATE,
  RK_ATTR_LIMIT,
  RK_ATTR_PID,
  RK_ATTR_STATS,
  RK_ATTR_INSTANCES,
  RK_ATTR_RC,
  RK_ATTR_CONGESTION_SEVERITY,
  RK_ATTR_SIZE_STATS,
  RK_ATTR_IS_TNIC,
  RK_ATTR_MAC,
  __RK_ATTR_MAX,
} genl_attr;
#define RK_ATTR_MAX           (__RK_ATTR_MAX - 1)

/* Reply return codes used by rk genetlink family */
typedef enum {
  RK_RC_SUCCESS,
  RK_RC_EOMEM,                /* Memory allocation failed */
  RK_RC_MISSING_ATTR,         /* Request is missing a required attr */
  RK_RC_ERR_IF,               /* Error trying to fetch iface info */
  RK_RC_UNDEFINED,            /* Unhandled error */
} genl_rc;

typedef genl_rc rkd_rc;       /* The rk-daemon uses the same reply
                               * return codes as the kernel module  */

/* Size of genl msgs that carry an u32 attr */
#define RKMSG_U32_SIZE        (sizeof(struct nlmsghdr) +   \
                               sizeof(struct genlmsghdr) + \
                               sizeof(struct nlattr) +     \
                               sizeof(unsigned int))

struct monitor_stats {
  int           ifindex;
  int           rate;
  unsigned char mac[6];
};

#define ETH_P_RK        0x6473

/* This is the ifindex used to identify the
 * monitor that accumulates all other measurements */
#define ACC_IFINDEX                -1

/* This is the structure of a network congestion feedback message.
 * This structure is put at the network level of an ordinary packet.
 * The data is stored in network byte order. */
struct rkfb {
	unsigned int  severity;
	/* The following vars were added for debugging */
	unsigned int time;
	int ifindex;
	int thput;
	int min;
};

#endif /* _RATEKEEPER_MESSAGING_H_ */

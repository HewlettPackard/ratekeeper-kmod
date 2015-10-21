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

#ifndef _RATEKEEPER_MESSAGING_USER_H_
#define _RATEKEEPER_MESSAGING_USER_H_

#include "messaging.h"

struct tc_options {
	int burst;
	int qsize;
	int mtu;
};

/* List of commands accepted by rk-daemon. */
typedef enum {
	RKMSG_SET,
	RKMSG_GET,
	RKMSG_REPLY,
	RKMSG_CONGESTION,
	RKMSG_LIMITS,
} rkmsg_command;

/* All messages exchanged between user level processes contains this
 * header.  The data is stored in network byte order. */
struct rkmsg_header {
	rkmsg_command cmd;
};

/* When replying to a request, rk-daemon puts this structure on the
 * reply rkmsg. The data is stored in network byte order.  */
struct rkreply {
	unsigned int rc;
};

/* This is the structure that carries information received from (and
 * sent to) rkconfig. All the data is stored in network byte order. */
struct rkdata {
	char vnic[IFNAMSIZ];
	char tnic[IFNAMSIZ];
	int  vnet_id;
	int  min;
	int  max;
	int  thput;              /* Used by RKMSG_GET */
	int  fb_count;           /* # of fb messages intercepted at this vnic */
	/* TC options */
	struct tc_options vnic_tco;
	struct tc_options tnic_tco;
};

struct rkmsg_limits {
	int highmark;
	int max_allocation;
	int vnic_headroom;
};

/* Ratekeeper daemon port */
#define RKCONFIG_PORT           0x8889

#endif /* _RATEKEEPER_MESSAGING_USER_H_ */

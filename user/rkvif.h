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

/* The ratekeeper daemon uses a hash table to maintain the state of
 * each monitor. This file defines the API of this hash table. rkvif
 * is essentially a bucket, and the functions to add, find, update and
 * delete buckets are defined after the rkvif structure. Ratekeeper
 * currently uses uthash as its underlying hash table implementation
 * (http://uthash.sourceforge.net/)
 */

#ifndef _RATEKEEPER_RKVIF_H_
#define _RATEKEEPER_RKVIF_H_

#include <uthash.h>
#include <net/if.h>
#include <net/ethernet.h>

#include "tc.h"
struct tc_options;

// Uncomment the line below to associate rate limiters with tnics
//#define RK_USE_TNIC 1

struct rk_traffic_info {
	int min;
	int max;
	int current;
	unsigned char mac[ETH_ALEN];
};

struct rkvnic {
	int ifindex;
	struct rk_traffic_info ti;
	struct tc_options tco;
	/* TODO: keep socket used to send fb
	 * Q: what if the interface is gone? */
	int sock;
	/* Hash */
	UT_hash_handle hh;

#ifdef RK_USE_TNIC
	struct rktnic* tnic;
#else
	unsigned int vnet_id;
#endif
	int rl_rate_kbit;            /* Current rate limiter rate */
	int fb_count;                /* # of fb messages intercepted */
	/* congestion severity received on feedback message */
	/* with higher severity the increase function is slower */
	unsigned int congestion_severity;
};

struct rktnic {
	int ifindex;
	/* Rate & TC params */
	struct rk_traffic_info ti;
	struct tc_options tco;
	/* TODO: keep socket used to send fb
	 * Q: what if the interface is gone? */
	int sock;
	/* Hash */
	UT_hash_handle hh;

	int ref_count;
	unsigned int vnet_id;
};


/* functions to get a vnic/tnic in the hash table using the ifindex */
struct rkvnic *rkvnic_find(int ifindex, struct rkvnic **root);
struct rktnic *rktnic_find(int ifindex, struct rktnic **root);

/* Functions to add/delete a given rkvif or rktnic.  
 * They return 0 on success and -1 on failure */
struct rkvnic* rkvnic_add(int ifindex , struct rkvnic **root);
struct rktnic* rktnic_add(int ifindex , struct rktnic **root);
int rkvnic_del(int ifindex , struct rkvnic **vroot, struct rktnic **troot);
int rktnic_del(int ifindex , struct rktnic **root);

/* functions to associate/disassociate a tnic with a vnic */ 
int rk_tnic_get(struct rktnic *tnic, struct rkvnic *vnic);
int rk_tnic_put(struct rktnic *tnic, struct rkvnic *vnic, struct rktnic **troot);

/* functions to increment/decrement the tnic min rate called when
   a vnic is added/removed. The tnic min rate is the sum of the 
   min rates of all local vnics of that tenant  */
static inline void rktnic_rate_inc(struct rktnic *tnic, int rate)
{
	tnic->ti.min += rate;
}

static inline void rktnic_rate_dec(struct rktnic *tnic, int rate)
{
	tnic->ti.min -= rate;
}

#endif /* _RATEKEEPER_RKVIF_H_ */

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

/*
 * The ratekeeper daemon uses a hash table to maintain the state of
 * each monitor that is in the ratekeeper recovery phase. This file
 * defines the API of this hash table. rkinc is essentially a bucket,
 * and the functions to add, find, update and delete buckets are
 * defined after the rkinc structure. Ratekeeper currently uses uthash
 * as its underlying hash table implementation
 *  (http://uthash.sourceforge.net/) 
*/

#ifndef _RATEKEEPER_RKINC_H_
#define _RATEKEEPER_RKINC_H_

#include <uthash.h>
#include "rkvif.h"
/* extern struct rkvif; */

struct rkinc {
  int            vnic_ifindex;
  struct rkvnic  *vnic;
  /* Hash */
  UT_hash_handle hh;
};

int rkinc_add(struct rkinc *rki, struct rkinc **root);
int rkinc_del(struct rkinc *rki, struct rkinc **root);

#define rkinc_foreach(rki,aux,root)             \
  HASH_ITER(hh,*root,rki,aux)

#endif /* _RATEKEEPER_RKINC_H_ */

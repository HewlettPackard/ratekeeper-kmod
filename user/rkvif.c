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

#include <stdlib.h>
#include "rkvif.h"

struct rkvnic *rkvnic_add(int ifindex, struct rkvnic **root)
{
	struct rkvnic *vnic = malloc(sizeof(struct rkvnic));

	if (!vnic)
		return NULL;

	vnic->ifindex = ifindex;

	HASH_ADD_INT(*root, ifindex, vnic);
	return vnic;
}


struct rktnic *rktnic_add(int ifindex, struct rktnic **root)
{
	struct rktnic *tnic = malloc(sizeof(struct rktnic));

	if (!tnic)
		return NULL;

	tnic->ref_count = 0;
	tnic->ti.min = 0;
	tnic->ti.max = 0;
	tnic->ti.current = 0;

	tnic->ifindex = ifindex;

	HASH_ADD_INT(*root, ifindex, tnic);
	return tnic;
}


struct rkvnic *rkvnic_find(int ifindex, struct rkvnic **root)
{
	struct rkvnic *vnic_;
	HASH_FIND_INT(*root, &ifindex, vnic_);
	return vnic_;
}

struct rktnic *rktnic_find(int ifindex, struct rktnic **root)
{
	struct rktnic *tnic_;
	HASH_FIND_INT(*root, &ifindex, tnic_);
	return tnic_;
}

int rktnic_del(int ifindex, struct rktnic **root)
{
	struct rktnic *tnic;
	tnic = rktnic_find(ifindex, root);
	if (tnic) {
		HASH_DEL(*root, tnic);
		free(tnic);
		return 0;
	}
	return -1;
}

#ifdef RK_USE_TNIC
int rk_tnic_get(struct rktnic *tnic, struct rkvnic *vnic)
{
	vnic->tnic = tnic;
	tnic->ref_count++;
	return 0;
}

int rk_tnic_put(struct rktnic *tnic, struct rkvnic *vnic, struct rktnic **troot)
{
	vnic->tnic = NULL;
	tnic->ref_count--;
	
	if (tnic->ref_count <= 0)
		rktnic_del(tnic->ifindex, troot);

	return 0;
}
#endif


int rkvnic_del(int ifindex, struct rkvnic **vroot, struct rktnic **troot)
{
	struct rkvnic *vnic;
	vnic = rkvnic_find(ifindex, vroot);
	if (vnic) {
#ifdef RK_USE_TNIC
		rk_tnic_put(vnic->tnic, vnic, troot);
#endif
		HASH_DEL(*vroot, vnic);
		free(vnic);
		return 0;
	}
	return -1;
}

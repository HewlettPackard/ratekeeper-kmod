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
#include "rkinc.h"

struct rkinc *rkinc_find(struct rkinc *rki, struct rkinc **root)
{
	struct rkinc *rki_;
	HASH_FIND_INT(*root, &rki->vnic_ifindex, rki_);
	return rki_;
}

struct rkinc *rkinc_find_i(int ifindex, struct rkinc **root)
{
	struct rkinc *rki_;
	HASH_FIND_INT(*root, &ifindex, rki_);
	return rki_;
}

int rkinc_add(struct rkinc *rki, struct rkinc **root)
{
	if (!rkinc_find(rki, root)) {
		struct rkinc *rki_ = malloc(sizeof(struct rkinc));

		memcpy(rki_, rki, sizeof(struct rkinc));
		HASH_ADD_INT(*root, vnic_ifindex, rki_);
		return 1;
	}
	return 0;
}

int rkinc_del(struct rkinc *rki, struct rkinc **root)
{
	struct rkinc *rki_;
	rki_ = rkinc_find(rki, root);
	if (rki_) {
		HASH_DEL(*root, rki_);
		free(rki_);
		return 1;
	}
	return 0;
}

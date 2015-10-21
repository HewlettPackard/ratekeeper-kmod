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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>             /* ??? */
#include <arpa/inet.h>          /* hton* */

#include "../include/messaging_user.h"
#include "util.h"
#include "tc.h"
#include "ifcache.h"

extern struct tc_options tcopt;

/* fd of log file - TODO: logging utility (?) */
FILE *RKLOGFILE;
struct ifcache *ifcache_root = NULL;

static int rkmsg_send(void *msg, int len);
static int rkconfig_set(char **argv);
static int rkconfig_get(char **argv);
static int rkconfig_limits(char **argv);
static void usage(void);

/* Print rkmsgs */
static void print_rkreply(struct rkreply *msg);
static void print_rkdata(struct rkdata *msg);

int main(int argc, char *argv[])
{
	if (argc < 2 )
		usage();

	if (!strcmp(argv[1], "set") && argc == 7)
		rkconfig_set(&argv[2]);
	else if (!strcmp(argv[1], "get") && argc == 2)
		rkconfig_get(&argv[2]);
	else if (!strcmp(argv[1], "limits") && argc == 5)
		rkconfig_limits(&argv[2]);
	else
		usage();
	return 0;
}

static int rkconfig_limits(char **argv)
{
	int highmark, max_allocation, vnic_headroom;
	struct {
		struct rkmsg_header  h;
		struct rkmsg_limits  limits;
	} rkmsg;

	max_allocation = strtoul(argv[0], NULL, 10);
	if ( (max_allocation <= 0) || (max_allocation > 100000) ) {
	  fprintf(stderr, "ERROR: Link max allocation (%d) has to be greater than zero.\n",
		  max_allocation);
                exit(1);
	}
	highmark = strtoul(argv[1], NULL, 10);
	if ( highmark <= 0 ) {
	  fprintf(stderr, "ERROR: Link highmark (%d) has to be greater than zero.\n",
		  highmark);
                exit(1);
	}

	if ( max_allocation > highmark ) {
	  fprintf(stderr, "ERROR: Link highmark (%d) has to be larger or equal to max allocation (%d).\n", 
		  highmark, max_allocation);
                exit(1);
	}

	vnic_headroom = strtoul(argv[2], NULL, 10);
	if ( vnic_headroom < 0 ) {
	  fprintf(stderr, "ERROR: VNIC headroom (%d) has to be larger or equal to zero.\n",
		  highmark);
                exit(1);
	}

	/* Building rkmsg */
	memset(&rkmsg, 0, sizeof(rkmsg));
	rkmsg.h.cmd = htonl(RKMSG_LIMITS);
	rkmsg.limits.highmark = htonl(highmark);
	rkmsg.limits.max_allocation = htonl(max_allocation);
	rkmsg.limits.vnic_headroom = htonl(vnic_headroom);
	return rkmsg_send(&rkmsg, sizeof(rkmsg));
}

static int rkconfig_set(char **argv)
{
	char *vnic, *tnic;
	int min, max, vnet_id;
	struct tc_options *tco;
	struct {
		struct rkmsg_header h;
		struct rkdata       d;
	} rkmsg;

	vnic = argv[0];
	tnic = argv[1];

	min = strtoul(argv[2], NULL, 10);
	if (min < -1)
		eexit("value for MIN is invalid");
	max = strtoul(argv[3], NULL, 10);
	if (max < -1 || max == 0)
		eexit("value for MAX is invalid");
	vnet_id = strtoul(argv[4], NULL, 10);
	if (vnet_id < 0)
		eexit("value for VNET_ID is invalid");

	/* Building rkmsg */
	memset(&rkmsg, 0, sizeof(rkmsg));
	rkmsg.h.cmd = htonl(RKMSG_SET);
	strncpy(rkmsg.d.vnic, vnic, IFNAMSIZ);
	strncpy(rkmsg.d.tnic, tnic, IFNAMSIZ);
	rkmsg.d.min     = htonl(min);
	rkmsg.d.max     = htonl(max);
	rkmsg.d.vnet_id = htonl(vnet_id);

	for (tco = &rkmsg.d.vnic_tco; tco <= &rkmsg.d.tnic_tco; tco++) {
		tco->burst = htonl(tco->burst);
		tco->qsize = htonl(tco->qsize);
		tco->mtu   = htonl(tco->mtu);
	}

	/* tc_default_options(&rkmsg.d.vnic_tco, max); */
	/* tc_default_options(&rkmsg.d.tnic_tco, max); */
	return rkmsg_send(&rkmsg, sizeof(rkmsg));
}

static int rkconfig_get(char **argv)
{
	struct {
		struct rkmsg_header h;
	} rkmsg;

	/* Building rkmsg */
	memset(&rkmsg, 0, sizeof(rkmsg));
	rkmsg.h.cmd = htonl(RKMSG_GET);
	return rkmsg_send(&rkmsg, sizeof(rkmsg));
}

static int rkmsg_send(void *msg, int len)
{
	struct sockaddr_in addr;
	struct rkmsg_header *rkmsghdr;
	struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	char buf[256];
	int sock, err;
	fd_set fd;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		eexit("could not open remote socket");

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(RKCONFIG_PORT);
	addr.sin_addr.s_addr = htonl(0x7F000001); /* = 127.0.0.1 localhost */

	if (sendto(sock, msg, len, 0, (struct sockaddr *) &addr,
			   sizeof(struct sockaddr_in)) < 0)
		eexit("send error");

	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	if (select(sock+1, &fd, NULL, NULL, &timeout)) {
		while ((err = recv(sock, buf, 256, MSG_DONTWAIT)) > 0) {
			rkmsghdr = (void*) buf;
			switch(ntohl(rkmsghdr->cmd)) {
			case RKMSG_REPLY:
				print_rkreply((void *)rkmsghdr + sizeof(struct rkmsg_header));
				break;
			case RKMSG_GET:
				print_rkdata((void *)rkmsghdr + sizeof(struct rkmsg_header));
				break;
			default:
				printf("Unknown rkmsg received, rkmsg_cmd = 0x%4x \n",
					   ntohl(rkmsghdr->cmd));
			}
		}
	}
	else
		printf("Request timed out\n");
	return 0;
}

static void print_rkreply(struct rkreply *rkr)
{
	switch (ntohl(rkr->rc)) {
	case RK_RC_SUCCESS:
		printf("Command executed successfully by rk-daemon\n");
		return;
	case RK_RC_MISSING_ATTR:
		printf("One or more attributes are missing\n");
		return;
	case RK_RC_ERR_IF:
		printf("Interface not found\n");
		return;
	default:
		printf("Unknown error\n");
	}
}

static void print_rkdata(struct rkdata *rkd)
{
	static int print_header = 1;
	if (print_header) {
		printf("%-16s%-16s%-16s%-16s%-16s%-16s%-16s\n", "VNIC", "TNIC",
		       "VNET_ID", "MIN(mbps)", "MAX(mbps)", "CURRENT(mbps)",
		       "#FB");
		print_header = 0;
	}
	printf("%-16s%-16s%-16d%-16d%-16d%-16d%-16d\n", rkd->vnic, rkd->tnic,
	       ntohl(rkd->vnet_id), ntohl(rkd->min), ntohl(rkd->max),
	       ntohl(rkd->thput), ntohl(rkd->fb_count));
}


static void usage(void)
{
	printf("Usage: rkconfig set <VNIC> <TNIC> <MIN> <MAX> <VNET_ID>\n"
		   "                get\n"
		   "                limits <link max_allocation> <link highmark> <vnic headroom>\n"
		   "       The values for MIN, MAX  should be given in mbit/s\n\n."
		   "       max_allocation <= highmark, are also specified in mbit/s\n."
	           "       vnic headroom is given in units of 0.1%% of the max rate"
	           "       (e.g. for a vnic with max=1000Mb/s and headroom=50 (5%%) "
	           "       the rate monitor in ratekeeper kernel is configured with 1050Mb/s)\n" );
	exit(0);
}


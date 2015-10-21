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

#ifndef __UTIL_H_
#define __UTIL_H_

#define ETH_ADDR_FMT       "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_ARGS(ea)  (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define DEBUG              10
//#define DEBUG              0
#define DEBUGMSG(l, ...) {if(DEBUG >= l){ fprintf (RKLOGFILE, __VA_ARGS__); \
      fflush(RKLOGFILE); }}

/* TODO: This should be replaced with a function that receives a
   va_list as arg */
#define WARN(s)            { fprintf(RKLOGFILE, s);         \
    fflush(RKLOGFILE); }
#define WARN1(s,a1)        { fprintf(RKLOGFILE, s, a1);     \
    fflush(RKLOGFILE); }
#define WARN2(s,a1,a2)     { fprintf(RKLOGFILE, s, a1, a2); \
    fflush(RKLOGFILE); }

char *str_alloc(char *fmt, ...);
void run(char *cmd_fmt, ...);
int  prun(char *str1, char *str2, char *cmd_fmt, ...);
void eexit(char *err);
void ppacket(char *buf, int len);

#endif /* __UTIL_H_ */

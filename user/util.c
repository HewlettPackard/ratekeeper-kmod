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
#include <string.h>
#include <stdarg.h>
#include "util.h"

#define STR_DEFAULT_SIZE 256

extern FILE *RKLOGFILE;

static char *str_alloc_valist(char *fmt, va_list _args)
{
	char *str;
	int needed;
	va_list args;

	str = malloc(STR_DEFAULT_SIZE);
	va_copy(args, _args);
	needed = vsnprintf(str, STR_DEFAULT_SIZE, fmt, args);
	va_end(args);
	if (needed > STR_DEFAULT_SIZE) {
		str = realloc(str, needed + 1);
		va_copy(args, _args);
		vsnprintf(str, STR_DEFAULT_SIZE, fmt, args);
		va_end(args);
	}
	return str;
}

char *str_alloc(char *fmt, ...)
{
	char *str;
	va_list args;

	va_start(args, fmt);
	str = str_alloc_valist(fmt, args);
	va_end(args);
	return str;
}

void run(char *cmd_fmt, ...)
{
	char cmd[1024];
	va_list args;
	int stat;

	va_start(args, cmd_fmt);
	if(vsnprintf(cmd, 1024, cmd_fmt, args) >= 1024)
		eexit("command length too big!");
	va_end(args);

	DEBUGMSG(2, "=======\nrunning:\n%s\n", cmd);
	stat = system(cmd);
	if (stat != 0)
		fprintf(RKLOGFILE,"Command FAILED: %s\n", cmd);
	if (stat == -1)
		eexit("could not run the command");

}

/* Parse the output of the command specified by last args.
 *
 * Returns 1 if str1 and str2 are both in one of the output lines and
 * 0 otherwise. */
int prun(char *str1, char *str2, char *cmd_fmt, ...)
{
	FILE *pipe;
	char buf[1024];
	va_list args;
	int ret;

	va_start(args, cmd_fmt);
	if(vsnprintf(buf, 1024, cmd_fmt, args) >= 1024)
		eexit("command length too big!");
	va_end(args);

	DEBUGMSG(2,"=======\nrunning:\n%s\n", buf);
	pipe = popen(buf, "r");
	if (pipe == NULL)
		eexit("could not open pipe");

	ret = 0;
	while(!feof(pipe))
		if (fgets(buf, 1024, pipe) != NULL)
			if (strstr(buf, str1) && strstr(buf, str2)) {
				ret = 1;
				break;
			}
	pclose(pipe);
	return ret;
}

void eexit(char *err)
{
	fprintf(RKLOGFILE, "Error: %s\n", err);
	fflush(RKLOGFILE);
	exit(0);
}

void ppacket(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (i != 0 && !(i % 4))
			fprintf(RKLOGFILE, "\n");
		fprintf(RKLOGFILE, "%02x ",(unsigned char)buf[i]);
	}
	fprintf(RKLOGFILE, "\n");
}

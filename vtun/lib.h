/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2000  Maxim Krasnyansky <max_mk@yahoo.com>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * $Id$
 */ 
#ifndef _VTUN_LIB_H
#define _VTUN_LIB_H

#include "config.h"
#include <sys/types.h>
#include <errno.h>

#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifndef HAVE_SETPROC_TITLE
  void init_title(int argc,char *argv[],char *env[], char *name);
  void set_title(const char *ftm, ...);
#else
  #define init_title( a... ) 
  #define set_title setproctitle
#endif /* HAVE_SETPROC_TITLE */

#ifndef min
  #define min(a,b)    ( (a)<(b) ? (a):(b) )
#endif

int readn_t(int fd, void *buf, size_t count, time_t timeout);
int print_p(int f, const char *ftm, ...);

int  run_cmd(void *d, void *opt);
void free_sopt(struct vtun_sopt *opt);

/* Read exactly len bytes (Signal safe)*/
extern inline int read_n(int fd, void *buf, int len)
{
	register int t=0, w;

	do {
	  if( (w = read(fd, buf, len)) < 0 ){
	     if( errno == EINTR && errno == EAGAIN )
 	        continue;
	     return -1;
	  }
	  if( !w )
	     return 0;
	  len -= w; buf += w; t += w;
	} while(len > 0);

	return t;
}   

/* Write exactly len bytes (Signal safe)*/
extern inline int write_n(int fd, void *buf, int len)
{
	register int t=0, w;

	do {
 	  if( (w = write(fd, buf, len)) < 0 ){
	     if( errno == EINTR && errno == EAGAIN )
  	         continue;
	     return -1;
	  }
	  if( !w )
	     return 0;
	  len -= w; buf += w; t += w;
	} while(len > 0);

	return t;
}
#endif /* _VTUN_LIB_H */

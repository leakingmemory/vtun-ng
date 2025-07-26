/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>

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
 * $Id: lib.h,v 1.7.2.4 2016/10/01 21:27:51 mtbishop Exp $
 */ 
#ifndef _VTUN_LIB_H
#define _VTUN_LIB_H

#include "config.h"
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef __linux__
#include <bsd/unistd.h>  /* For setproctitle on Linux */
#endif


#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifndef HAVE_SETPROC_TITLE
  void init_title(int argc,char *argv[],char *env[], char *name);
  void set_title(const char *ftm, ...);
#else
#ifdef HAVE_SETPROCTITLE_INIT
    #define init_title(argc, argv, env, title) { setproctitle_init(argc, argv, env); setproctitle(title); }
#else
    #define init_title( a... )
#endif
  #define set_title setproctitle
#endif /* HAVE_SETPROC_TITLE */

#ifndef min
  #define min(a,b)    ( (a)<(b) ? (a):(b) )
#endif

int readn_t(int fd, void *buf, size_t count, time_t timeout);
int print_p(int f, const char *ftm, ...);

/* signal safe syslog function */
void vtun_syslog (int priority, char *format, ...);

int is_io_cancelled(void);

/* Write exactly len bytes (Signal safe)*/
static inline int write_n(int fd, char *buf, int len)
{
	register int t=0, w;

	while (!is_io_cancelled() && len > 0) {
 	  if( (w = write(fd, buf, len)) < 0 ){
	     if( errno == EINTR || errno == EAGAIN )
  	         continue;
	     return -1;
	  }
	  if( !w )
	     return 0;
	  len -= w; buf += w; t += w;
	}

	return t;
}
#endif /* _VTUN_LIB_H */

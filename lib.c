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
 * $Id: lib.c,v 1.9.2.5 2016/10/01 21:46:01 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#ifndef HAVE_SETPROC_TITLE
/* Functions to manipulate with program title */

extern char **environ;
static char	*title_start;	/* start of the proc title space */
static char	*title_end;     /* end of the proc title space */
static int	title_size;

void init_title(int argc,char *argv[], char *envp[], char *name)
{
	int i;

	/*
	 *  Move the environment so settitle can use the space at
	 *  the top of memory.
	 */

	for (i = 0; envp[i]; i++);

	environ = (char **) malloc(sizeof (char *) * (i + 1));

	for(i = 0; envp[i]; i++)
	   environ[i] = strdup(envp[i]);
	environ[i] = NULL;

	/*
	 *  Save start and extent of argv for set_title.
	 */

	title_start = argv[0];

	/*
	 *  Determine how much space we can use for set_title.  
	 *  Use all contiguous argv and envp pointers starting at argv[0]
 	 */
	for(i=0; i<argc; i++)
	    if( !i || title_end == argv[i])
	       title_end = argv[i] + strlen(argv[i]) + 1;

	for(i=0; envp[i]; i++)
  	    if( title_end == envp[i] )
	       title_end = envp[i] + strlen(envp[i]) + 1;
	
	strcpy(title_start, name);
	title_start += strlen(name);
	title_size = title_end - title_start;
}

void set_title(const char *fmt, ...)
{
	char buf[255];
	va_list ap;

	memset(title_start,0,title_size);

	/* print the argument string */
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	if( strlen(buf) > title_size - 1)
	   buf[title_size - 1] = '\0';

	strcat(title_start, buf);
}
#endif  /* HAVE_SETPROC_TITLE */

void set_title_str(const char *str) {
    set_title("%s", str);
}

/* 
 * Print padded messages.
 * Used by 'auth' function to force all messages 
 * to be the same len.
 */
int print_p(int fd,const char *fmt, ...)
{
	char buf[VTUN_MESG_SIZE];
	va_list ap;

	memset(buf,0,sizeof(buf));

	/* print the argument string */
	va_start(ap, fmt);
	vsnprintf(buf,sizeof(buf)-1, fmt, ap);
	va_end(ap);
  
	return write_n(fd, buf, sizeof(buf));
}

void vtun_syslog (int priority, char *format, ...)
{
   static volatile sig_atomic_t in_syslog= 0;
   char buf[255];
   va_list ap;

   if(! in_syslog) {
      in_syslog = 1;
    
      va_start(ap, format);
      vsnprintf(buf, sizeof(buf)-1, format, ap);
      syslog(priority, "%s", buf);
      closelog();
      va_end(ap);

      in_syslog = 0;
   }
}

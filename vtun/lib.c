/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998,1999  Maxim Krasnyansky <max_mk@yahoo.com>

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
 * Version: 2.0 12/30/1999 Maxim Krasnyansky <max_mk@yahoo.com>
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

extern int errno;

#ifndef HAVE_SETPROC_TITLE
/* Functions to manipulate with program title */

extern char **environ;
char	*title_start;	/* start of the proc title space */
char	*title_end;     /* end of the proc title space */
int	title_size;

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

/* 
 * Allocate pseudo tty, returns master side fd. 
 * Stores slave name in the first arg(must be large enough).
 */  
int getpty(char *sl_name)
{
	char ptyname[] = "/dev/ptyXY";
	char ch[] = "pqrstuvwxyz";
	char digit[] = "0123456789abcdefghijklmnopqrstuv";
	int  l, m;
	int  mr_fd;

	/* This algorithm should work for almost all standard Unices */	
	for(l=0; ch[l]; l++ ) {
 	    for(m=0; digit[m]; m++ ) {
	 	ptyname[8] = ch[l];
		ptyname[9] = digit[m];
		/* Open the master */
		if( (mr_fd=open(ptyname, O_RDWR)) < 0 )
	 	   continue;
		/* Check the slave */
		ptyname[5] = 't';
		if( (access(ptyname, R_OK | W_OK)) < 0 ){
		   close(mr_fd);
		   ptyname[5] = 'p';
		   continue;
		}
		strcpy(sl_name,ptyname);
		return mr_fd;
	    }
	}
	return -1;
}

/* 
 * Allocate Ether TAP device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */  
int gettap(char *dev)
{
	char tapname[14];
	int i, fd;

	if( *dev ) {
	   sprintf(tapname, "/dev/%s", dev);
	   return open(tapname, O_RDWR);
	}

	for(i=0; i < 255; i++) {
	   sprintf(tapname, "/dev/tap%d", i);
	   /* Open device */
	   if( (fd=open(tapname, O_RDWR)) > 0 ) {
	      sprintf(dev, "tap%d",i);
	      return fd;
	   }
	}
	return -1;
}

/* Allocate TUN device. */  
int gettun(char *dev)
{
	char tunname[14];
	int i, fd;

	if( *dev ) {
	   sprintf(tunname, "/dev/%s", dev);
	   return open(tunname, O_RDWR);
	}

	for(i=0; i < 255; i++){
	   sprintf(tunname, "/dev/tun%d", i);
	   /* Open device */
	   if( (fd=open(tunname, O_RDWR)) > 0 ){
	      sprintf(dev, "tun%d", i);
	      return fd;
	   }
	}
	return -1;
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

/* Connect with timeout */
int connect_t(int s, struct sockaddr *svr, time_t timeout) 
{
	int sock_flags;
	fd_set fdset;
	struct timeval tv;

	tv.tv_usec=0; tv.tv_sec=timeout;

	sock_flags=fcntl(s,F_GETFL);
	if( fcntl(s,F_SETFL,O_NONBLOCK) < 0 )
	  return -1;

	if( connect(s,svr,sizeof(struct sockaddr)) < 0 && errno != EINPROGRESS)
	   return -1;

	FD_ZERO(&fdset);
	FD_SET(s,&fdset);
	if( select(s+1,NULL,&fdset,NULL,&tv) > 0 ){
	   int l=sizeof(errno);	 
 	   errno=0;
 	   getsockopt(s,SOL_SOCKET,SO_ERROR,&errno,&l);
	} else
	   errno=ETIMEDOUT;  	

	fcntl(s,F_SETFL,sock_flags); 

 	if(errno)
	   return -1;

	return 0;
}	

/* Read N bytes with timeout */
int readn_t(int fd, void *buf, size_t count, time_t timeout) 
{
	fd_set fdset;
	struct timeval tv;

	tv.tv_usec=0; tv.tv_sec=timeout;

	FD_ZERO(&fdset);
	FD_SET(fd,&fdset);
	if( select(fd+1,&fdset,NULL,NULL,&tv) <= 0)
	   return -1;

	return read_n(fd, buf, count);
}

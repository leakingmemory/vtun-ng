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

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

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
#include "lib.h"

int tcp_write(int fd, char *buf, int len)
{
     unsigned short nlen, cnt; 
     struct iovec iv[2];

     nlen = htons(len); 
     len  = len & VTUN_FSIZE_MASK;

     iv[0].iov_len  = sizeof(short); 
     iv[0].iov_base = (char *) &nlen; 
     if( buf ) {
        iv[1].iov_len  = len; 
        iv[1].iov_base = buf;
	cnt = 2;
     } else {
        /* Write flags only */
	cnt = 1;
     }

     while(1) {
        register int err;
	err = writev(fd, iv, cnt); 
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	if( err > 0 && err < (len + sizeof(short)) ) {
	   /* We wrote only part of the frame, lets write the rest
	    * FIXME should check if wrote less than sizeof(short) */
	   err -= sizeof(short);
	   return write_n(fd, buf + err, len - err);
	}

	return err;
     }
}

int tcp_read(int fd, char *buf)
{
     unsigned short len, flen;
     register int err;     

     /* Read frame size */
     if( (err = read_n(fd, (char *)&len, sizeof(short)) ) < 0)
	return err;

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ) {
     	/* Oversized frame, drop it. */ 
        while(flen) {
	   len = min(flen, VTUN_FRAME_SIZE);
           if( (len = read_n(fd, buf, len)) <= 0 )
	      break;
           flen -= len;
        }                                                               
	return VTUN_BAD_FRAME;
     }	

     if( len & ~VTUN_FSIZE_MASK ) {
	/* Return flags */
	return len;
     }

     /* Read frame */
     return read_n(fd, buf, flen);
}

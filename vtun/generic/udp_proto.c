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
#include <ctype.h>
#include <stdarg.h>
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
#include <netinet/udp.h>
#endif

#include "vtun.h"
#include "lib.h"

/* Functions to read/write TCP and UDP frames. */
int udp_write(int fd, char *buf, int len)
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
	if( err < 0 ){
	   if( errno == EAGAIN || errno == EINTR )
	      continue;
	   if( errno == ENOBUFS )
	      return 0;
	}
	/* Even if we wrote only part of the frame
         * we can't use second write since it will produce 
         * another UDP frame */  
        return err;
     }
}

int udp_read(int fd, char *buf)
{
     unsigned short len, flen, cnt;
     struct iovec iv[2];

     /* Get frame size */
     while(1) {
	register int err;     
        if( (err = recv(fd, &len, sizeof(short), MSG_PEEK)) > 0)
	   break;
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	return err;
     }

     len = ntohs(len);
     flen = len & VTUN_FSIZE_MASK;

     if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ) {
     	/* Oversized frame, drop it.  
	 * On UDP socket read will drop remaining part of the frame */
        read(fd, buf, VTUN_FRAME_SIZE);
	return VTUN_BAD_FRAME;
     }	

     /* Read frame */
     iv[0].iov_len  = sizeof(short);
     iv[0].iov_base = (char *) &flen;
     if( len & ~VTUN_FSIZE_MASK ) {
	/* Read flags only */
	cnt = 1;
     } else {	
        iv[1].iov_len  = flen;
        iv[1].iov_base = buf;
	cnt = 2;
     }

     while(1) {
	register int err;     
	errno = 0;
        if( (err = readv(fd, iv, cnt)) > 0) 
	   return len;
	if( err < 0 && ( errno == EAGAIN || errno == EINTR ) )
	   continue;
	return err;
     }
}		

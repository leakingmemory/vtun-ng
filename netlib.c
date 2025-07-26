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
 * $Id: netlib.c,v 1.11.2.5 2016/10/01 21:46:01 mtbishop Exp $
 */ 

#include "config.h"
#include "vtun_socks.h"

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
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

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

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "netlib.h"

/*
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error.
 */
int udp_session(struct vtun_host *host) 
{
     struct sockaddr_in saddr; 
     short port;
     int s,opt;
     extern int is_rmt_fd_connected;

     if( (s=socket(AF_INET,SOCK_DGRAM,0))== -1 ){
        vtun_syslog(LOG_ERR,"Can't create socket");
        return -1;
     }

     opt=1;
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 
    
     /* Set local address and port */
     local_addr(&saddr, host, 1);
     if( bind(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vtun_syslog(LOG_ERR,"Can't bind to the socket");
        return -1;
     }

     opt = sizeof(saddr);
     if( getsockname(s,(struct sockaddr *)&saddr,&opt) ){
        vtun_syslog(LOG_ERR,"Can't get socket name");
        return -1;
     }

     /* Write port of the new UDP socket */
     port = saddr.sin_port;
     if( write_n(host->rmt_fd,(char *)&port,sizeof(short)) < 0 ){
        vtun_syslog(LOG_ERR,"Can't write port number");
        return -1;
     }
     host->sopt.lport = htons(port);

     /* Read port of the other's end UDP socket */
     if( readn_t(host->rmt_fd,&port,sizeof(short),host->timeout) < 0 ){
        vtun_syslog(LOG_ERR,"Can't read port number %s", strerror(errno));
        return -1;
     }

     opt = sizeof(saddr);
     if( getpeername(host->rmt_fd,(struct sockaddr *)&saddr,&opt) ){
        vtun_syslog(LOG_ERR,"Can't get peer name");
        return -1;
     }

     saddr.sin_port = port;

     /* if the config says to delay the UDP connection, we wait for an
	incoming packet and then force a connection back.  We need to
	put this here because we need to keep that incoming triggering
	packet and pass it back up the chain. */

     if (VTUN_USE_NAT_HACK(host))
     	is_rmt_fd_connected=0;
	else {
     if( connect(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
        vtun_syslog(LOG_ERR,"Can't connect socket");
        return -1;
     }
     is_rmt_fd_connected=1;
	}
     
     host->sopt.rport = htons(port);

     /* Close TCP socket and replace with UDP socket */	
     close(host->rmt_fd); 
     host->rmt_fd = s;	

     vtun_syslog(LOG_INFO,"UDP connection initialized");
     return s;
}

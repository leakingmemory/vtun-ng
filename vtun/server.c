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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "lock.h"
#include "auth.h"

#include "compat.h"

void connection(int sock)
{
     struct sockaddr_in my_addr, cl_addr;
     struct vtun_host *host;
     struct sigaction sa;
     char *ip;
     int opt;

     opt = sizeof(struct sockaddr_in);
     if( getpeername(sock, (struct sockaddr *) &cl_addr, &opt) ){
        syslog(LOG_ERR, "Can't get peer name");
        exit(-1);
     }
     opt = sizeof(struct sockaddr_in);
     if( getsockname(sock, (struct sockaddr *) &my_addr, &opt) < 0 ){
        syslog(LOG_ERR,"Can't get local socket address");
        exit(-1); 
     }

     ip = strdup(inet_ntoa(cl_addr.sin_addr));

     if( (host=auth_server(sock)) ){	
        sa.sa_handler=SIG_IGN;
	sa.sa_flags=SA_NOCLDWAIT;;
        sigaction(SIGHUP,&sa,NULL);

	syslog(LOG_INFO,"Session %s[%s:%d] opened", host->host, ip, 
					ntohs(cl_addr.sin_port) );
        host->rmt_fd = sock; 
	
        host->sopt.laddr = strdup(inet_ntoa(my_addr.sin_addr));
        host->sopt.lport = vtun.svr_port;
        host->sopt.raddr = strdup(ip);
	host->sopt.rport = ntohs(cl_addr.sin_port);

	/* Start tunnel */
	tunnel(host);

	syslog(LOG_INFO,"Session %s closed", host->host);

	/* Unlock host. (locked in auth_server) */	
	unlock_host(host);
     } else {
        syslog(LOG_INFO,"Denied connection from %s:%d", ip,
					ntohs(cl_addr.sin_port) );
     }
     close(sock);

     exit(0);
}

void listener(void)
{
     struct sockaddr_in my_addr, cl_addr;
     int s, s1, opt;

     memset(&my_addr, 0, sizeof(my_addr));
     my_addr.sin_family = AF_INET;
     my_addr.sin_addr.s_addr = INADDR_ANY;
     my_addr.sin_port = htons(vtun.svr_port);	

     if( (s=socket(AF_INET,SOCK_STREAM,0))== -1 ){
	syslog(LOG_ERR,"Can't create socket");
	exit(1);
     }

     opt=1;
     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); 

     if( bind(s,(struct sockaddr *)&my_addr,sizeof(my_addr)) ){
	syslog(LOG_ERR,"Can't bind to the socket");
	exit(1);
     }

     if( listen(s, 10) ){
	syslog(LOG_ERR,"Can't listen on the socket");
	exit(1);
     }

     set_title("waiting for connections on port %d", vtun.svr_port);

     while(1){
        opt=sizeof(cl_addr);
	if( (s1=accept(s,(struct sockaddr *)&cl_addr,&opt)) == -1 )
	   continue; 

	switch( fork() ){
	   case 0:
	      connection(s1);
	      break;
	   case -1:
	      syslog(LOG_ERR, "Couldn't fork()");
	   default:
	      close(s1);
	      break;
	}
     }  
}	

void server(int sock)
{
     struct sigaction sa;

     sa.sa_handler=SIG_IGN;
     sa.sa_flags=SA_NOCLDWAIT;;
     sigaction(SIGINT,&sa,NULL);
     sigaction(SIGQUIT,&sa,NULL);
     sigaction(SIGCHLD,&sa,NULL);
     sigaction(SIGPIPE,&sa,NULL);

     syslog(LOG_INFO,"VTUN server ver %s (%s)", VER,
		vtun.svr_type == VTUN_INETD ? "inetd" : "stand" );

     switch( vtun.svr_type ){
	case VTUN_STAND_ALONE:
	   listener();
	   break;
        case VTUN_INETD:
	   connection(sock);
	   break;
     }    
}

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "auth.h"
#include "compat.h"

static int client_term;
static void sig_term(int sig)
{
     syslog(LOG_INFO,"Terminated by user");
     client_term = -1;
}

void client(struct vtun_host *host)
{
     struct sockaddr_in my_addr,svr_addr;
     struct hostent *hent;
     struct sigaction sa;
     int s;	

     syslog(LOG_INFO,"VTun client ver %s started",VER);

     memset(&sa,0,sizeof(sa));     
     sa.sa_handler=SIG_IGN;
     sa.sa_flags = SA_NOCLDWAIT;
     sigaction(SIGHUP,&sa,NULL);
     sigaction(SIGINT,&sa,NULL);
     sigaction(SIGQUIT,&sa,NULL);
     sigaction(SIGPIPE,&sa,NULL);
     sigaction(SIGCHLD,&sa,NULL);

     sa.sa_handler=sig_term;
     sigaction(SIGTERM,&sa,NULL);
 
     memset(&my_addr,0,sizeof(my_addr));
     my_addr.sin_family = AF_INET;
     my_addr.sin_addr.s_addr = vtun.laddr;
     my_addr.sin_port = 0;	

     memset(&svr_addr,0,sizeof(my_addr));
     svr_addr.sin_family = AF_INET;
     svr_addr.sin_port = htons(vtun.port);	

     client_term = 0;
     while( !client_term ){ 
	/* Lookup server's IP address.
	 * We do it on every reconnect because server's IP 
	 * address can be dynamic.
	 */
        if( !(hent = gethostbyname(vtun.svr_name)) ){
           syslog(LOG_ERR, "Can't resolv server address %s",vtun.svr_name);
           exit(1);
        }
        svr_addr.sin_addr.s_addr = *(unsigned long *)hent->h_addr; 

	/* We have to create socket again every time
	 * we want to connect, since STREAM sockets 
	 * can be successfully connected only once.
	 */
        if( (s=socket(AF_INET,SOCK_STREAM,0))==-1 ){
	   syslog(LOG_ERR,"Can not create socket");
	   exit(1);
        }

        if( bind(s,(struct sockaddr *)&my_addr,sizeof(my_addr)) ){
	   syslog(LOG_ERR,"Can not bind to the socket");
	   exit(1);
        }

        syslog(LOG_INFO,"Connecting to %s", vtun.svr_name);
	set_title("connecting to %s", vtun.svr_name);

        /* 
         * Clear speed and flags which will be supplied by server. 
         */
        host->spd_in = host->spd_out = 0;
        host->flags &= VTUN_CLNT_MASK;

        if( connect_t(s,(struct sockaddr *) &svr_addr, vtun.timeout) ){
	   syslog(LOG_INFO,"Can't connect to %s",vtun.svr_name);
        } else {
	   if( auth_client(s, host) ){   
	      syslog(LOG_INFO,"Session %s[%s] opened",host->host,vtun.svr_name);

 	      host->rmt_fd = s;

	      /* Start the tunnel */
	      client_term = tunnel(host);

	      syslog(LOG_INFO,"Session %s[%s] closed",host->host,vtun.svr_name);
	   } else {
	      syslog(LOG_INFO,"Connection denied by %s",vtun.svr_name);
	   }
	   close(s);
	}
	
	/* If persist option is set, sleep and try to reconnect */
	if( !client_term && vtun.persist > 0 ) 
	  sleep(5);
        else
	  break;
     }
     syslog(LOG_INFO,"Exit");
     return;
}


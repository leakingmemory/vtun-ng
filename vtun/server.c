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
#include <signal.h>
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

#include "vtun.h"
#include "lib.h"
#include "auth.h"

#include "compat.h"

void server(void)
{
     struct sockaddr_in my_addr,cl_addr;
     struct sigaction sa;
     struct vtun_host *host;
     int  s,s1;
     int  opt;
     char *ip;

     sa.sa_handler=SIG_IGN;
     sa.sa_flags=SA_NOCLDWAIT;;
     sigaction(SIGINT,&sa,NULL);
     sigaction(SIGQUIT,&sa,NULL);
     sigaction(SIGCHLD,&sa,NULL);
     sigaction(SIGPIPE,&sa,NULL);

     memset(&my_addr,0,sizeof(my_addr));
     my_addr.sin_family = AF_INET;
     my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
     my_addr.sin_port = htons(vtun.port);	

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

     if( listen(s,5) ){
	syslog(LOG_ERR,"Can't listen on the socket");
	exit(1);
     }

     syslog(LOG_INFO,"VTUN server ver %s started ",VER);

     set_title("waiting for connections on port %d",vtun.port);

     while(1){
        opt=sizeof(cl_addr);
	if( (s1=accept(s,(struct sockaddr *)&cl_addr,&opt)) == -1 )
	   continue; 

	if( !fork() ){
	   ip=inet_ntoa(cl_addr.sin_addr);
	   if( (host=auth_server(s1)) ){	
              sa.sa_handler=SIG_IGN;
              sigaction(SIGHUP,&sa,NULL);

	      syslog(LOG_INFO,"Session %s[%s] opened ", host->host, ip);

              host->rmt_fd = s1; 
	
	      /* Start tunnel */
	      tunnel(host);

	      syslog(LOG_INFO,"Session %s[%s] closed", host->host, ip);
	   } else {
	      syslog(LOG_INFO,"Denied connection from %s", ip);
	   }
	   close(s1);
	   exit(0);
        }
	close(s1);
     }  
}	

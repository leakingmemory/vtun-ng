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
#include <signal.h>

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
#include "netlib.h"
#include "driver.h"

int (*dev_write)(int fd, char *buf, int len);
int (*dev_read)(int fd, char *buf, int len);

int (*proto_write)(int fd, char *buf, int len);
int (*proto_read)(int fd, char *buf);

/* Initialize and start the tunnel.
   Returns:
      -1 - critical error
      0  - normal close or noncritical error 
*/
   
int tunnel(struct vtun_host *host)
{
     int null_fd, pid, opt;
     int fd[2]={-1, -1};
     char dev[12]="";

     /* Initialize device. */
     if( host->dev )
        strcpy(dev, host->dev); 
     switch( host->flags & VTUN_TYPE_MASK ){
	case VTUN_TTY:
	   if( (fd[0]=pty_alloc(dev)) < 0 ){
	      syslog(LOG_ERR,"Can't allocate pseudo tty");
	      return -1;
           }
	   break;

	case VTUN_PIPE:
	   if( pipe_alloc(fd) < 0 ){
 	      syslog(LOG_ERR,"Can't create pipe");
   	      return -1;
	   }
	   break;

	case VTUN_ETHER:
	   if( (fd[0]=tap_alloc(dev)) < 0 ){
 	      syslog(LOG_ERR,"Can't allocate tap device");
   	      return -1;
	   }
	   break;

	case VTUN_TUN:
	   if( (fd[0]=tun_alloc(dev)) < 0 ){
 	      syslog(LOG_ERR,"Can't allocate tun device");
   	      return -1;
	   }
	   break;
     }

     /* Initialize protocol. */
     switch( host->flags & VTUN_PROT_MASK ){
        case VTUN_TCP:
	   opt=1;
	   setsockopt(host->rmt_fd,SOL_SOCKET,SO_KEEPALIVE,&opt,sizeof(opt) );

	   opt=1;
	   setsockopt(host->rmt_fd,IPPROTO_TCP,TCP_NODELAY,&opt,sizeof(opt) );

	   proto_write = tcp_write;
	   proto_read  = tcp_read;

	   break;

        case VTUN_UDP:
	   if( (opt = udp_session(host, VTUN_TIMEOUT)) == -1){
	      syslog(LOG_ERR,"Can't establish UDP session");
	      close(fd[0]); close(fd[1]);
	      return 0;
	   } 	

 	   proto_write = udp_write;
	   proto_read = udp_read;

	   break;
     }

     switch( (pid=fork()) ){
	case -1:
	   syslog(LOG_ERR,"Couldn't fork()");
	   close(fd[0]); close(fd[1]);
	   return 0;
	case 0:
     	   switch( host->flags & VTUN_TYPE_MASK ){
	      case VTUN_TTY:
	         /* Open pty slave (becomes controlling terminal) */
	         if( (fd[1] = open(dev, O_RDWR)) < 0){
	            syslog(LOG_ERR,"Couldn't open slave pty");
	            exit(0);
	         }
		 /* Fall through */
	      case VTUN_PIPE:
	         null_fd = open("/dev/null", O_RDWR);
	         close(fd[0]);
	         close(0); dup(fd[1]);
                 close(1); dup(fd[1]);
	         close(fd[1]);

	         /* Route stderr to /dev/null */
	         close(2); dup(null_fd);
	         close(null_fd);
	         break;
	      case VTUN_ETHER:
	      case VTUN_TUN:
		 break;
	   }

	   /* Run list of up commands */
	   set_title("%s running up commands", host->host);
	   llist_trav(&host->up, run_cmd, &host->sopt);

   	   exit(0);           
	default:
	   switch( host->flags & VTUN_TYPE_MASK ){
	      case VTUN_TTY:
	         set_title("%s tty", host->host);

		 dev_read  = pty_read;
  		 dev_write = pty_write; 
	         break;

	      case VTUN_PIPE:
		 /* Close second end of the pipe */
		 close(fd[1]);
	         set_title("%s pipe", host->host);

		 dev_read  = pipe_read;
  		 dev_write = pipe_write; 
	  	 break;

	      case VTUN_ETHER:
	         set_title("%s ether %s", host->host, dev);

		 dev_read  = tap_read;
  		 dev_write = tap_write; 
	   	 break;

	      case VTUN_TUN:
	         set_title("%s tun %s", host->host, dev);

		 dev_read  = tun_read;
  		 dev_write = tun_write; 
	   	 break;
     	   }

     	   host->sopt.dev = strdup(dev);
	   host->loc_fd = fd[0];
	   opt = linkfd(host);

	   set_title("%s running down commands", host->host);
	   llist_trav(&host->down,run_cmd, &host->sopt);

	   set_title("%s closing", host->host);

	   /* Close all fds */
	   close(host->loc_fd); close(host->rmt_fd);
	   close(fd[0]); close(fd[1]);	

	   return opt;
     }
}

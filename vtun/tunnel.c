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

/* 
 * Establish UDP session with host connected to fd(socket).
 * Returns connected UDP socket or -1 on error. 
 */
int udp_session(int fd, time_t timeout) 
{
	struct sockaddr_in saddr; 
	short  port;
        int   s,opt;

     	if( (s=socket(AF_INET,SOCK_DGRAM,0))== -1 ){
	   syslog(LOG_ERR,"Can't create socket");
	   return -1;
     	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
     	saddr.sin_port = 0;
	
     	if( bind(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
	   syslog(LOG_ERR,"Can't bind to the socket");
   	   return -1;
     	}

	opt = sizeof(saddr);
	if( getsockname(s,(struct sockaddr *)&saddr,&opt) ){
	   syslog(LOG_ERR,"Can't get socket name");
   	   return -1;
     	}
		
	/* Write port of the new UDP socket */
	port = saddr.sin_port;
	if( write_n(fd,&port,sizeof(short)) < 0 ){
	   syslog(LOG_ERR,"Can't write port number");
	   return -1;
     	}

	/* Read port of the other's end UDP socket */
	if( readn_t(fd,&port,sizeof(short),timeout) < 0 ){
	   syslog(LOG_ERR,"Can't read port number %s", strerror(errno));
	   return -1;
     	}

	opt = sizeof(saddr);
	if( getpeername(fd,(struct sockaddr *)&saddr,&opt) ){
	   syslog(LOG_ERR,"Can't get peer name");
   	   return -1;
     	}

	saddr.sin_port = port;
	if( connect(s,(struct sockaddr *)&saddr,sizeof(saddr)) ){
	   syslog(LOG_ERR,"Can't connect socket");
	   return -1;
     	}

	return s;
}

/* 
 * Split args string and execute program in child process.
 * Substitutes opt in place off '%%'. Understands single quotes. 
 */ 
void run_program(char *prg, char *prm, int flags, char *opt)
{
     char *argv[50],*str;
     int pid, i;	

      switch( (pid=fork()) ){
	case -1:
	   syslog(LOG_ERR,"Couldn't fork()");
	   return;
	case 0:
	   break;
	default:
    	   if( flags & VTUN_CMD_WAIT ) {
	      /* Wait for termination */
	      if( waitpid(pid, &i, 0) > 0 && (WIFEXITED(i) && WEXITSTATUS(i)) )
		 syslog(LOG_INFO,"%s returned error %d", prg, WEXITSTATUS(i) );
	   }
    	   if( flags & VTUN_CMD_DELAY ) {
	      struct timespec tm = { VTUN_DELAY_SEC, 0 };
	      /* Small delay hack to sleep after pppd start.
	       * Until I'll find good solution for solving 
	       * PPP + route problem  */
	       nanosleep(&tm, NULL);
	   }
	   return;	 
     }

     if( (str=strrchr(prg,'/')) )
        argv[0] = str+1;	
     else
        argv[0] = prg;	
	
     i = 1;
     if(prm){
        str = prm;
        while( *str && i < 50){
	  if( *str == ' ' ){
	     str++;
	     continue; 
	  }

	  if( *str == '%' && *(str+1) == '%' ){
	     argv[i++] = strdup(opt);
	     str+=2;	
	     continue;
	  }

	  if( *str == '\'' ){
	     argv[i++] = ++str;
	     while( *str ){
		if( *str == '\'' ){
		   *(str++) = '\0';
		   break;
		}
		str++;
	     }
	     continue;
	  }	     

	  argv[i++] = str;
	  while( *str ){
	     if( *str == ' ' ){
	        *(str++) = '\0';
	        break;
	     }
	     str++;
	  }
        }
     }
     argv[i]=NULL;

     execv(prg,argv);

     syslog(LOG_ERR,"Can't exec program %s",prg);
}

int run_cmd(void *d, void *opt)
{
     struct vtun_cmd *cmd = d;	

     run_program(cmd->prog, cmd->args, cmd->flags, (char*)opt); 
     return 0;
}

int tunnel(struct vtun_host *host)
{
     int fd[2],null_fd;
     char buf[12]="";
     int pid,opt;

     switch( host->flags & VTUN_TYPE_MASK ){
	case VTUN_TTY:
	   if( (fd[0]=getpty(buf)) < 0){
	      syslog(LOG_ERR,"Can't allocate pseudo tty");
	      return -1;
           }
	   break;
	case VTUN_PIPE:
	   if( socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0){
 	      syslog(LOG_ERR,"Can't create pipe");
   	      return -1;
	   }
	   break;
	case VTUN_ETHER:
	   if( host->dev )
	      strcpy(buf,host->dev); 
	   if( (fd[0]=gettap(buf)) < 0){
 	      syslog(LOG_ERR,"Can't allocate tap device");
   	      return -1;
	   }
	   break;
	case VTUN_TUN:
	   if( host->dev )
	      strcpy(buf,host->dev); 
	   if( (fd[0]=gettun(buf)) < 0){
 	      syslog(LOG_ERR,"Can't allocate tun device");
   	      return -1;
	   }
	   break;
     }

     switch( (pid=fork()) ){
	case -1:
	   syslog(LOG_ERR,"Couldn't fork()");
	   return -1;
	case 0:
     	   switch( host->flags & VTUN_TYPE_MASK ){
	      case VTUN_TTY:
	         /* Open pty slave (becomes controlling terminal) */
	         if( (fd[1] = open(buf, O_RDWR)) < 0){
	            syslog(LOG_ERR,"Couldn't open slave pty");
	            return -1;
	         }
		 /* Fall through */
	      case VTUN_PIPE:
	         if( (null_fd = open("/dev/null", O_RDWR)) < 0){
	            syslog(LOG_ERR,"Couldn't open /dev/null");
	            return -1;
	         }	
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
	   /*
	    * Run list of initialization commands
	    */
	   set_title("%s running init commands", host->host);
	   llist_trav(&host->up,run_cmd,buf);

   	   exit(0);           
	default:
	   switch( host->flags & VTUN_TYPE_MASK ){
	      case VTUN_TTY:
	         set_title("%s tty prog pid <%d>", host->host, pid);
	         break;
	      case VTUN_PIPE:
		 /* Close second end of the pipe */
		 close(fd[1]);
	         set_title("%s pipe prog pid <%d>", host->host, pid);
	  	 break;
	      case VTUN_ETHER:
	         set_title("%s ether %s", host->host, buf);
	   	 break;
	      case VTUN_TUN:
	         set_title("%s tun %s", host->host, buf);
	   	 break;
     	   }

	   switch( host->flags & VTUN_PROT_MASK ){
	      case VTUN_TCP:
	         opt=1;
	         setsockopt(host->rmt_fd,SOL_SOCKET,SO_KEEPALIVE,&opt,sizeof(opt));

	         opt=1;
	         setsockopt(host->rmt_fd,IPPROTO_TCP,TCP_NODELAY,&opt,sizeof(opt));
	         break;
	      case VTUN_UDP:
	         if( (opt = udp_session(host->rmt_fd,VTUN_TIMEOUT)) == -1){
		    syslog(LOG_ERR,"Can't establish UDP session");
		    return -1;
	         } 	
	         /* UDP session, close TCP socket */	
	         close(host->rmt_fd); host->rmt_fd = opt;		
	  	 break;
     	   }

	   host->loc_fd = fd[0];
	   opt = linkfd(host);

	   set_title("%s running deinit commands", host->host);
	   llist_trav(&host->down,run_cmd,buf);

	   set_title("%s closing", host->host);
	   /* Close all fds */
	   close(host->loc_fd);
	   close(host->rmt_fd);

	   return opt;
     }
}

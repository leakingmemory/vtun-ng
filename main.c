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
 * $Id: main.c,v 1.9.2.8 2016/10/01 21:37:39 mtbishop Exp $
 */ 

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/mman.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "compat.h"

#define OPTSTRING "mif:P:L:t:npq"
#ifdef HAVE_WORKING_FORK
#  define SERVOPT_STRING "s"
#else
#  define SERVOPT_STRING ""
#endif

/* Global options for the server and client */
struct vtun_opts vtun;
struct vtun_host default_host;

static void write_pid(void);
static void reread_config(int sig);
static void usage(void);

extern int optind,opterr,optopt;
extern char *optarg;

/* for the NATHack bit.  Is our UDP session connected? */
int is_rmt_fd_connected=1; 

int main(int argc, char *argv[], char *env[])
{
     int svr, daemon, sock, fd, opt;
#if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK)
     int dofork;
#endif
     struct vtun_host *host = NULL;
     struct sigaction sa;
     char *hst;

     /* Configure default settings */
     svr = 0; daemon = 1; sock = 0;
#if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK)
     dofork = 1;
#endif

     vtun.cfg_file = VTUN_CONFIG_FILE;
     vtun.persist = -1;
     vtun.timeout = -1;
	
     /* Dup strings because parser will try to free them */
     vtun.ppp   = strdup("/usr/sbin/pppd");
     vtun.ifcfg = strdup("/sbin/ifconfig");
     vtun.route = strdup("/sbin/route");
     vtun.fwall = strdup("/sbin/ipchains");	
     vtun.iproute = strdup("/sbin/ip");	

     vtun.svr_name = NULL;
     vtun.svr_addr = NULL;
     vtun.bind_addr.port = -1;
     vtun.svr_type = -1;
     vtun.syslog   = LOG_DAEMON;

     /* Initialize default host options */
     memset(&default_host, 0, sizeof(default_host));
     default_host.flags   = VTUN_TTY | VTUN_TCP;
     default_host.multi   = VTUN_MULTI_ALLOW;
     default_host.timeout = VTUN_CONNECT_TIMEOUT;
     default_host.ka_interval = 30;
     default_host.ka_maxfail  = 4;
     default_host.loc_fd = default_host.rmt_fd = -1;

     /* Start logging to syslog and stderr */
     openlog("vtund", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

     while( (opt=getopt(argc,argv,OPTSTRING SERVOPT_STRING)) != EOF ){
	switch(opt){
	    case 'm':
	        if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
		    perror("Unable to mlockall()");
		    exit(-1);
	        }
		break;
	    case 'i':
		vtun.svr_type = VTUN_INETD;
#ifdef HAVE_WORKING_FORK
	    case 's':
#endif
		svr = 1;
		break;
	    case 'L':
		vtun.svr_addr = strdup(optarg);
		break;
	    case 'P':
		vtun.bind_addr.port = atoi(optarg);
		break;
	    case 'f':
		vtun.cfg_file = strdup(optarg);
		break;
	    case 'n':
		daemon = 0;
		break;
	    case 'p':
		vtun.persist = 1;
		break;
	    case 't':
	        vtun.timeout = atoi(optarg);	
	        break;
	    case 'q':
		vtun.quiet = 1;
		break;
	    default:
		usage();
	        exit(1);
	}
     }	
     reread_config(0);

     if (vtun.syslog != LOG_DAEMON) {
	/* Restart logging to syslog using specified facility  */
 	closelog();
 	openlog("vtund", LOG_PID|LOG_NDELAY|LOG_PERROR, vtun.syslog);
     }

	clear_nat_hack_flags(svr);

     if(!svr){
	if( argc - optind < 2 ){
	   usage();
           exit(1);
	}
	hst = argv[optind++];

        if( !(host = find_host(hst)) ){	
	   vtun_syslog(LOG_ERR,"Host %s not found in %s", hst, vtun.cfg_file);
	   exit(1);
        }

	vtun.svr_name = strdup(argv[optind]);
     } 
      	
     /* 
      * Now fill uninitialized fields of the options structure
      * with default values. 
      */ 
     if(vtun.bind_addr.port == -1)
	vtun.bind_addr.port = VTUN_PORT;
     if(vtun.persist == -1)
	vtun.persist = 0;
     if(vtun.timeout == -1)
	vtun.timeout = VTUN_TIMEOUT;

     switch( vtun.svr_type ){
	case -1:
	   vtun.svr_type = VTUN_STAND_ALONE;
	   break;
	case VTUN_INETD:
	   sock = dup(0);
#if defined(HAVE_WORKING_FORK) || defined(HAVE_WORKING_VFORK)
	   dofork = 0; 
#endif
	   break;
     }

     if( daemon ){
#ifdef HAVE_WORKING_FORK
	if( dofork && fork() )
	   exit(0);
#elif defined(HAVE_WORKING_VFORK)
	if( dofork && vfork() )
	   exit(0);
#endif

        /* Direct stdin,stdout,stderr to '/dev/null' */
        fd = open("/dev/null", O_RDWR);
	close(0); dup(fd);
	close(1); dup(fd);
        close(2); dup(fd);
        close(fd);

	setsid();

	chdir("/");
     }

     if(svr){
        memset(&sa,0,sizeof(sa));     
        sa.sa_handler=reread_config;
        sigaction(SIGHUP,&sa,NULL);

        init_title(argc,argv,env,"vtunngd[s]: ");

	if( vtun.svr_type == VTUN_STAND_ALONE ){
#ifdef HAVE_WORKING_FORK
	   write_pid();
#else
	   vtun_syslog(LOG_ERR,"Standalone server is not supported. Use -i");
	   exit(1);
#endif
	}
	
	server(sock);
     } else {	
        init_title(argc,argv,env,"vtunngd[c]: ");
        client(host);
     }

     closelog();
	
     return 0;
}

/* 
 * Very simple PID file creation function. Used by server.
 * Overrides existing file. 
 */
static void write_pid(void)
{
     FILE *f;

     if( !(f=fopen(VTUN_PID_FILE,"w")) ){
        vtun_syslog(LOG_ERR,"Can't write PID file");
        return;
     }

     fprintf(f,"%d",(int)getpid());
     fclose(f);
}

static void reread_config(int sig)
{
     if( !read_config(vtun.cfg_file) ){
	vtun_syslog(LOG_ERR,"No hosts defined");
	exit(1);
     }
}

static void usage(void)
{
     printf("VTun ver %s\n", VTUN_VER);
     printf("Usage: \n");
     printf("  Server:\n");
#ifdef HAVE_WORKING_FORK
     printf("\tvtund <-s|-i> [-f file] [-P port] [-L local address]\n");
#else
     printf("\tvtund <-i> [-f file] [-P port] [-L local address]\n");
#endif
     printf("  Client:\n");
     /* I don't think these work. I'm disabling the suggestion - bish 20050601*/
     printf("\tvtund [-f file] " /* [-P port] [-L local address] */
	    "[-q] [-p] [-m] [-t timeout] <host profile> <server address>\n");
}

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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "vtun.h"
#include "lib.h"

#include "compat.h"

/* Global options for the server and client */
struct vtun_opts vtun;

void write_pid(void);
void reread_config(int sig);
void usage(void);

extern int optind,opterr,optopt;
extern char *optarg;

int main(int argc, char *argv[], char *env[]){
     struct vtun_host *host = NULL;
     int svr = 0, daemon = 1;
     struct hostent *hent;  
     struct sigaction sa;
     char *hst;
     int opt;

     /* Configure default options */
     vtun.persist = -1;
     vtun.timeout = -1;
     vtun.cfg_file = VTUN_CONFIG_FILE;
	
     /* Dup strings because parser will try to free them */	
     vtun.ppp   = strdup("/usr/sbin/pppd");
     vtun.ifcfg = strdup("/sbin/ifconfig");
     vtun.route = strdup("/sbin/route");
     vtun.fwall = strdup("/sbin/ipchains");	

     vtun.laddr = INADDR_ANY;
     vtun.svr_name = NULL;
     vtun.port  = VTUN_PORT; 

     /* Start logging to syslog and stderr */
     openlog("vtund", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);

     while( (opt=getopt(argc,argv,"sf:P:t:npL:")) != EOF ){
	switch(opt){
	    case 's':
		svr = 1;
		break;
	    case 'P':
		vtun.port = atoi(optarg);
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
	    case 'L':
	        if( !(hent = gethostbyname(optarg)) ){
		   syslog(LOG_ERR, "Can't resolv local address %s",optarg);
		   exit(1);
		}
		vtun.laddr = *(unsigned long *)hent->h_addr;	
	        break;
	    default:
		usage();
	        exit(1);
	}
     }	
     reread_config(0);

     if(!svr){
	if( argc - optind < 2 ){
	   usage();
           exit(1);
	}
	hst = argv[optind++];

        if( !(host = find_host(hst)) ){	
	   syslog(LOG_ERR,"Host %s not found in %s", hst, vtun.cfg_file);
	   exit(1);
        }

	vtun.svr_name = strdup(argv[optind]);
     } 
      	
     /* 
      * Now fill uninitialized fields of the options structure
      * with default values. 
      */ 

     if(vtun.port == -1)
	vtun.port = VTUN_PORT;
     if(vtun.persist == -1)
	vtun.persist = 0;		
     if(vtun.timeout == -1)
	vtun.timeout = VTUN_CONNECT_TIMEOUT;

     if(daemon){
        if( fork() )
	   exit(0);

        /* Direct stderr to '/dev/null', otherwise syslog 
	 * will write to it */
        close(2); open("/dev/null", O_RDWR);

	close(0);close(1);
	setsid();

	chdir("/");
     }

     if(svr){
        memset(&sa,0,sizeof(sa));     
        sa.sa_handler=reread_config;
        sigaction(SIGHUP,&sa,NULL);

        init_title(argc,argv,env,"vtund[s]: ");
	
	write_pid();
	
	server();
     } else {	
        init_title(argc,argv,env,"vtund[c]: ");
        client(host);
     }

     closelog();
	
     return 0;
}

/* 
 * Very simple PID file creation function. Used by server.
 * Overrides existing file. 
 */
void write_pid(void)
{
	FILE *f;

	if( !(f=fopen(VTUN_PID_FILE,"w")) ){
	   syslog(LOG_ERR,"Can't write PID file");
	   return;
	}

	fprintf(f,"%d",(int)getpid());
	fclose(f);
}

void reread_config(int sig)
{
     if( !read_config(vtun.cfg_file) ){
	syslog(LOG_ERR,"No hosts defined");
	exit(1);
     }
}

void usage(void)
{
     printf("Usage: \n");
     printf("  Server:\n");
     printf("\tvtund <-s> [-f file] [-P port]\n");
     printf("  Client:\n");
     printf("\tvtund [-f file] [-P port] [-L local address] [-p] [-t timeout] <host> <server adress>\n");
}



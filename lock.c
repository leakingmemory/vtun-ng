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
 * $Id: lock.c,v 1.6.2.3 2016/10/01 21:27:51 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h" 
#include "lock.h"

void unlock_host(struct vtun_host *host)
{ 
  char lock_file[255];

  if( host->multi == VTUN_MULTI_ALLOW )
     return;

  sprintf(lock_file, "%s/%s", VTUN_LOCK_DIR, host->host);

  if( unlink(lock_file) < 0 )
     vtun_syslog(LOG_ERR, "Unable to remove lock %s", lock_file);
}

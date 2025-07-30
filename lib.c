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
 * $Id: lib.c,v 1.9.2.5 2016/10/01 21:46:01 mtbishop Exp $
 */ 

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

void vtun_syslog (int priority, char *format, ...)
{
   static volatile sig_atomic_t in_syslog= 0;
   char buf[255];
   va_list ap;

   if(! in_syslog) {
      in_syslog = 1;
    
      va_start(ap, format);
      vsnprintf(buf, sizeof(buf)-1, format, ap);
      syslog(priority, "%s", buf);
      closelog();
      va_end(ap);

      in_syslog = 0;
   }
}

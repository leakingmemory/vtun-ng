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

#include "config.h"
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

int shaper_init(struct vtun_host *host);
int shaper_counter(int len, char *in, char **out);
int shaper_avail(void);

struct lfd_mod lfd_shaper = {
     "Shaper",
     shaper_init,
     shaper_counter,
     shaper_avail,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL
};

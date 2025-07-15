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
 * $Id: lfd_zlib.c,v 1.5.2.4 2016/10/01 21:46:01 mtbishop Exp $
 */ 

/* ZLIB compression module */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

int zlib_alloc(struct vtun_host *host);
int zlib_free();
int zlib_comp(int len, char *in, char **out);
int zlib_decomp(int len, char *in, char **out);

struct lfd_mod lfd_zlib = {
     "ZLIB",
     zlib_alloc,
     zlib_comp,
     NULL,
     zlib_decomp,
     NULL,
     zlib_free,
     NULL,
     NULL
};

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
#ifndef _LINKFD_H
#define _LINKFD_H

/* Priority of the process in the link_fd function */
#define LINKFD_PRIO -19

int linkfd(struct vtun_host *host);

/* Module */
struct lfd_mod {
   char *name;
   int (*alloc)(struct vtun_host *host);
   int (*encode)(int len, char *in, char **out);
   int (*avail_encode)(void);
   int (*decode)(int len, char *in, char **out);
   int (*avail_decode)(void);
   int (*free)(void);

   struct lfd_mod *next;
   struct lfd_mod *prev;
};

/* External LINKFD modules */

extern struct lfd_mod lfd_zlib;
extern struct lfd_mod lfd_lzo;
extern struct lfd_mod lfd_encrypt;
extern struct lfd_mod lfd_shaper;

#endif

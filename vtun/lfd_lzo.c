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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#ifdef HAVE_LZO

#include "lzo1x.h"
/* LZO compression module */

static lzo_byte *zbuf;
static lzo_voidp wmem;
static int zbuf_size = VTUN_FRAME_SIZE * VTUN_FRAME_SIZE / 64 + 16 +3;

/* Pointer to compress function */
int (*lzo1x_compress)(const lzo_byte *src, lzo_uint  src_len,
		   	    lzo_byte *dst, lzo_uint *dst_len,
		   	    lzo_voidp wrkmem);
/* 
 * Initialize compressor/decompressor.
 * Allocate the buffers.
 */  

int alloc_lzo(struct vtun_host *host)
{
     int mem;

     switch( host->zlevel ) {
	case 9:
	   lzo1x_compress = lzo1x_999_compress;
           mem = LZO1X_999_MEM_COMPRESS;
           break;
	default: 	   
 	   lzo1x_compress = lzo1x_1_15_compress;
           mem = LZO1X_1_15_MEM_COMPRESS;
           break;
     }

     if( lzo_init() != LZO_E_OK ){
	syslog(LOG_ERR,"Can't initialize compressor");
	return 1;
     }	
     if( !(zbuf = lzo_malloc(zbuf_size)) ){
	syslog(LOG_ERR,"Can't allocate buffer for the compressor");
	return 1;
     }	
     if( !(wmem = lzo_malloc(mem)) ){
	syslog(LOG_ERR,"Can't allocate buffer for the compressor");
	return 1;
     }	

     syslog(LOG_INFO, "LZO compression[level %d] initialized", host->zlevel);

     return 0;
}

/* 
 * Deinitialize compressor/decompressor.
 * Free the buffer.
 */  

int free_lzo()
{
     lzo_free(zbuf);
     lzo_free(wmem);
     return 0;
}

inline int expand_zbuf(int len)
{
     if( !(zbuf = realloc(zbuf,zbuf_size+len)) )
         return -1;
     zbuf_size += len;     
     return 0;
}

/* 
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dinamicly.
 */  
int comp_lzo(int len, char *in, char **out)
{ 
     int zlen = 0;    
     int err;
     
     if( (err=lzo1x_compress(in,len,zbuf,&zlen,wmem)) != LZO_E_OK ){
        syslog(LOG_ERR,"Compress error %d",err);
        return -1;
     }

     *out = zbuf;
     return zlen;
}

int decomp_lzo(int len, char *in, char **out)
{
     int zlen = 0;     
     int err;

     if( zbuf_size < len )
	expand_zbuf(zlen - zbuf_size);
	
     if( (err=lzo1x_decompress(in,len,zbuf,&zlen,wmem)) != LZO_E_OK ){
        syslog(LOG_ERR,"Decompress error %d",err);
        return -1;
     }

     *out = zbuf;
     return zlen;
}

#else  /* HAVE_LZO */

/* Dummy function if LZO support is not compiled */
int alloc_lzo(struct vtun_host *host)
{
     syslog(LOG_INFO, "LZO compression is not supported");
     return -1;
}

int free_lzo()
{
     return 0;
}

int comp_lzo(int len, char *in, char **out)
{ 
     return 0;
}

int decomp_lzo(int len, char *in, char **out)
{
     return 0;
}

#endif /* HAVE_LZO */


struct lfd_mod lfd_lzo = {
     "LZO",
     alloc_lzo,
     comp_lzo,
     NULL,
     decomp_lzo,
     NULL,
     free_lzo,
     NULL,NULL
};

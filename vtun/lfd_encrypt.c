
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

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with 
 * several improvements and modifications by me.  
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>

#include <md5.h>
#include <blowfish.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 16 
#define ENC_KEY_SIZE 16

BF_KEY key;
char * enc_buf;

int alloc_encrypt(struct vtun_host *host)
{
   if( !(enc_buf = malloc(ENC_BUF_SIZE)) ){
      syslog(LOG_ERR,"Can't allocate buffer for encryptor");
      return -1;
   }

   BF_set_key(&key, ENC_KEY_SIZE, MD5(host->passwd,strlen(host->passwd),NULL));

   syslog(LOG_INFO, "Encryption initialized.");
   return 0;
}

int free_encrypt()
{
   free(enc_buf);

   return 0;
}

int encrypt_buf(int len, char *in, char **out)
{ 
   register int pad, p;
   register char *in_ptr = in, *out_ptr = enc_buf;

   /* 8 - ( len % 8 ) */
   pad = (~len & 0x07) + 1; p = 8 - pad;

   memset(out_ptr, 0, pad);
   *out_ptr = (char) pad;
   memcpy(out_ptr + pad, in_ptr, p);  
   BF_ecb_encrypt(out_ptr, out_ptr, &key, BF_ENCRYPT);
   out_ptr += 8; in_ptr += p; 
   len = len - p;

   for(p=0; p < len; p += 8 )
      BF_ecb_encrypt(in_ptr + p,  out_ptr + p, &key, BF_ENCRYPT);

   *out = enc_buf;
   return len + 8;
}

int decrypt_buf(int len, char *in, char **out)
{
   register int p;

   for(p = 0; p < len; p += 8)
      BF_ecb_encrypt(in + p, in + p, &key, BF_DECRYPT);

   p = *in;
   *out = in + p;

   return len - p;
}

/* 
 * Module structure.
 */
struct lfd_mod lfd_encrypt = {
     "Encryptor",
     alloc_encrypt,
     encrypt_buf,
     NULL,
     decrypt_buf,
     NULL,
     free_encrypt,
     NULL,NULL
};

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
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)       
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with
 * several improvements and modifications by me.
 */

/*
 * The current lfd_encrypt module is based on code attributed above and 
 * uses new code written by Dale Fountain <dpf-vtun@fountainbay.com> to 
 * allow multiple ciphers, modes, and key sizes. Feb 2004.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

int alloc_encrypt(struct vtun_host *host);
int free_encrypt();
int encrypt_buf(int len, char *in, char **out);
int decrypt_buf(int len, char *in, char **out);

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
     NULL,
     NULL
};

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
 * $Id: lfd_legacy_encrypt.c,v 1.1.4.4 2016/10/01 21:27:51 mtbishop Exp $
 * Code added wholesale temporarily from lfd_encrypt 1.2.2.8
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
 * several improvements and modifications.  
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

int alloc_legacy_encrypt(struct vtun_host *host);
int free_legacy_encrypt();
int legacy_encrypt_buf(int len, char *in, char **out);
int legacy_decrypt_buf(int len, char *in, char **out);

/* 
 * Module structure.
 */
struct lfd_mod lfd_legacy_encrypt = {
     "Encryptor",
     alloc_legacy_encrypt,
     legacy_encrypt_buf,
     NULL,
     legacy_decrypt_buf,
     NULL,
     free_legacy_encrypt,
     NULL,
     NULL
};


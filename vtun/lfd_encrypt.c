
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
 * lfd_encrypt.c,v 1.4 2001/09/20 06:36:23 talby Exp
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with 
 * several improvements and modifications by me.  
 */

/* 
 * Robert Stone <talby@trap.mtview.ca.us>
 * 2000/05/18	* Added cfb64 mode for tcp connections.  This should
 *		  significantly hinder known plaintext attacks.
 * 2000/05/24	* UDP algorithm cleanup.
 * 2000/06/04	* Now uses runtime generated session keys.  This should
 *		  greatly lessen the value of cyptanalysis on a tunnel.
 * planned	* Add a key rotation system so that there is a fixed limit
 *		  on the ammount of data encrypted under one sesion key.
 *		  (This will require a header on my layer of processing.)
 *		* Permutate ivec for tcp.  SSH doesn't bother, should we?
 *		* Add a runtime generated permutation-pad for udp mode
 *		  encryption to help address known plaintext attacks in ecb
 *		  mode.  Would this really help?  It does provide 40320
 *		  permutations on crypted text, but is that computationally
 *		  hard to unravel?
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

/* OpenSSL includes */
#include <openssl/md5.h>
#include <openssl/blowfish.h>

#ifndef __APPLE_CC__
#include <openssl/rand.h>
#endif  /* __APPLE_CC__ */

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 16
#define ENC_KEY_SIZE 16

BF_KEY key;

char *enc_buf;
int (*crypt_buf) (int, char *, char *, int) = NULL;

/* encryption could be stronger if the initial ivec was not
 * a constant, but this is only an issue with the first
 * packet. (first few packets?) */
int str_crypt_buf(int len, char *ibuf, char *obuf, int enc)
{
	static unsigned char ivec[16] =
	    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	static int num[2] = { 0, 0 };

	BF_cfb64_encrypt(ibuf, obuf, len, &key, ivec + (enc << 3),
			 num + enc, enc);
	return (len);
}

/* UDP packets get a header.  The first byte in the packet is the
 * length of the header.  The header pads the data out to an 8 byte
 * boundary */
int pkt_crypt_buf(int len, char *ibuf, char *obuf, int enc)
{
	char *ip = ibuf, *op = obuf;
	int i = len >> 3;
	char hdr[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	char hlen;

	if (enc == BF_ENCRYPT) {	/* build header */
		hlen = 8 - (len & 7);
		if (hlen == 0)
			hlen = 8;
		hdr[0] = hlen;
		memcpy(hdr + hlen, ip, 8 - hlen);
		BF_ecb_encrypt(hdr, op, &key, enc);
		op += 8;
		ip += 8 - hlen;
		len += hlen;
	} else {		/* strip header */
		BF_ecb_encrypt(ip, hdr, &key, enc);
		hlen = hdr[0];
		memcpy(op, hdr + hlen, 8 - hlen);
		op += 8 - hlen;
		ip += 8;
		len -= hlen;
	}
	while (i > 0) {
		BF_ecb_encrypt(ip, op, &key, enc);
		ip += 8;
		op += 8;
		i--;
	}
	return (len);
}

int encrypt_buf(int len, char *in, char **out)
{
	*out = enc_buf;
	return (crypt_buf(len, in, *out, BF_ENCRYPT));
}

int decrypt_buf(int len, char *in, char **out)
{
	*out = enc_buf;
	return (crypt_buf(len, in, *out, BF_DECRYPT));
}

unsigned char *session_key(struct vtun_host *host)
{
	static char buf[ENC_KEY_SIZE];
	BF_KEY initkey;
	fd_set rfd;
	struct timeval tv;
	u_int32_t val;
	char ivec[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int fun[4];
	char *mode;

	BF_set_key(&initkey, ENC_KEY_SIZE,
		   MD5(host->passwd, strlen(host->passwd), NULL));
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfd);
	FD_SET(host->rmt_fd, &rfd);
	select(host->rmt_fd + 1, &rfd, NULL, NULL, &tv);
	if (!FD_ISSET(host->rmt_fd, &rfd)) {
		char cbuf[ENC_KEY_SIZE];

		RAND_seed(host->passwd, strlen(host->passwd));
		RAND_bytes(buf, ENC_KEY_SIZE);
		BF_cbc_encrypt(buf, cbuf, ENC_KEY_SIZE, &initkey, ivec,
			       BF_ENCRYPT);
		write(host->rmt_fd, cbuf, ENC_KEY_SIZE);
		mode = "send";
	} else {
		read(host->rmt_fd, buf, ENC_KEY_SIZE);
		BF_cbc_encrypt(buf, buf, ENC_KEY_SIZE, &initkey, ivec,
			       BF_DECRYPT);
		mode = "recv";
	}
	/* return(MD5(host->passwd, strlen(host->passwd), NULL)); */
	memcpy(fun, buf, ENC_KEY_SIZE);
	vtun_syslog(LOG_ERR, "blowfish: %s key %08x %08x %08x %08x", mode,
		    htonl(fun[0]), htonl(fun[1]), htonl(fun[2]), htonl(fun[3]));
	return (buf);
}

int alloc_encrypt(struct vtun_host *host)
{
	char *mode;

	if ((enc_buf = (char *) lfd_alloc(ENC_BUF_SIZE)) == NULL) {
		vtun_syslog(LOG_ERR, "Unable to allocate encryption buffer");
		return -1;
	}

	BF_set_key(&key, ENC_KEY_SIZE, session_key(host));

	if (host->flags & VTUN_TCP) {
		crypt_buf = str_crypt_buf;
		mode = "cfb64";
	} else {
		crypt_buf = pkt_crypt_buf;
		mode = "ecb";
	}

	vtun_syslog(LOG_INFO, "blowfish/%s encryption initialized", mode);
	return 0;
}

int free_encrypt()
{
	lfd_free(enc_buf);

	return 0;
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
	NULL, NULL
};

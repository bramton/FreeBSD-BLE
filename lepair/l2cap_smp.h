/*
 * Copyright (c) 2015 Takanori Watanabe
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _L2CAP_SMP_H_
#define _L2CAP_SMP_H_
#include <sys/types.h>
#include <bluetooth.h>
#include <openssl/aes.h>

/* Security Manager Protocol codes */
#define SMP_CODE_PAIRREQ 0x01
#define SMP_CODE_PAIRRES 0x02
#define SMP_CODE_PAIRCONFIRM 0x03
#define SMP_CODE_PAIRRAND 0x04
#define SMP_CODE_PAIRFAIL 0x05
#define SMP_CODE_ENCINFO 0x06
#define SMP_CODE_CENTRALINFO 0x07
#define SMP_CODE_IDINFO 0x08
#define SMP_CODE_IDADDR 0x09
#define SMP_CODE_SIGNINFO 0x0a
#define SMP_CODE_SECREQ 0x0b

#define SMP_OOB_AUTH_NOT_PRESENT 0x00

/* Pairing request and response */
struct __attribute__((packed)) ng_l2cap_smp_pairinfo {
	uint8_t code;
	uint8_t iocap;
	uint8_t oobflag;
	uint8_t authreq;
	uint8_t maxkeysize;
	uint8_t ikeydist;
	uint8_t rkeydist;  
};

/* Pairing confirmation, random, encryption info, identity resolving key */
struct __attribute__((packed)) ng_l2cap_smp_keyinfo {
	uint8_t code;
	uint8_t val[16];
};

/* Pairing failed */
struct __attribute__((packed)) ng_l2cap_smp_failed {
	uint8_t code;
	uint8_t reason;
};

/* Central identification */
struct __attribute__((packed)) ng_l2cap_smp_centralinfo {
	uint8_t code;
	uint16_t ediv; /* Encrypted Diversifier */
	uint8_t rand[8];
};

/* Identity address information */
struct __attribute__((packed)) ng_l2cap_smp_idaddr {
	uint8_t code;
	uint8_t addrtype;
	bdaddr_t bdaddr;
};

static int iocapmat[5][5] ={
  {0, 0, 1, 0, 1},
  {0, 0, 1, 0, 1},
  {-1, -1, -1, 0, -1},
  {0, 0, 0, 0, 0},
  {-1, -1, -1, 0, -1}
};

int smp_e(const uint8_t*, const uint8_t*, uint8_t*);
int smp_s1(const uint8_t*, uint8_t*, uint8_t*, uint8_t*);
int smp_c1(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint8_t, bdaddr_t*,uint8_t, bdaddr_t*);
void inline swap128(uint8_t *src, uint8_t *dst)
{
	int i;
	for(i=0;i < 16; i++){
		dst[i] = src[15-i];
	}
}

#endif

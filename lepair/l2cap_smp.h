/*
 * Copyright (c) 2015 Takanori Watanabe
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _L2CAP_SMP_H_
#define _L2CAP_SMP_H_
#define L2CAP_SOCKET_CHECKED
#include <sys/types.h>
#include <bluetooth.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

/* Security Manager Protocol codes */
#define SMP_CODE_PAIRREQ 0x01
#define SMP_CODE_PAIRRES 0x02
#define SMP_CODE_PAIRCONFIRM 0x03
#define SMP_CODE_PAIRRAND 0x04
#define SMP_CODE_PAIRFAIL 0x05
#define SMP_CODE_LTK 0x06 /* Encryption Information */
#define SMP_CODE_CID 0x07 /* Central Identification */
#define SMP_CODE_IRK 0x08 /* Identity Information */
#define SMP_CODE_IDADDR 0x09 /* Identity Address */
#define SMP_CODE_CSRK 0x0a /* Signing Information */
#define SMP_CODE_SECREQ 0x0b /* Security Request */

#define SMP_OOB_DATA  0x01

#define SMP_IOCAP_DISPONLY   0x00
#define SMP_IOCAP_DISPYESNO  0x01
#define SMP_IOCAP_KEYBONLY   0x02
#define SMP_IOCAP_NOINPNOOUT 0x03
#define SMP_IOCAP_KEYBDISP   0x04

/* Authentication requirements flags */
#define SMP_AUTH_BOND      0x01
#define SMP_AUTH_MITM      0x04
#define SMP_AUTH_CS        0x08
#define SMP_AUTH_KEYPRESS  0x10
#define SMP_AUTH_CT2       0x40

/* Key distribution */
#define SMP_KEYDIS_ENC  0x01
#define SMP_KEYDIS_ID   0x02
#define SMP_KEYDIS_SIGN 0x04
#define SMP_KEYDIS_LINK 0x08

/* Key generation methods */
#define SMP_USE_JUSTWORKS 0x00
#define SMP_USE_PASSKEY_I 0x01 /* Responder displays, initiator inputs */
#define SMP_USE_PASSKEY_R 0x02 /* Initiator displays, responder inputs */

/* Pairing request and response */
struct __attribute__((packed)) ng_l2cap_smp_pairinfo {
	uint8_t code;
	uint8_t iocap;
	uint8_t oob;
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
struct __attribute__((packed)) ng_l2cap_smp_cid {
	uint8_t code;
	uint16_t ediv; /* Encrypted Diversifier */
	uint64_t rand;
};

/* Identity address information */
struct __attribute__((packed)) ng_l2cap_smp_idaddr {
	uint8_t code;
	uint8_t addrtype;
	bdaddr_t bdaddr;
};

static uint8_t iocapmat[5][5] ={
  {SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_I, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_I},
  {SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_I, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_I},
  {SMP_USE_PASSKEY_R, SMP_USE_PASSKEY_R, SMP_USE_PASSKEY_R, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_R},
  {SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS, SMP_USE_JUSTWORKS},
  {SMP_USE_PASSKEY_R, SMP_USE_PASSKEY_R, SMP_USE_PASSKEY_R, SMP_USE_JUSTWORKS, SMP_USE_PASSKEY_R},
};

int smp_e(const uint8_t*, const uint8_t*, uint8_t*);
int smp_eb(const uint8_t*, const uint8_t*, uint8_t*);
int smp_s1(const uint8_t*, const uint8_t*, const uint8_t*, uint8_t*);

/* Confirm value generation function for LE legacy pairing */
int smp_c1(uint8_t*, uint8_t*, uint8_t*, uint8_t*, uint8_t, bdaddr_t*,uint8_t, bdaddr_t*);
int smp_c1b(const uint8_t *, const uint8_t *,
		const struct ng_l2cap_smp_pairinfo*, const struct ng_l2cap_smp_pairinfo*,
		const uint8_t, const bdaddr_t*,
		const uint8_t, const bdaddr_t*, uint8_t*);

void inline swap128(const uint8_t *src, uint8_t *dst)
{
	for (int i=0; i < 16; i++) {
		dst[i] = src[15-i];
	}
}

#endif

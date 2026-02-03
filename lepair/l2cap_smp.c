/*
 * Copyright (c) 2015 Takanori Watanabe
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "l2cap_smp.h"

int smp_e(const uint8_t *k,const uint8_t *data, uint8_t *out)
{
	AES_KEY key;
	AES_set_encrypt_key(k, 128, &key);
	AES_ecb_encrypt(data, out, &key, AES_ENCRYPT);
	return 0;
}

int smp_s1(const uint8_t *k, uint8_t *r1, uint8_t *r2, uint8_t *out)
{
	uint8_t r[16];
	bcopy(r1+8, r, 8);
	bcopy(r2+8, r+8, 8);
	return smp_e(k, r, out);
}

int smp_c1(uint8_t *k, uint8_t *r, uint8_t *preq,
		  uint8_t *pres, uint8_t iat, bdaddr_t *ia,
		  uint8_t rat, bdaddr_t *ra)
{
	uint8_t p1[16];
	uint8_t p2[16];
	uint8_t tmp[16];
	int i;
	for(i = 0; i< 7; i++){
		p1[i+7] = preq[6-i];
		p1[i] = pres[6-i];
	}
	p1[14] = rat;
	p1[15] = iat;
	bzero(p2, sizeof(p2));
	for(i = 0; i< 6; i++){
		p2[i+4] = ia->b[5-i];
		p2[i+10] = ra->b[5-i];
	}
	for(i = 0; i < 16; i++){
		r[i] = r[i]^p1[i];
	}
	
	smp_e(k, r, tmp);
	for(i = 0; i < 16; i++){
		tmp[i] = tmp[i]^p2[i];
	}
	smp_e(k, tmp, r);
	
	return (0);
}
int smp_c1_unittest()
{
  int i;
  uint8_t tpq[7] = {0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07};
  
  uint8_t tps[7] = {0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05};
  bdaddr_t bdi = {.b = {0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1}};
  bdaddr_t bdr = {.b = {0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1}};
  uint8_t rav[16] = {0x57, 0x83, 0xd5, 0x21, 0x56, 0xad, 0x6f,0x0e, 0x63, 0x88, 0x27, 0x4e, 0xc6, 0x70, 0x2e, 0xe0};
  uint8_t k[16];
  bzero(k, sizeof(k));
  smp_c1(k, rav, tpq, tps, 1, &bdi, 0, &bdr);
  for(i = 0 ;i < sizeof(rav); i++){
    printf("%02x ", rav[i]);		  
  }
  printf("\n");
  return (0);
}

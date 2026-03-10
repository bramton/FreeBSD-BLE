/*
 * Copyright (c) 2015 Takanori Watanabe
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _ATT_H_
#define _ATT_H_

#include <sys/types.h>

#include <uuid.h>

#define ATT_OP_ERR 1
#define ATT_OP_MTU_REQ 2
#define ATT_OP_MTU_RES 3
#define ATT_OP_FIND_INFO_REQ 4
#define ATT_OP_FIND_INFO_RES 5
#define ATT_OP_FIND_TYPE_REQ 6
#define ATT_OP_FIND_TYPE_RES 7
#define ATT_OP_READ_TYPE_REQ 8
#define ATT_OP_READ_TYPE_RES 9
#define ATT_OP_READ_REQ 0xa
#define ATT_OP_READ_RES 0xb
#define ATT_OP_READ_BLOB_REQ 0xc
#define ATT_OP_READ_BLOB_RES 0xd
#define ATT_OP_READ_MULT_REQ 0xe
#define ATT_OP_READ_MULT_RES 0xf
#define ATT_OP_READ_GROUP_REQ 0x10
#define ATT_OP_READ_GROUP_RES 0x11
#define ATT_OP_WRITE_REQ 0x12
#define ATT_OP_WRITE_RES 0x13
#define ATT_OP_WRITE_CMD 0x52
#define ATT_OP_WRITE_SGN_CMD 0xd2
#define ATT_OP_PREP_WRITE_REQ 0x16
#define ATT_OP_PREP_WRITE_RES 0x17
#define ATT_OP_EXE_WRITE_RSP 0x18
#define ATT_OP_HANDLE_NTF 0x1b
#define ATT_OP_HANDLE_IND 0x1d
#define ATT_OP_HANDLE_CFM 0x1e
#define ATT_OP_MULTI_HANDLE_NTF 0x23

#define ATT_OPC_METHOD_MSK 0x3f

struct le_attreq {
	uint8_t opcode;
	void *cparam;
	size_t clen;
	void *rparam;
	size_t rlen;
};

struct __attribute__((packed))
le_att_find_info_req {
	uint16_t start;
	uint16_t end;
};

struct __attribute__((packed))
le_att_read_group_req_short {
	uint16_t start;
	uint16_t end;
	uint16_t type;
};

struct __attribute__((packed))
le_att_read_group_req_long {
	uint16_t start;
	uint16_t end;
	uuid_t type;
};


int le_attsend(int s, uint8_t opc, void *param, size_t plen);
int le_attrecv(int s, void *buf, size_t len, time_t to);
int le_attreq(int s, struct le_attreq *r, time_t to);

#endif /* _ATT_H_ */

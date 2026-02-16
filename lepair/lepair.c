/*
 * Copyright (c) 2015 Takanori Watanabe
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/bitstring.h>
#include <sys/select.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <openssl/aes.h>
#include <netgraph/ng_message.h>
#include <netgraph/bluetooth/include/ng_hci.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "hccontrol.h"
#include "l2cap_smp.h"

int timeout = 30;

struct smp_ctx {
	int hci_handle;
	struct sockaddr_l2cap l2ar, l2al;
	struct ng_l2cap_smp_pairinfo preq;
	struct ng_l2cap_smp_pairinfo pres;
	uint8_t tk[16]; /* Temporary Key */
	uint8_t stk[16]; 
	uint8_t rval[16];
	uint8_t rvalr[16]; /* Random value from responder */
	uint8_t cnfrm_val[16];
};
struct smp_ctx ctx;

int l2s, hs; /* l2cap socket and hci socket */
int l2connect(bdaddr_t *bdrema, bdaddr_t *bdloca, int hci, uint8_t rem_addrtype)
{
	l2s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (l2s < 0)
		return (-1);

	ctx.l2al.l2cap_len = sizeof(ctx.l2al);
	ctx.l2al.l2cap_family = AF_BLUETOOTH;
	ctx.l2al.l2cap_bdaddr_type = BDADDR_LE_PUBLIC; // TODO: always ??
	bdaddr_copy(&ctx.l2al.l2cap_bdaddr, bdloca);
	if (bind(l2s, (struct sockaddr *) &ctx.l2al, sizeof(struct sockaddr_l2cap)) < 0) {
		perror("Could not bind to local address");
		return (-1);
	}

	ctx.l2ar.l2cap_len = sizeof(ctx.l2ar);
	ctx.l2ar.l2cap_family = AF_BLUETOOTH;
	ctx.l2ar.l2cap_cid = NG_L2CAP_SMP_CID;
	ctx.l2ar.l2cap_bdaddr_type = rem_addrtype;
	//ctx.l2ar.l2cap_bdaddr_type = BDADDR_LE_RANDOM;
	bdaddr_copy(&ctx.l2ar.l2cap_bdaddr, bdrema);

	printf("Trying to connect to remote device\n");
	if (connect(l2s, (struct sockaddr *) &ctx.l2ar, sizeof(struct sockaddr_l2cap)) < 0 && 
	    errno != EINPROGRESS) {
	    perror("Failed to connect to l2cap socket");
	    return (-1);
	}
	perror("After connect");
	return (0);
}

/* Copied from hccontrol/node.c Should actually be from getsockopt?  */
int find_hci_con_handle(void) {
	struct ng_btsocket_hci_raw_con_list r;
 	int ret = -1;
	memset(&r, 0, sizeof(r));
	r.num_connections = NG_HCI_MAX_CON_NUM;
	r.connections = calloc(NG_HCI_MAX_CON_NUM, sizeof(ng_hci_node_con_ep));
	if (r.connections == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	if (ioctl(hs, SIOC_HCI_RAW_NODE_GET_CON_LIST, &r, sizeof(r)) < 0) {
		goto out;
	}

	for (int n = 0; n < r.num_connections; n++) {	
		if (bdaddr_same(&r.connections[n].bdaddr, &ctx.l2ar.l2cap_bdaddr)) {
			ctx.hci_handle = r.connections[n].con_handle;
			ret = 0;
			goto out;
		}
	}

out:
	free(r.connections);
	return (ret);
}

int send_pairing_request(void) {
	ssize_t n;
	struct ng_l2cap_smp_pairinfo preq;
	memset(&preq, 0, sizeof(preq));
	preq.code = SMP_CODE_PAIRREQ;
	preq.iocap = SMP_IOCAP_KEYBDISP;
	preq.oob = SMP_OOB_DATA;
	preq.authreq = SMP_AUTH_BOND;
	preq.maxkeysize = 16;
	preq.ikeydist = SMP_KEYDIS_ENC;
	preq.rkeydist = SMP_KEYDIS_ENC;
	n = write(l2s, &preq, sizeof(preq));
	if (n < 0) {
		perror("Could not send pairing request");
		return (-1);
	}
	else if (n != sizeof(preq)) {
		printf("Could not send complete pairing request\n");
		return (-1);
	}
	memcpy(&ctx.preq, &preq, sizeof(preq));
	return (0);
}

int process_pairing_response(struct ng_l2cap_smp_pairinfo *pres) {
	unsigned int pin = 0;
	//printf("CODE:%d IOCAP %d %d %d %d %d %d(%d)\n", pres->code,pres->iocap ,
	//	 pres->oob, pres->authreq,
	//	 pres->maxkeysize, pres->ikeydist, pres->rkeydist, sizeof(*pres));
	memcpy(&ctx.pres, pres, sizeof(*pres));

	if((ctx.preq.iocap < 5) && (ctx.pres.iocap < 5)){
	  if(iocapmat[ctx.pres.iocap][ctx.preq.iocap]==SMP_USE_PASSKEY_I){
	    printf("PIN requested:\n");
	    if(scanf("%u", &pin) != 1){
	      printf("PIN FAIL\n");
	      pin = 0;
	    }
	  }else if(iocapmat[ctx.pres.iocap][ctx.preq.iocap]== SMP_USE_PASSKEY_R){
	    pin = arc4random()%999999;
	  }
	  fprintf(stderr, "PIN:%u %x\n", pin, pin);
	} else {
	  	fprintf(stderr, "IO cap out of range\n");
		return (-1);
	}
	ctx.tk[15] = pin & 0xff;
	ctx.tk[14] = (pin >> 8) & 0xff;
	ctx.tk[13] = (pin >> 16) & 0xff;
	return (0);
}

int send_pairing_confirm(void) {
	struct ng_l2cap_smp_keyinfo msg_cnfrm;
	uint8_t ret[16];

	arc4random_buf(ctx.rval, sizeof(ctx.rval));

	msg_cnfrm.code = SMP_CODE_PAIRCONFIRM;
	smp_c1b(ctx.tk, ctx.rval, &ctx.preq, &ctx.pres,
	       ctx.l2al.l2cap_bdaddr_type, &ctx.l2al.l2cap_bdaddr, 
	       ctx.l2ar.l2cap_bdaddr_type, &ctx.l2ar.l2cap_bdaddr, ret);
	swap128(ret, msg_cnfrm.val);
	if (write(l2s, &msg_cnfrm, sizeof(msg_cnfrm)) < 0) {
		perror("Failed sending confirm msg");
		return (-1);
	}
	return (0);
}

void hexdump(uint8_t *val) {
	for (int i = 0; i < 16; i++) {
		printf("%02x ", val[i]);
	}
	printf("\n");
}
int process_pairing_confirm(struct ng_l2cap_smp_keyinfo *pkt) {
	printf("<Pairing confirm received\n");
	memcpy(&ctx.cnfrm_val, pkt->val, sizeof(pkt->val));
	return (0);
}

int process_pairing_failed(struct ng_l2cap_smp_failed *pf) {
	printf("<Pairing failed: %d\n", pf->reason);
	return (0);
}

int send_rand_val(void) {
	printf(">Sending random value\n");
	struct ng_l2cap_smp_keyinfo msg_rand;
	msg_rand.code = SMP_CODE_PAIRRAND;		
	swap128(ctx.rval, msg_rand.val);
	if (write(l2s, &msg_rand, sizeof(msg_rand))  < 0) {
		perror("Failed sending random value");
		return (-1);
	}
	return (0);
}
int process_pairing_randv(struct ng_l2cap_smp_keyinfo *pkt) {
	printf("<Received random value\n");
	uint8_t ret[16];
	swap128(pkt->val, ctx.rvalr);
	smp_c1b(ctx.tk, ctx.rvalr, &ctx.preq, &ctx.pres,
	       ctx.l2al.l2cap_bdaddr_type, &ctx.l2al.l2cap_bdaddr, 
	       ctx.l2ar.l2cap_bdaddr_type, &ctx.l2ar.l2cap_bdaddr, ret);

	/* Validate confirm value */
	for(int i = 0; i < 16; i++){
		if(ret[i] != ctx.cnfrm_val[15-i]){
			printf("uh oh mis match!!\n");
			return (-1);
		}
	}

	return (0);
}

int generate_stk(void) {
	uint8_t ret[16];
	smp_s1(ctx.tk, ctx.rval, ctx.rvalr, ret);
	swap128(ret, ctx.stk);
	return (0); // TODO
}

int start_encryption(void) {
	printf("Starting encryption\n");
	struct bt_devreq req;
	ng_hci_le_start_encryption_cp cp;
	//ng_hci_status_rp rp;

	memcpy(&cp.long_term_key, ctx.stk, 16);
	cp.connection_handle = ctx.hci_handle;
	cp.random_number = 0;
	cp.encrypted_diversifier = 0;

	req.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE ,NG_HCI_OCF_LE_START_ENCRYPTION);
	req.cparam = &cp;
	req.clen = sizeof(cp);
	bt_devreq(hs, &req, 30);
	return (0);
}

int le_smpconnect(bdaddr_t *bdaddr, bdaddr_t *bdloc, int hci, uint8_t addrtype)
{
	/*
		struct ng_l2cap_smp_failed failed;
	       



		{
			uint8_t mr[16], sr[16],stk[16];
			{
				struct ng_l2cap_smp_keyinfo ki;
				struct ng_l2cap_smp_centralinfo ci;
				ng_hci_le_start_encryption_cp cp;
				
				uint8_t pkt[30];
				int encok=0, mok=0;
				
				while(encok==0||mok==0){
					read(s, pkt, sizeof(pkt));
					switch(pkt[0]){
					case SMP_CODE_CENTRALINFO:
						mok=1;
						bcopy(pkt, &ci,sizeof(ci));
						break;
					case SMP_CODE_ENCINFO:
						encok=1;
						bcopy(pkt,&ki, sizeof(ki));
						break;
						
					}
				}
				printf("device{\n");
				printf("\tname \"thisdevice\";\n ");
				printf("\tbdaddr %s;\n", bt_ntoa(bdaddr, NULL));
				printf("\taddrtype %s;\n", (israndom)?
				       "lernd":"lepub");
				printf("\tediv 0x%04x;\n",ci.ediv);
				cp.encrypted_diversifier = ci.ediv;
				cp.random_number = 0;
				for(i = 0; i < 8 ; i++){
					cp.random_number
						|= (((uint64_t)ci.rand[i])<<(i*8));
				}
				printf("\trand 0x%lx;\n", cp.random_number);

				printf("\tkey 0x");
				for(i = 0 ; i < 16; i++){
					printf("%02x", ki.val[i]);
					cp.long_term_key[i] = ki.val[i];
				}
				printf(";\n");
				printf("\tpin nopin;\n");
				printf("}\n");
				arc4random_buf(ki.val, sizeof(ki.val));
				ki.code = SMP_CODE_ENCINFO;
				write(s, &ki, sizeof(ki));
				ci.ediv = arc4random()&0xffff;
				arc4random_buf(&ci.rand, sizeof(ci.rand));
				ci.code = SMP_CODE_CENTRALINFO;
				write(s, &ci, sizeof(ci));

#if 0
				sleep(4);
				cp.connection_handle = handle;
				n = sizeof(cp);
				hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE
							       ,NG_HCI_OCF_LE_START_ENCRYPTION),
					    (char *)&cp, sizeof(cp), (char *)&rp, &n);
				sleep(30);
#endif
			}
			
				
		}

#if 0
		{
			ng_hci_le_connection_update_cp cp = {
				.connection_handle = handle,
				.conn_interval_min = htobs(6),
				.conn_interval_max = htobs(7),
				.conn_latency = htobs(0),
				.supervision_timeout = htobs(0xc80),
				.minimum_ce_length = htobs(1),
				.maximum_ce_length = htobs(1)
			};
			ng_hci_status_rp rp;

			int n = sizeof(cp);
			hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_CONNECTION_UPDATE),
				    (char *)&cp, sizeof(cp), (char *)&rp, &n);
		}
#endif

	fail:
		if(ng){
			failed.code = SMP_CODE_PAIRFAIL;
			failed.reason = 4;
			write(s, &failed, sizeof(failed));
		}
	}
	return 0;
	*/
}

int main(int argc, char *argv[]) {
	memset(&ctx, 0, sizeof(ctx));

	//smp_c1_unittest();
	//smp_c1_unittest_b();
	char *node = "ubt1hci";
	bdaddr_t bd, bdloc;
	int ch;
	uint8_t addrtype = BDADDR_LE_PUBLIC;
	uint8_t buf[512]; // TODO: max size?
	 ssize_t len;
	
	while((ch = getopt(argc, argv, "r")) != -1){
		switch(ch){
		case 'r':
			addrtype = BDADDR_LE_RANDOM;
			break;
		default:
			fprintf(stderr, "Usage: %s [-r] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if(argc <= 0){
		fprintf(stderr, "Not enough arguments\n");
	}

	if (bt_devaddr(node, &bdloc) < 1) {
		perror("Failed to get address of local node");
		return (-1);
	}
	if (!bt_aton(argv[0], &bd)) {
		fprintf(stderr, "Invalid remote address\n");
		return (-1);
	}
	
	printf("Opening %s with address %s\n", node, bt_ntoa(&bdloc, NULL));
	if ((hs = bt_devopen(node)) < 1) {
		fprintf(stderr, "Failed opening local node\n");
		return (-1);
	}

	if (l2connect(&bd, &bdloc, 0, addrtype) < 0) {
		fprintf(stderr, "Failed connecting to remote.\n");
		return (-1);
		goto out;
	}
	if (find_hci_con_handle() < 0) {
		fprintf(stderr, "Failed to find hci handle of l2cap connection.\n");
		return (-1);
		goto out;
	}

	send_pairing_request();
	for (;;) {
		len = read(l2s, &buf, sizeof(buf));
	       if (len < 0) {
	       	perror("Error reading from l2cap socket");
	       	goto out;
	       }
	       if (buf[0] == SMP_CODE_PAIRRES) {
	       	if (process_pairing_response((struct ng_l2cap_smp_pairinfo*)buf) == 0) {
	       		send_pairing_confirm();
	       	}
	       } else if (buf[0] == SMP_CODE_PAIRCONFIRM) {
	       	process_pairing_confirm((struct ng_l2cap_smp_keyinfo*)buf);
	       	send_rand_val();
	       } else if (buf[0] == SMP_CODE_PAIRFAIL) {
	       	process_pairing_failed((struct ng_l2cap_smp_failed*)buf);
	       } else if (buf[0] == SMP_CODE_PAIRRAND) {
	       	process_pairing_randv((struct ng_l2cap_smp_keyinfo*)buf);
		generate_stk();
		start_encryption();
	       } else {
	       	printf("Unknown code: %d\n", buf[0]);
	       	return (-1);
	       	goto out;
	       }
	       memset(buf, 0, sizeof(buf));
	}

out:
	 close(l2s);
	 close(hs);
	 memset(&ctx, 0, sizeof(ctx));
}

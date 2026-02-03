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

static int le_connect_result(int s);

int le_smpconnect(bdaddr_t *bdaddr, int hci, bool israndom)
{
	struct sockaddr_l2cap l2addr;
	int s;
	int i;
	int handle = 0;
	struct ng_l2cap_smp_pairinfo preq, pres;
	uint8_t k[16];
	struct sockaddr_l2cap myname;

	s = socket(PF_BLUETOOTH, SOCK_SEQPACKET|SOCK_NONBLOCK,
		   BLUETOOTH_PROTO_L2CAP);
	if (s < 0)
		return (-1);

	l2addr.l2cap_len = sizeof(l2addr);
	l2addr.l2cap_family = AF_BLUETOOTH;
	l2addr.l2cap_psm = 0;
	l2addr.l2cap_cid = NG_L2CAP_SMP_CID;
	l2addr.l2cap_bdaddr_type = israndom ? BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
	memcpy(bdaddr, &l2addr.l2cap_bdaddr, sizeof(*bdaddr));

	// TODO: no bind needed???
	if (connect(s, (struct sockaddr *) &l2addr, sizeof(l2addr)) < 0){
	  perror("connect");
	  return (-1);
	}

	do {
	  handle = le_connect_result(hci);
	} while(handle==0);

	{
	  int fl;
	  fl = fcntl(s, F_GETFL, 0);
	  fcntl(s, F_SETFL, fl&~O_NONBLOCK);
	}
		
	{
	  preq.code = SMP_CODE_PAIRREQ;
	  preq.iocap = 4;
	  preq.oobflag = SMP_OOB_AUTH_NOT_PRESENT;
	  preq.authreq = 1;
	  preq.maxkeysize = 16;
	  preq.ikeydist = 1;
	  preq.rkeydist = 1;
	  write(s, &preq, sizeof(preq));

	  ssize_t len;
	  do {
	    len = read(s, &pres, sizeof(pres));
#if 0
	    printf("%d, pi.code %d\n",len, pres.code);
#endif
	    
	  } while (pres.code != SMP_CODE_PAIRRES);
#if 0
	  printf("C\n");
	  printf("CODE:%d IOCAP %d %d %d %d %d %d(%d)\n", pres.code,pres.iocap ,
		 pres.oobflag, pres.authreq,
		 pres.maxkeysize, pres.ikeydist, pres.rkeydist, sizeof(pres));
#endif
	}

	{
		socklen_t siz = sizeof(myname);
		if(getsockname(s, (struct sockaddr *)&myname,&siz)!=0){
			perror("getsockname");
		}
	}
	{
		struct ng_l2cap_smp_keyinfo mrand,mconfirm,srand,sconfirm;
		struct ng_l2cap_smp_failed failed;
		uint8_t rval[16];
		int ng = 0;
		int res;
		unsigned int pin = 0;
		if((preq.iocap<5)&& (pres.iocap<5)){
		  if(iocapmat[pres.iocap][preq.iocap]==1){
		    printf("PIN requested:\n");
		    if(scanf("%u", &pin) != 1){
		      printf("PIN FAIL\n");
		      pin = 0;
		    }
		  }else if(iocapmat[pres.iocap][preq.iocap]== -1){
		    pin = arc4random()%999999;
		  }
		  fprintf(stderr, "PIN:%u %x\n", pin, pin);
		}
		bzero(k, sizeof(k));
		k[15] = pin&0xff;
		pin>>=8;
		k[14] = pin&0xff;
		pin>>=8;
		k[13] = pin&0xff;
		arc4random_buf(rval, sizeof(rval));
		swap128(rval, mrand.val);
		mconfirm.code = SMP_CODE_PAIRCONFIRM;
		mrand.code = SMP_CODE_PAIRRAND;		
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  (israndom) ? 1 : 0, bdaddr);
		swap128(rval, mconfirm.val);
		write(s, &mconfirm, sizeof(mconfirm));
	       
		res = read(s, &sconfirm, sizeof(sconfirm));
		if(sconfirm.code != SMP_CODE_PAIRCONFIRM){
			printf("FAILED:sconfirm.code %d\n", sconfirm.code);
		}
		sleep(5);
		write(s, &mrand, sizeof(mrand));
		res = read(s, &srand, sizeof(srand));
		if(srand.code != SMP_CODE_PAIRRAND){
			struct ng_l2cap_smp_failed *req;
			req = (void *)&srand;
			printf("FAILED:srand.code %d %d\n", req->code, req->reason);
			ng = 1;
			goto fail;
		}
		swap128(srand.val, rval);
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  israndom ? 1:0, bdaddr);
		for(i =0; i< 16; i++){
			if(rval[i] != sconfirm.val[15-i]){
				ng = 1;
				goto fail;
			}
		}
		

		{
			uint8_t mr[16], sr[16],stk[16];
			ng_hci_le_start_encryption_cp cp;
			ng_hci_status_rp rp;
			ssize_t n;

			swap128(mrand.val, mr);
			swap128(srand.val, sr);
			smp_s1(k, sr, mr, stk);
			swap128(stk, cp.long_term_key);
			cp.connection_handle = handle;
			cp.random_number = 0;
			cp.encrypted_diversifier = 0;
			n = sizeof(cp);
			hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE
				     ,NG_HCI_OCF_LE_START_ENCRYPTION),
				    (char *)&cp, sizeof(cp), (char *)&rp, &n);
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
}

static int le_connect_result(int s)
{
	uint8_t buf[512];
	ng_hci_event_pkt_t *e = (ng_hci_event_pkt_t *)buf;
	ng_hci_le_ep *ep = (ng_hci_le_ep *)(e+1);
	ng_hci_le_connection_complete_ep *ccep = (ng_hci_le_connection_complete_ep *)(ep+1);
	struct bt_devfilter flt, flt_old;

	ssize_t n;
	int error = 0;
	int to = 30;

	memset(&flt, 0, sizeof(flt));
	bt_devfilter_pkt_set(&flt, NG_HCI_EVENT_PKT);
	bt_devfilter_evt_set(&flt, NG_HCI_EVENT_LE);
	if (bt_devfilter(s, &flt, &flt_old) < 0)
		return(-1);

	n = bt_devrecv(s, buf, sizeof(buf), to);
	if (n < 0) {
		error = errno;
		goto out;
	}

	if(e->type != NG_HCI_EVENT_PKT){
		error = EIO;
		goto out;
	}

	if(ep->subevent_code != NG_HCI_LEEV_CON_COMPL){
		error = EIO;
		goto out;
	}
#if 1
	char addrstring[50];
	printf("Connection Event:Status%d, handle%d, role%d, address_type:%d\n",
	       ccep->status, ccep->handle, ccep->role, ccep->address_type);
	bt_ntoa(&ccep->address, addrstring);
	printf("%s %d %d %d %d\n", addrstring, ccep->interval, ccep->latency,
	       ccep->supervision_timeout, ccep->master_clock_accuracy);
#endif
	if(ccep->status != 0){
		printf("REQUEST ERROR %d\n", ccep->status);
		return 0;
	}

out:
	bt_devfilter(s, &flt_old, NULL);
	if (error != 0) {
		errno = error;
		return (-1);
	}

	return ccep->handle;
}

int main(int argc, char *argv[])
{

	int s;
	char *node="ubt0hci";
	int addr_valid = 0;
	bdaddr_t bd;
	int ch;
	bool addrrandom = false;
	
	while((ch = getopt(argc, argv, "r")) != -1){
		switch(ch){
		case 'r':
			addrrandom = true;
			break;
		default:
			fprintf(stderr, "Usage: %s [-r] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if(argc > 0){
		addr_valid = bt_aton(argv[0],&bd);
	}
	
	s = bt_devopen(node);

	if(addr_valid){
		le_smpconnect(&bd, s, addrrandom);
	}else{
		fprintf(stderr, "Address Invalid\n");
	}
	
	return 0;
}

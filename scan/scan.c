/* 
 * Copyright (c) 2026 Bram Ton
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/bitstring.h>
#include <sys/select.h>
#include <sys/queue.h>

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

struct ad_t {
	uint8_t length;
	uint8_t type;
	uint8_t *data;
};

struct le_adv_report {
	uint8_t type;
	uint8_t bdaddr_type;
	bdaddr_t bdaddr;
	struct ad_t *ads;
	int8_t rssi;
};

static int
parse_adv_report_pkt(ng_hci_le_advertising_report_ep *pkt) {
	ssize_t ad_data_size;
	ssize_t rem;
	uint8_t ad_length;
	uint8_t ad_type;
	uint8_t ads_length = 0;
	uint8_t *p;
	struct le_adv_report ar;

	printf("  Number of reports: %d\n", pkt->num_reports);
	if (pkt->num_reports == 0 || pkt->num_reports > 0x19)
		fprintf(stderr, "Num reports outside limits\n");
	p = (uint8_t *)(pkt + 1);
	for (int i = 0; i < pkt->num_reports; i++) {
		printf("    Advert type: %02x\n", *p++);
		printf("    Addr type: %02x\n", *p++);
		memcpy(&ar.bdaddr, p, sizeof(ar.bdaddr));
		printf("    Addr: %s\n", bt_ntoa(&ar.bdaddr, NULL));
		p += sizeof(bdaddr_t);
		//p += 6;
		ad_data_size = *p++;

		/* Determine number of AD structures */
		rem = ad_data_size;
		while (rem > 0) {
			ads_length++;
			ad_length = *p++;
			rem -= (ad_length + 1);
			p += ad_length;
		}
		p -= ad_data_size; /* Reset pointer to first AD structure*/
		printf("    AD length: %d\n", ads_length);

		ar.ads = (struct ad_t *)malloc(ads_length*sizeof(struct ad_t));
		for (int i = 0; i < ads_length; i++) {
			ad_length = *p++;
			ar.ads[i].length = ad_length;
			ad_type = *p++;
			ar.ads[i].type = ad_type;
			ar.ads[i].data = (uint8_t *)malloc(ad_length - 1);
			memcpy(ar.ads[i].data, p, ad_length - 1);
			p += (ad_length - 1);
			if (ad_type == 0x0a) {
				printf("     Tx power: %d dBm\n", (int8_t)(ar.ads[i].data[0]));
			}
			else if (ad_type == 0x09) {
				char *str = (char *)malloc(ad_length);
				strlcpy(str, (char *)ar.ads[i].data, ad_length-1);
				printf("     name: %s\n", str);
			}
			else {
				printf("     Data type: %02x (len: %d)\n", ad_type, ad_length);
			}
		}
		ar.rssi = (int8_t)*p++;
		printf("    RSSI: %i dBm\n", ar.rssi);
	}
}

static int
le_scan_enable(int s) {
	ng_hci_le_set_scan_enable_cp cp;
	struct bt_devreq req;

	memset(&cp, 0, sizeof(cp));
	cp.le_scan_enable = 1;
	cp.filter_duplicates = 0;

	memset(&req, 0, sizeof(req));
	req.opcode = NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_SCAN_ENABLE);
	req.cparam = &cp;
	req.clen = sizeof(cp);
	if (bt_devreq(s, &req, 10) < 0) {
		perror("Could not enable scan");
		return (-1);
	}

	return (0);
}

int
main(int argc, char *argv[]) {
	uint8_t buf[512];
	int s, n;
	char *node = "ubt1hci";
	ng_hci_event_pkt_t *hdr;
	ng_hci_le_ep *lep;

	if ((s = bt_devopen(node)) < 1) {
		fprintf(stderr, "Failed opening local node %s\n", node);
		return (-1);
	}

	le_scan_enable(s);

	struct bt_devfilter old, new;
	memset(&new, 0, sizeof(new));
	bt_devfilter_pkt_set(&new, NG_HCI_EVENT_PKT); 
	bt_devfilter_evt_set(&new, NG_HCI_EVENT_LE);
	if (bt_devfilter(s, &new, &old) < 0)
		return (-1);

	memset(buf, 0, sizeof(buf));
	for(;;) {
		//n = bt_devrecv(s, buf, sizeof(buf), 10);
		n = read(s, buf, sizeof(buf));
		if (n < 0 && errno != ETIMEDOUT) {
			perror("Error reading from socket");
			goto out;
		}
		hdr = (ng_hci_event_pkt_t *)buf;
		printf("Received something %d\n", hdr->length);
		lep = (ng_hci_le_ep *)(hdr + 1);
		if (lep->subevent_code == NG_HCI_LEEV_ADVREP) {
			parse_adv_report_pkt((ng_hci_le_advertising_report_ep *)(lep + 1));
		}
		memset(buf, 0, sizeof(buf));
	}


out:
	 close(s);
}

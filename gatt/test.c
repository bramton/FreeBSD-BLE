#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bluetooth.h>
#define L2CAP_SOCKET_CHECKED

#include "att.h"
#include "gatt.h"

int
main(int argc, char *argv[]) {
	int l2s;
	bdaddr_t bdcen, bdper;
	struct sockaddr_l2cap l2cen,l2a;
	uint8_t addrtype = BDADDR_LE_PUBLIC;
	int ch;
	char *node = "ubt0hci";
	uint16_t imtu, omtu;
	size_t len;
	struct le_attreq req;
	struct le_att_exchange_mtu_msg mtu_msg, mtu_rsp;

	while((ch = getopt(argc, argv, "n:r")) != -1){
		switch(ch){
		case 'r':
			addrtype = BDADDR_LE_RANDOM;
			break;
		case 'n':
			node = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s [-r] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (bt_devaddr(node, &bdcen) < 1) {
		perror("Failed to get address of local node");
		return (-1);
	}

	if (!bt_aton(argv[0], &bdper)) {
		fprintf(stderr, "Invalid peripheral address\n");
		return (-1);
	}

	l2s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (l2s < 0) {
		perror("Failed opening socket");
		return (-1);
	}

	memset(&l2cen, 0, sizeof(l2cen));
	l2cen.l2cap_len = sizeof(l2cen);
	l2cen.l2cap_family = AF_BLUETOOTH;
	l2cen.l2cap_bdaddr_type = BDADDR_LE_PUBLIC; // TODO: always ??
	bdaddr_copy(&l2cen.l2cap_bdaddr, &bdcen);

	if (bind(l2s, (struct sockaddr *) &l2cen, sizeof(l2cen)) < 0) {
		perror("Could not bind to local address");
		return (-1);
	}
	addrtype = BDADDR_LE_RANDOM;
	memset(&l2a, 0, sizeof(l2a));
	l2a.l2cap_len = sizeof(l2a);
	l2a.l2cap_family = AF_BLUETOOTH;
	l2a.l2cap_cid = NG_L2CAP_ATT_CID;
	l2a.l2cap_bdaddr_type = addrtype;
	bdaddr_copy(&l2a.l2cap_bdaddr, &bdper);

	if (connect(l2s, (struct sockaddr *) &l2a, sizeof(l2a)) < 0 && 
	    errno != EINPROGRESS) {
	    perror("Failed to connect to l2cap socket");
	    return (-1);
	}

	len = sizeof(imtu);
	if (getsockopt(l2s, SOL_L2CAP, SO_L2CAP_IMTU, &imtu, &len) < -1) {
		perror("Failed to get l2cap imtu");
		return(-1);
	}
	printf("imtu: %d\n", imtu);

	len = sizeof(omtu);
	if (getsockopt(l2s, SOL_L2CAP, SO_L2CAP_OMTU, &omtu, &len) < -1) {
		perror("Failed to get l2cap omtu");
		return(-1);
	}
	printf("omtu: %d\n", omtu);

	mtu_msg.mtu_size = imtu;
	memset(&req, 0, sizeof(req));
	req.opcode  = ATT_OP_MTU_REQ;
	req.cparam = &mtu_msg;
	req.clen = sizeof(mtu_msg);
	req.rparam = &mtu_rsp;
	req.rlen = sizeof(mtu_rsp);
	if (le_attreq(l2s, &req, 30) < 0) {
		perror("att req fail");
		return (-1);
	}

	struct le_att_read_group_req_short pkt;
	req.opcode= ATT_OP_READ_GROUP_REQ;
	pkt.start = 0x0001;
	pkt.end = 0xFFFF;
	pkt.type = GATT_SERVICE_PRIMARY;
	req.cparam = &pkt;
	req.clen = sizeof(pkt);

	le_attreq(l2s, &req, 30);

	close(l2s);
	return (0);
}

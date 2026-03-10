/*
 * Copyright (c) 2026 Bram Ton
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/uio.h>
//#include <sys/sysctl.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include "att.h"

/* Derived from bt_devreq() */
int
le_attreq(int s, struct le_attreq *r, time_t to) {
	uint8_t buf[255];
	uint8_t *opc = buf;
	ssize_t n;
	time_t t_end;
	int error = 0;

	if (s < 0 || r == NULL || to < 0) {
		errno = EINVAL;
	       	return (-1);
	}

       	if ((r->rlen == 0 && r->rparam != NULL) ||
	    (r->rlen > 0 && r->rparam == NULL)) {
		errno = EINVAL;
	       	return (-1);
	}

	n = le_attsend(s, r->opcode, r->cparam, r->clen);
	if (n < 0) {
		error = errno;
		goto out;
	}

	t_end = time(NULL) + to;

	do {
		to = t_end - time(NULL);
		if (to < 0)
			to = 0;
		
		n = le_attrecv(s, buf, sizeof(buf), to);
		if (n < 0) {
			error = EIO;
			goto out;
		}

		printf("Before method check\n");
		printf("method: %02x\n", (buf[0]));
		printf("blablabla\n");
		if (*opc & ATT_OPC_METHOD_MSK != ((r->opcode & ATT_OPC_METHOD_MSK) + 1)) {
			printf("ERROR\n");
			error = EIO;
			goto out;
		}

		printf("Received something (%d):", n);
		n -= sizeof(*opc);
		printf("Received something (%d):", n);
		r->rlen = n;
		memcpy(r->rparam, opc + 1, r->rlen);

		printf("Received something (%d):", r->rlen);
		for (int i = 0; i < n; i++) {
			printf("%02x", buf[i]);
		}
		printf("\n");

	} while (to > 0);




out:
	if (error != 0) {
		errno = error;
		return (-1);
	}

	return (0);
}

int
le_attsend(int s, uint8_t oc, void *param, size_t plen) {
	struct iovec iv[2];
	int ivn;

	if ((plen == 0 && param != NULL) ||
	    (plen  > 0 && param == NULL) ||
	     plen  > UINT8_MAX) { /// TODO: what is max pkt size????
		errno = EINVAL;
	        return (-1);
	}

	iv[0].iov_base = &oc;
	iv[0].iov_len = sizeof(oc);
	ivn = 1;
	printf("oc: %02x\n", oc);

	if (plen > 0) {
		iv[1].iov_base = param;
		iv[1].iov_len = plen;
		ivn = 2;
	}
	printf("param (%d)", plen);
	for (int i = 0; i < plen; i++) {
		printf("%02x", ((uint8_t*)param)[i]);
	}
	printf("\n");

	while (writev(s, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;

		return (-1);
	}

	return 0;
}

int
le_attrecv(int s, void *buf, size_t len, time_t to) {
	ssize_t n;

	if (buf == NULL || len == 0) {
		errno = EINVAL;
		return (-1);
	}

	if (to >= 0) {
		fd_set rfd;
		struct timeval tv;
		FD_ZERO(&rfd);
		FD_SET(s, &rfd);
		tv.tv_sec = to;
		tv.tv_usec = 0;

		while ((n = select(s + 1, &rfd, NULL, NULL, &tv)) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return (-1);
		}

		if (n == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}

		assert(FD_ISSET(s, &rfd));
	}

	while ((n = read(s, buf, len)) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return (-1);
	} 

	return n;
}

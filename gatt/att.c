/*
 * Copyright (c) 2026 Bram Ton
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/uio.h>
//#include <sys/sysctl.h>

#include <errno.h>
#include <inttypes.h>
#include <time.h>

#include "att.h"

/* Derived from bt_devreq() */
int
le_attreq(int s, struct le_attreq *r, time_t to) {
	uint8_t buf[255];
	struct le_att_opcode *opcode = (struct le_att_opcode *)buf;
	ssize_t n;
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
out:
	if (error != 0) {
		errno = error;
		return (-1);
	}

	return (0);
}

int
le_attsend(int s, struct le_att_opcode oc, void *param, size_t plen) {
	struct iovec iv[2];
	int ivn;

	if ((plen == 0 && param != NULL) ||
	    (plen  > 0 && param == NULL) ||
	     plen  > UINT8_MAX) { /// TODO: what is max pkt size????
		errno = EINVAL;
	        return (-1);
	}

	iv[0].iov_base = &oc;
	iv[0].iov_len = sizeof(struct le_att_opcode);
	ivn = 1;

	if (plen > 0) {
		iv[1].iov_base = param;
		iv[1].iov_len = plen;
		ivn = 2;
	}

	while (writev(s, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;

		return (-1);
	}

	return 0;
}

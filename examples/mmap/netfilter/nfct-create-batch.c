/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

static void put_msg(char *buf, uint16_t i, int seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	struct nlattr *nest1, *nest2;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlh->nlmsg_seq = seq;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	nest1 = mnl_attr_nest_start(nlh, CTA_TUPLE_ORIG);
	nest2 = mnl_attr_nest_start(nlh, CTA_TUPLE_IP);
	mnl_attr_put_u32(nlh, CTA_IP_V4_SRC, inet_addr("1.1.1.1"));
	mnl_attr_put_u32(nlh, CTA_IP_V4_DST, inet_addr("2.2.2.2"));
	mnl_attr_nest_end(nlh, nest2);

	nest2 = mnl_attr_nest_start(nlh, CTA_TUPLE_PROTO);
	mnl_attr_put_u8(nlh, CTA_PROTO_NUM, IPPROTO_TCP);
	mnl_attr_put_u16(nlh, CTA_PROTO_SRC_PORT, htons(i));
	mnl_attr_put_u16(nlh, CTA_PROTO_DST_PORT, htons(1025));
	mnl_attr_nest_end(nlh, nest2);
	mnl_attr_nest_end(nlh, nest1);

	nest1 = mnl_attr_nest_start(nlh, CTA_TUPLE_REPLY);
	nest2 = mnl_attr_nest_start(nlh, CTA_TUPLE_IP);
	mnl_attr_put_u32(nlh, CTA_IP_V4_SRC, inet_addr("2.2.2.2"));
	mnl_attr_put_u32(nlh, CTA_IP_V4_DST, inet_addr("1.1.1.1"));
	mnl_attr_nest_end(nlh, nest2);

	nest2 = mnl_attr_nest_start(nlh, CTA_TUPLE_PROTO);
	mnl_attr_put_u8(nlh, CTA_PROTO_NUM, IPPROTO_TCP);
	mnl_attr_put_u16(nlh, CTA_PROTO_SRC_PORT, htons(1025));
	mnl_attr_put_u16(nlh, CTA_PROTO_DST_PORT, htons(i));
	mnl_attr_nest_end(nlh, nest2);
	mnl_attr_nest_end(nlh, nest1);

	nest1 = mnl_attr_nest_start(nlh, CTA_PROTOINFO);
	nest2 = mnl_attr_nest_start(nlh, CTA_PROTOINFO_TCP);
	mnl_attr_put_u8(nlh, CTA_PROTOINFO_TCP_STATE, TCP_CONNTRACK_SYN_SENT);
	mnl_attr_nest_end(nlh, nest2);
	mnl_attr_nest_end(nlh, nest1);

	mnl_attr_put_u32(nlh, CTA_STATUS, htonl(IPS_CONFIRMED));
	mnl_attr_put_u32(nlh, CTA_TIMEOUT, htonl(1000));
}

static int cb_err(const struct nlmsghdr *nlh, void *data)
{
	struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
	if (err->error != 0)
		printf("message with seq %u has failed: %s\n",
			nlh->nlmsg_seq, strerror(-err->error));
	return MNL_CB_OK;
}

static mnl_cb_t cb_ctl_array[NLMSG_MIN_TYPE] = {
	[NLMSG_ERROR] = cb_err,
};

static void
send_batch(struct mnl_socket *nl, struct mnl_nlmsg_batch *b, int portid)
{
	int ret, skerr, fd = mnl_socket_get_fd(nl);
	char buf[MNL_SOCKET_BUFFER_SIZE * 2];
	struct nl_mmap_hdr *frame;
	void *ptr;
	ssize_t len;
	socklen_t errlen = sizeof(skerr);
	struct mnl_ring *rxring, *txring;

	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);
	txring = mnl_socket_get_ring(nl, MNL_RING_TX);

	ret = mnl_socket_sendto(nl, NULL, 0);
	if (ret == -1) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}
	mnl_ring_advance(txring);

	/* receive and digest all the acknowledgments from the kernel. */
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	ret = select(fd + 1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		perror("select");
		exit(EXIT_FAILURE);
	}
	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		if (getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_ERROR, &skerr, &errlen) < 0) {
			perror("getsockopt");
			exit(EXIT_FAILURE);
		}
		if (skerr) {
			fprintf(stderr, "got SO_ERROR: %s\n", strerror(skerr));
			break;
		}

		frame = mnl_ring_get_frame(rxring);
		if (frame->nm_status == NL_MMAP_STATUS_VALID) {
			if (frame->nm_len == 0)
				goto release;
			len = frame->nm_len;
			ptr = MNL_FRAME_PAYLOAD(frame);
		} else if (frame->nm_status == NL_MMAP_STATUS_COPY) {
			len = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (len < 0) {
				perror("mnl_socket_recvfrom");
				exit(EXIT_FAILURE);
			}
			ptr = buf;
		} else {
			FD_ZERO(&readfds);
			FD_SET(fd, &readfds);
			ret = select(fd + 1, &readfds, NULL, NULL, &tv);
			if (ret == -1) {
				perror("select");
				exit(EXIT_FAILURE);
			}
			continue;
		}

		ret = mnl_cb_run2(ptr, len, 0, portid,
				  NULL, NULL, cb_ctl_array,
				  MNL_ARRAY_SIZE(cb_ctl_array));
		if (ret == -1) {
			perror("mnl_cb_run2");
			exit(EXIT_FAILURE);
		}
	release:
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(rxring);
	}
}

int main(void)
{
	struct mnl_socket *nl;
	struct mnl_nlmsg_batch *b;
	int j;
	unsigned int seq, portid;
	uint16_t i;
	struct mnl_ring *txring;
	struct nl_mmap_hdr *frame;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}
	if (mnl_socket_set_ringopt(nl, MNL_RING_RX,
				   MNL_SOCKET_BUFFER_SIZE * 16, 16,
				   MNL_SOCKET_BUFFER_SIZE, 16 * 16) < 0) {
		perror("mnl_socket_set_ringopt - RX");
		exit(EXIT_FAILURE);
	}
	/* will be used in send_batch */
	if (mnl_socket_set_ringopt(nl, MNL_RING_TX,
				   MNL_SOCKET_BUFFER_SIZE * 16, 16,
				   MNL_SOCKET_BUFFER_SIZE, 16 * 16) < 0) {
		perror("mnl_socket_set_ringopt - TX");
		exit(EXIT_FAILURE);
	}
	if (mnl_socket_map_ring(nl) < 0) {
		perror("mnl_socket_map_ring");
		exit(EXIT_FAILURE);
	}
	txring = mnl_socket_get_ring(nl, MNL_RING_TX);

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	frame = mnl_ring_get_frame(txring);
	/* The buffer that we use to batch messages is
	   nlmr.nm_frame_size - sizeof(struct nl_mmap_hdr), but we limit the
	   batch to half of it since the last message that does not fit the
	   batch goes over the upper boundary, if you break this rule, expect
	   memory corruptions. */
	b = mnl_nlmsg_batch_start(MNL_FRAME_PAYLOAD(frame), (MNL_SOCKET_BUFFER_SIZE - sizeof(struct nl_mmap_hdr)) / 2);
	if (b == NULL) {
		perror("mnl_nlmsg_batch_start");
		exit(EXIT_FAILURE);
	}

	seq = time(NULL);
	for (i = 1024, j = 0; i < 65535; i++, j++) {
		put_msg(mnl_nlmsg_batch_current(b), i, seq + j);

		/* is there room for more messages in this batch?
		 * if so, continue. */
		if (mnl_nlmsg_batch_next(b))
			continue;

		frame->nm_len = mnl_nlmsg_batch_size(b);
		frame->nm_status = NL_MMAP_STATUS_VALID;
		send_batch(nl, b, portid);
		/* mnl_socket_advance_ring(nl, MNL_RING_TX) was called in send_batch() */

		frame = mnl_ring_get_frame(txring);
		/* this moves the last message that did not fit into the
		 * batch to the head of it. */
		mnl_nlmsg_batch_reset_buffer(b, MNL_FRAME_PAYLOAD(frame),
					     (MNL_SOCKET_BUFFER_SIZE - sizeof(struct nl_mmap_hdr)) / 2);

	}

	/* check if there is any message in the batch not sent yet. */
	if (!mnl_nlmsg_batch_is_empty(b)) {
		frame->nm_len = mnl_nlmsg_batch_size(b);
		frame->nm_status = NL_MMAP_STATUS_VALID;
		send_batch(nl, b, portid);
	}
	mnl_nlmsg_batch_stop(b);
	mnl_socket_close(nl);

	return 0;
}

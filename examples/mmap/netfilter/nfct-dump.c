/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int parse_counters_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_COUNTERS_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_COUNTERS_PACKETS:
	case CTA_COUNTERS_BYTES:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_counters(const struct nlattr *nest)
{
	struct nlattr *tb[CTA_COUNTERS_MAX+1] = {};

	mnl_attr_parse_nested(nest, parse_counters_cb, tb);
	if (tb[CTA_COUNTERS_PACKETS]) {
		printf("packets=%"PRIu64" ",
		       be64toh(mnl_attr_get_u64(tb[CTA_COUNTERS_PACKETS])));
	}
	if (tb[CTA_COUNTERS_BYTES]) {
		printf("bytes=%"PRIu64" ",
		       be64toh(mnl_attr_get_u64(tb[CTA_COUNTERS_BYTES])));
	}
}

static int parse_ip_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_IP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_IP_V4_SRC:
	case CTA_IP_V4_DST:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTA_IP_V6_SRC:
	case CTA_IP_V6_DST:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
				       sizeof(struct in6_addr)) < 0) {
			perror("mnl_attr_validate2");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_ip(const struct nlattr *nest)
{
	struct nlattr *tb[CTA_IP_MAX+1] = {};

	mnl_attr_parse_nested(nest, parse_ip_cb, tb);
	if (tb[CTA_IP_V4_SRC]) {
		struct in_addr *in = mnl_attr_get_payload(tb[CTA_IP_V4_SRC]);
		printf("src=%s ", inet_ntoa(*in));
	}
	if (tb[CTA_IP_V4_DST]) {
		struct in_addr *in = mnl_attr_get_payload(tb[CTA_IP_V4_DST]);
		printf("dst=%s ", inet_ntoa(*in));
	}
	if (tb[CTA_IP_V6_SRC]) {
		struct in6_addr *in = mnl_attr_get_payload(tb[CTA_IP_V6_SRC]);
		char out[INET6_ADDRSTRLEN];

		if (!inet_ntop(AF_INET6, in, out, sizeof(out)))
			printf("src=%s ", out);
	}
	if (tb[CTA_IP_V6_DST]) {
		struct in6_addr *in = mnl_attr_get_payload(tb[CTA_IP_V6_DST]);
		char out[INET6_ADDRSTRLEN];

		if (!inet_ntop(AF_INET6, in, out, sizeof(out)))
			printf("dst=%s ", out);
	}
}

static int parse_proto_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_PROTO_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_PROTO_NUM:
	case CTA_PROTO_ICMP_TYPE:
	case CTA_PROTO_ICMP_CODE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTA_PROTO_SRC_PORT:
	case CTA_PROTO_DST_PORT:
	case CTA_PROTO_ICMP_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_proto(const struct nlattr *nest)
{
	struct nlattr *tb[CTA_PROTO_MAX+1] = {};

	mnl_attr_parse_nested(nest, parse_proto_cb, tb);
	if (tb[CTA_PROTO_NUM]) {
		printf("proto=%u ", mnl_attr_get_u8(tb[CTA_PROTO_NUM]));
	}
	if (tb[CTA_PROTO_SRC_PORT]) {
		printf("sport=%u ",
			ntohs(mnl_attr_get_u16(tb[CTA_PROTO_SRC_PORT])));
	}
	if (tb[CTA_PROTO_DST_PORT]) {
		printf("dport=%u ",
			ntohs(mnl_attr_get_u16(tb[CTA_PROTO_DST_PORT])));
	}
	if (tb[CTA_PROTO_ICMP_ID]) {
		printf("id=%u ",
			ntohs(mnl_attr_get_u16(tb[CTA_PROTO_ICMP_ID])));
	}
	if (tb[CTA_PROTO_ICMP_TYPE]) {
		printf("type=%u ", mnl_attr_get_u8(tb[CTA_PROTO_ICMP_TYPE]));
	}
	if (tb[CTA_PROTO_ICMP_CODE]) {
		printf("code=%u ", mnl_attr_get_u8(tb[CTA_PROTO_ICMP_CODE]));
	}
}

static int parse_tuple_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_TUPLE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_TUPLE_IP:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTA_TUPLE_PROTO:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void print_tuple(const struct nlattr *nest)
{
	struct nlattr *tb[CTA_TUPLE_MAX+1] = {};

	mnl_attr_parse_nested(nest, parse_tuple_cb, tb);
	if (tb[CTA_TUPLE_IP]) {
		print_ip(tb[CTA_TUPLE_IP]);
	}
	if (tb[CTA_TUPLE_PROTO]) {
		print_proto(tb[CTA_TUPLE_PROTO]);
	}
}

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTA_TUPLE_ORIG:
	case CTA_COUNTERS_ORIG:
	case CTA_COUNTERS_REPLY:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTA_TIMEOUT:
	case CTA_MARK:
	case CTA_SECMARK:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[CTA_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*nfg), data_attr_cb, tb);
	if (tb[CTA_TUPLE_ORIG])
		print_tuple(tb[CTA_TUPLE_ORIG]);

	if (tb[CTA_MARK])
		printf("mark=%u ", ntohl(mnl_attr_get_u32(tb[CTA_MARK])));

	if (tb[CTA_SECMARK])
		printf("secmark=%u ", ntohl(mnl_attr_get_u32(tb[CTA_SECMARK])));

	if (tb[CTA_COUNTERS_ORIG]) {
		printf("original ");
		print_counters(tb[CTA_COUNTERS_ORIG]);
	}

	if (tb[CTA_COUNTERS_REPLY]) {
		printf("reply ");
		print_counters(tb[CTA_COUNTERS_REPLY]);
	}

	printf("\n");
	return MNL_CB_OK;
}

static int mnl_socket_poll(struct mnl_socket *nl)
{
	struct pollfd pfds[1];

	while (1) {
		pfds[0].fd	= mnl_socket_get_fd(nl);
		pfds[0].events	= POLLIN | POLLERR;
		pfds[0].revents = 0;

		if (poll(pfds, 1, -1) < 0 && errno != -EINTR)
			return -1;

		if (pfds[0].revents & POLLIN)
			return 0;
		if (pfds[0].revents & POLLERR)
			return -1;
	}
}

int main(void)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE * 2];
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	uint32_t seq, portid;
	int ret;
	ssize_t len;
	void *ptr;
	struct mnl_ring *txring, *rxring;
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
	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);
	txring = mnl_socket_get_ring(nl, MNL_RING_TX);

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	frame = mnl_ring_get_frame(txring);
	nlh = mnl_nlmsg_put_header(MNL_FRAME_PAYLOAD(frame));
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	frame->nm_len = nlh->nlmsg_len;
	frame->nm_status = NL_MMAP_STATUS_VALID;
	ret = mnl_socket_sendto(nl, NULL, 0);
	if (ret == -1) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}
	mnl_ring_advance(txring);

	portid = mnl_socket_get_portid(nl);

	while (1) {
		frame = mnl_ring_get_frame(rxring);
		if (frame->nm_status == NL_MMAP_STATUS_VALID) {
			if (frame->nm_len == 0)
				goto release;
			len = frame->nm_len;
			ptr = MNL_FRAME_PAYLOAD(frame);
		} else if (frame->nm_status == NL_MMAP_STATUS_COPY) {
			len = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (len == -1) {
				perror("mnl_socket_recvfrom");
				exit(EXIT_FAILURE);
			}
			ptr = buf;
		} else {
			ret = mnl_socket_poll(nl);
			if (ret == -1) {
				perror("mnl_socket_poll");
				exit(EXIT_FAILURE);
			}
			continue;
		}

		ret = mnl_cb_run(ptr, len, seq, portid, data_cb, NULL);
	release:
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(rxring);
		if (ret == -1) {
			perror("mnl_cb_run");
			exit(EXIT_FAILURE);
		} else if (ret <= MNL_CB_STOP)
                        break;
	}

	mnl_socket_close(nl);

	return 0;
}

/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

static int parse_mc_grps_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, CTRL_ATTR_MCAST_GRP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTRL_ATTR_MCAST_GRP_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_MCAST_GRP_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void parse_genl_mc_grps(struct nlattr *nested)
{
	struct nlattr *pos;

	mnl_attr_for_each_nested(pos, nested) {
		struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX+1] = {};

		mnl_attr_parse_nested(pos, parse_mc_grps_cb, tb);
		if (tb[CTRL_ATTR_MCAST_GRP_ID]) {
			printf("id-0x%x ",
				mnl_attr_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID]));
		}
		if (tb[CTRL_ATTR_MCAST_GRP_NAME]) {
			printf("name: %s ",
				mnl_attr_get_str(tb[CTRL_ATTR_MCAST_GRP_NAME]));
		}
		printf("\n");
	}
}

static int parse_family_ops_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_OP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTRL_ATTR_OP_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_OP_MAX:
		break;
	default:
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void parse_genl_family_ops(struct nlattr *nested)
{
	struct nlattr *pos;

	mnl_attr_for_each_nested(pos, nested) {
		struct nlattr *tb[CTRL_ATTR_OP_MAX+1] = {};

		mnl_attr_parse_nested(pos, parse_family_ops_cb, tb);
		if (tb[CTRL_ATTR_OP_ID]) {
			printf("id-0x%x ",
				mnl_attr_get_u32(tb[CTRL_ATTR_OP_ID]));
		}
		if (tb[CTRL_ATTR_OP_MAX]) {
			printf("flags ");
		}
		printf("\n");
	}
}

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTRL_ATTR_FAMILY_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_FAMILY_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_VERSION:
	case CTRL_ATTR_HDRSIZE:
	case CTRL_ATTR_MAXATTR:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case CTRL_ATTR_OPS:
	case CTRL_ATTR_MCAST_GROUPS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
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
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*genl), data_attr_cb, tb);
	if (tb[CTRL_ATTR_FAMILY_NAME]) {
		printf("name=%s\t",
			mnl_attr_get_str(tb[CTRL_ATTR_FAMILY_NAME]));
	}
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		printf("id=%u\t",
			mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]));
	}
	if (tb[CTRL_ATTR_VERSION]) {
		printf("version=%u\t",
			mnl_attr_get_u32(tb[CTRL_ATTR_VERSION]));
	}
	if (tb[CTRL_ATTR_HDRSIZE]) {
		printf("hdrsize=%u\t",
			mnl_attr_get_u32(tb[CTRL_ATTR_HDRSIZE]));
	}
	if (tb[CTRL_ATTR_MAXATTR]) {
		printf("maxattr=%u\t",
			mnl_attr_get_u32(tb[CTRL_ATTR_MAXATTR]));
	}
	printf("\n");
	if (tb[CTRL_ATTR_OPS]) {
		printf("ops:\n");
		parse_genl_family_ops(tb[CTRL_ATTR_OPS]);
	}
	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		printf("grps:\n");
		parse_genl_mc_grps(tb[CTRL_ATTR_MCAST_GROUPS]);
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

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE * 2];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	int ret;
	unsigned int seq, portid;
	ssize_t len;
	void *ptr;
	struct mnl_ring *txring, *rxring;
	struct nl_mmap_hdr *frame;

	if (argc > 2) {
		printf("%s [family name]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nl = mnl_socket_open(NETLINK_GENERIC);
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
	if (mnl_socket_map_ring(nl, MAP_SHARED) < 0) {
		perror("mnl_socket_map_ring");
		exit(EXIT_FAILURE);
	}
	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);
	txring = mnl_socket_get_ring(nl, MNL_RING_TX);

	frame = mnl_ring_get_frame(txring);
	if (frame->nm_status != NL_MMAP_STATUS_UNUSED) {
		fprintf(stderr, "could not get unused tx frame\n");
		exit(EXIT_FAILURE);
	}
	nlh = mnl_nlmsg_put_header(MNL_FRAME_PAYLOAD(frame));
	nlh->nlmsg_type	= GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_u32(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
	if (argc >= 2)
		mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, argv[1]);
	else
		nlh->nlmsg_flags |= NLM_F_DUMP;
	frame->nm_len = nlh->nlmsg_len;
	frame->nm_status = NL_MMAP_STATUS_VALID;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, NULL, 0) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}
	mnl_ring_advance(txring);

	ret = MNL_CB_OK;
	while (ret > 0) {
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
	}

	if (ret < 0) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}

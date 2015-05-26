/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case IFLA_ADDRESS:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_MTU:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
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
	struct nlattr *tb[IFLA_MAX+1] = {};
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

	printf("index=%d type=%d flags=%d family=%d ", 
		ifm->ifi_index, ifm->ifi_type,
		ifm->ifi_flags, ifm->ifi_family);

	if (ifm->ifi_flags & IFF_RUNNING)
		printf("[RUNNING] ");
	else
		printf("[NOT RUNNING] ");

	mnl_attr_parse(nlh, sizeof(*ifm), data_attr_cb, tb);
	if (tb[IFLA_MTU]) {
		printf("mtu=%d ", mnl_attr_get_u32(tb[IFLA_MTU]));
	}
	if (tb[IFLA_IFNAME]) {
		printf("name=%s ", mnl_attr_get_str(tb[IFLA_IFNAME]));
	}
	if (tb[IFLA_ADDRESS]) {
		uint8_t *hwaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);
		int i;

		printf("hwaddr=");
		for (i=0; i<mnl_attr_get_payload_len(tb[IFLA_ADDRESS]); i++) {
			printf("%.2x", hwaddr[i] & 0xff);
			if (i+1 != mnl_attr_get_payload_len(tb[IFLA_ADDRESS]))
				printf(":");
		}
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
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	ssize_t len;
	void *ptr;
	int ret;
	unsigned int seq, portid;
	struct mnl_ring *rxring;
	struct nl_mmap_hdr *frame;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_PACKET;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	/*
	if (mnl_socket_set_ringopt(nl, MNL_RING_TX,
				   MNL_SOCKET_BUFFER_SIZE * 16, 64, 16384,
				   64 * MNL_SOCKET_BUFFER_SIZE * 16 / 16384) < 0) {
		perror("mnl_socket_set_ringopt - TX");
		exit(EXIT_FAILURE);
	}
	*/
	if (mnl_socket_set_ringopt(nl, MNL_RING_RX,
				   MNL_SOCKET_BUFFER_SIZE * 16, 64, 16384,
				   64 * MNL_SOCKET_BUFFER_SIZE * 16 / 16384) < 0) {
		perror("mnl_socket_set_ringopt - RX");
		exit(EXIT_FAILURE);
	}
	if (mnl_socket_map_ring(nl) < 0) {
		perror("mnl_socket_map_ring");
		exit(EXIT_FAILURE);
	}
	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	ret = MNL_CB_OK;
	while (ret > 0) {
		frame = mnl_ring_get_frame(rxring);
		if (frame->nm_status == NL_MMAP_STATUS_VALID) {
			ptr = MNL_FRAME_PAYLOAD(frame);
			len = frame->nm_len;
			if (len == 0)
				goto release;
		} else if (frame->nm_status == NL_MMAP_STATUS_COPY) {
			len = recv(mnl_socket_get_fd(nl),
				   buf, sizeof(buf), MSG_DONTWAIT);
			if (len <= 0)
				break;
			ptr = buf;
		} else {
			if (mnl_socket_poll(nl) < 0) {
				perror("mnl_socket_poll");
				exit(EXIT_FAILURE);
			}
			continue;
		}

		ret = mnl_cb_run(ptr, len, seq, portid, data_cb, NULL);
		if (ret <= MNL_CB_STOP)
			break;
	release:
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(rxring);

	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}

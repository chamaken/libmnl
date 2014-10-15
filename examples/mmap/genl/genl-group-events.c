/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

static int group;

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	printf("received event type=%d from genetlink group %d\n",
		nlh->nlmsg_type, group);
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
	int ret;
	ssize_t len;
	void *ptr;
	struct mnl_ring *rxring;
	struct nl_mmap_hdr *frame;

	if (argc != 2) {
		printf("%s [group]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	group = atoi(argv[1]);

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
	if (mnl_socket_map_ring(nl) < 0) {
		perror("mnl_socket_map_ring");
		exit(EXIT_FAILURE);
	}
	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	if (mnl_socket_setsockopt(nl, NETLINK_ADD_MEMBERSHIP, &group,
				  sizeof(int)) < 0) {
		perror("mnl_socket_setsockopt");
		exit(EXIT_FAILURE);
	}

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
				perror("mnl_ring_poll");
				exit(EXIT_FAILURE);
			}
			continue;
		}

		ret = mnl_cb_run(ptr, len, 0, 0, data_cb, NULL);
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

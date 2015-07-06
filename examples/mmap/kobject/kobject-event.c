/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/mman.h>

#include <libmnl/libmnl.h>
#include <linux/netlink.h>

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
	char *ptr;
	struct mnl_ring *rxring;
	struct nl_mmap_hdr *frame;

	nl = mnl_socket_open(NETLINK_KOBJECT_UEVENT);
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
	if (mnl_socket_map_ring(nl, MAP_SHARED) < 0) {
		perror("mnl_socket_map_ring");
		exit(EXIT_FAILURE);
	}
	rxring = mnl_socket_get_ring(nl, MNL_RING_RX);

	/* There is one single group in kobject over netlink */
	if (mnl_socket_bind(nl, (1<<0), MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	ret = MNL_CB_OK;
	while (ret > 0) {
		int i;

		frame = mnl_ring_get_frame(rxring);
		if (frame->nm_status == NL_MMAP_STATUS_VALID) {
			if (frame->nm_len == 0)
				goto release;
			ret = frame->nm_len;
			ptr = MNL_FRAME_PAYLOAD(frame);
		} else if (frame->nm_status == NL_MMAP_STATUS_COPY) {
			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (ret < 0) {
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

		/* kobject uses a string based protocol, with no initial
		 * netlink header.
		 */
		for (i = 0; i < ret; i++)
			printf("%c", *(ptr + i));
	release:
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(rxring);
	}

	mnl_socket_close(nl);

	return 0;
}

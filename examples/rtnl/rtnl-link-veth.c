/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *nla1, *nla2, *nla3;
	struct ifinfomsg *ifm;
	int ret;
	unsigned int seq, portid;

	if (argc != 4) {
		printf("Usage: %s [ifname] [peer name] [add|del]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nlh = mnl_nlmsg_put_header(buf);
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	if (strncasecmp(argv[3], "add", strlen("add")) == 0) {
		nlh->nlmsg_type	= RTM_NEWLINK;
		ifm->ifi_change = IFF_UP;
		ifm->ifi_flags = IFF_UP;
	} else if (strncasecmp(argv[3], "del", strlen("del")) == 0) {
		nlh->nlmsg_type	= RTM_DELLINK;
	} else {
		fprintf(stderr, "%s is not `add' nor `del'\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);
	mnl_attr_put_str(nlh, IFLA_IFNAME, argv[1]);
	nla1 = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	mnl_attr_put_str(nlh, IFLA_INFO_KIND, "veth");
	nla2 = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	nla3 = mnl_attr_nest_start(nlh, VETH_INFO_PEER);
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	mnl_attr_put_str(nlh, IFLA_IFNAME, argv[2]);
	mnl_attr_nest_end(nlh, nla3);
	mnl_attr_nest_end(nlh, nla2);
	mnl_attr_nest_end(nlh, nla1);

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1){
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}

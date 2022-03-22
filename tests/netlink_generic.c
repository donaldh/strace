/*
 * Copyright (c) 2017-2021 The strace developers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This test case is based on netlink_selinux.c */

#include "tests.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "netlink.h"
#include <linux/genetlink.h>
#include "test_netlink.h"

struct req {
	const struct nlmsghdr nlh;
	struct genlmsghdr gnlh;
};

struct reqnla {
	struct req req;
	struct attr {
		struct nlattr nla;
		__u32 value;
	} attr;
};

static void
test_nlmsg_type(const int fd)
{
	/*
	 * Though GENL_ID_CTRL number is statically fixed in this test case,
	 * strace does not have a builtin knowledge that the corresponding
	 * string is "nlctrl".
	 */
	long rc;
	struct req req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = GENL_ID_CTRL,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.gnlh = {
			.cmd = CTRL_CMD_GETFAMILY
		}
	};

	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_GETFAMILY, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));
}

static void
test_sendmsg_nlmsg_type(const int fd)
{
	long rc;
	struct req req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = GENL_ID_CTRL,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.gnlh = {
			.cmd = CTRL_CMD_GETFAMILY
		}
	};

        struct iovec iov[1] = {
		{ .iov_base = &req, .iov_len = sizeof(req) }
        };
        struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = 1
        };

        rc = sendmsg(fd, &msg, MSG_DONTWAIT);
        printf("sendmsg(%d, {msg_name=NULL, msg_namelen=0"
	       ", msg_iov=[{iov_base=[{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_GETFAMILY, version=0}], iov_len=%u}], msg_iovlen=1"
	       ", msg_controllen=0, msg_flags=0}, MSG_DONTWAIT) = %s\n",
	       fd, req.nlh.nlmsg_len, (unsigned int) iov[0].iov_len,
	       sprintrc(rc));
}

static void
test_missing_type(const int fd)
{
	long rc;
	struct req req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = UINT16_MAX,
			.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
		},
		.gnlh = {
			.cmd = CTRL_CMD_GETFAMILY,
			.version = 1
		}
	};

	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=0xffff /* GENERIC_FAMILY_??? */"
	       ", nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=0x3 /* ??? */, version=1}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	struct reqnla reqnla = {
		.req = {
			.nlh = {
				.nlmsg_len = sizeof(reqnla),
				.nlmsg_type = UINT16_MAX,
				.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST
			},
			.gnlh = {
				.cmd = CTRL_CMD_GETFAMILY,
				.version = 1
			}
		},
		.attr = {
			.nla = {
				.nla_type = CTRL_ATTR_OP,
				.nla_len = sizeof(reqnla.attr),
			},
			.value = 0
		}
	};

	rc = sendto(fd, &reqnla, sizeof(reqnla), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=0xffff /* GENERIC_FAMILY_??? */"
	       ", nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=0x3 /* ??? */, version=1"
	       ", data=\"\\x08\\x00\\x0a\\x00\\x00\\x00\\x00\\x00\"}]"
	       ", %u, MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, (unsigned int) sizeof(reqnla),
	       (unsigned int) sizeof(reqnla), sprintrc(rc));
}

static void
test_genlmsg_cmds(const int fd)
{
	long rc;
	struct req req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = GENL_ID_CTRL,
			.nlmsg_flags = NLM_F_REQUEST
		}
	};

	req.gnlh.cmd = CTRL_CMD_GETFAMILY;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_GETFAMILY, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = CTRL_CMD_NEWFAMILY;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_NEWFAMILY, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = CTRL_CMD_DELFAMILY;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_DELFAMILY, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = CTRL_CMD_GETPOLICY;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_GETPOLICY, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = __CTRL_CMD_MAX;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=0xb /* CTRL_CMD_??? */, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = CTRL_CMD_UNSPEC;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_UNSPEC, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));

	req.gnlh.cmd = CTRL_CMD_UNSPEC;
	rc = sendto(fd, &req, sizeof(req), MSG_DONTWAIT, NULL, 0);
	printf("sendto(%d, [{nlmsg_len=%u, nlmsg_type=nlctrl"
	       ", nlmsg_flags=NLM_F_REQUEST, nlmsg_seq=0, nlmsg_pid=0}"
	       ", {cmd=CTRL_CMD_UNSPEC, version=0}], %u"
	       ", MSG_DONTWAIT, NULL, 0) = %s\n",
	       fd, req.nlh.nlmsg_len,
	       (unsigned int) sizeof(req), sprintrc(rc));
}

static void
test_nlctrl_msg(const int fd)
{
	struct genlmsghdr genl = {
		.cmd = CTRL_CMD_GETFAMILY,
		.version = 1
	};

	const char family[] = "nlctrl";

	struct nlattr nla = {
		.nla_type = CTRL_ATTR_FAMILY_NAME,
		.nla_len = sizeof(nla) + sizeof(family)
	};

	char buf[NLMSG_ALIGN(sizeof(genl) + nla.nla_len)];
	memcpy(buf, &genl, sizeof(genl));
	size_t offset = NLMSG_ALIGN(sizeof(genl));
	memcpy(buf + offset, &nla, sizeof(nla));
	offset += sizeof(nla);
	memcpy(buf + offset, &family, sizeof(family));

	void *const nlh0 = midtail_alloc(NLMSG_HDRLEN, sizeof(buf));

        TEST_NETLINK_(fd, nlh0, GENL_ID_CTRL, "nlctrl", NLM_F_REQUEST,
                      "NLM_F_REQUEST", sizeof(buf), &buf, sizeof(buf),
                      printf("{cmd=CTRL_CMD_GETFAMILY"), printf(", version=1"),
                      printf(", [{nla_len=11, nla_type=CTRL_ATTR_FAMILY_NAME}"),
                      printf(", \"nlctrl\"]}"));
}

int main(void)
{
	skip_if_unavailable("/proc/self/fd/");

	int fd = create_nl_socket(NETLINK_GENERIC);

	test_nlmsg_type(fd);
	test_sendmsg_nlmsg_type(fd);
	test_missing_type(fd);
	test_genlmsg_cmds(fd);
	test_nlctrl_msg(fd);

	printf("+++ exited with 0 +++\n");

	return 0;
}

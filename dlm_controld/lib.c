/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <linux/dlmconstants.h>
#include "dlm_controld.h"
#include "libdlmcontrol.h"

static int do_read(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return 0;
}

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

static int do_connect(const char *sock_path)
{
	struct sockaddr_un sun;
	socklen_t addrlen;
	int rv, fd;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto out;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(&sun.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(sun.sun_path+1) + 1;

	rv = connect(fd, (struct sockaddr *) &sun, addrlen);
	if (rv < 0) {
		close(fd);
		fd = rv;
	}
 out:
	return fd;
}

static void init_header(struct dlmc_header *h, int cmd, char *name,
			int extra_len)
{
	memset(h, 0, sizeof(struct dlmc_header));

	h->magic = DLMC_MAGIC;
	h->version = DLMC_VERSION;
	h->len = sizeof(struct dlmc_header) + extra_len;
	h->command = cmd;

	if (name)
		strncpy(h->name, name, DLM_LOCKSPACE_LEN);
}

static char copy_buf[DLMC_DUMP_SIZE];

static int do_dump(int cmd, char *name, char *buf)
{
	struct dlmc_header h;
	int fd, rv, len;

	memset(copy_buf, 0, DLMC_DUMP_SIZE);

	init_header(&h, cmd, name, 0);

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	memset(&h, 0, sizeof(h));

	rv = do_read(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	len = h.len - sizeof(h);

	if (len <= 0 || len > DLMC_DUMP_SIZE)
		goto out_close;

	rv = do_read(fd, copy_buf, len);
	if (rv < 0)
		goto out_close;

	memcpy(buf, copy_buf, len);
 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_dump_debug(char *buf)
{
	return do_dump(DLMC_CMD_DUMP_DEBUG, NULL, buf);
}

int dlmc_dump_config(char *buf)
{
	return do_dump(DLMC_CMD_DUMP_CONFIG, NULL, buf);
}

int dlmc_dump_log_plock(char *buf)
{
	return do_dump(DLMC_CMD_DUMP_LOG_PLOCK, NULL, buf);
}

int dlmc_dump_plocks(char *name, char *buf)
{
	return do_dump(DLMC_CMD_DUMP_PLOCKS, name, buf);
}

static int nodeid_compare(const void *va, const void *vb)
{
	const int *a = va;
	const int *b = vb;

	return *a - *b;
}

static void print_str(char *str, int len)
{
	char *p;
	int i;

	p = &str[0];
	for (i = 0; i < len-1; i++) {
		if (str[i] == ' ') {
			str[i] = '\0';
			printf("    %s\n", p);
			p = &str[i+1];
		}
	}

	if (p)
		printf("    %s\n", p);
}

static unsigned int kv(char *str, const char *k)
{
	char valstr[64];
	char *p;
	int i;

	p = strstr(str, k);
	if (!p)
		return 0;

	p = strstr(p, "=") + 1;
	if (!p)
		return 0;

	memset(valstr, 0, 64);

	for (i = 0; i < 64; i++) {
		if (*p == ' ')
			break;
		if (*p == '\0')
			break;
		if (*p == '\n')
			break;
		valstr[i] = *p;
		p++;
	}

	return (unsigned int)strtoul(valstr, NULL, 0);
}

static char *ks(char *str, const char *k)
{
	static char valstr[64];
	char *p;
	int i;

	p = strstr(str, k);
	if (!p)
		return 0;

	p = strstr(p, "=") + 1;
	if (!p)
		return 0;

	memset(valstr, 0, 64);

	for (i = 0; i < 64; i++) {
		if (*p == ' ')
			break;
		if (*p == '\0')
			break;
		if (*p == '\n')
			break;
		valstr[i] = *p;
		p++;
	}

	return valstr;
}

static void print_daemon(struct dlmc_state *st, char *str, char *bin, uint32_t flags)
{
	unsigned int cluster_ringid, daemon_ringid;
	unsigned int fipu;

	if (flags & DLMC_STATUS_VERBOSE) {
		printf("our_nodeid %d\n", st->nodeid);
		print_str(str, st->str_len);
		return;
	}

	cluster_ringid = kv(str, "cluster_ringid");
	daemon_ringid = kv(str, "daemon_ringid");

	printf("cluster nodeid %d quorate %u ring seq %u %u\n",
		st->nodeid,
		kv(str, "quorate"),
		cluster_ringid, daemon_ringid);

	fipu = kv(str, "fence_in_progress_unknown");

	printf("daemon now %u fence_pid %u %s\n",
		kv(str, "monotime"),
		kv(str, "fence_pid"),
		fipu ? "fence_init" : "");
}

static void format_daemon_node(struct dlmc_state *st, char *str, char *bin, uint32_t flags,
			       char *node_line, char *fence_line)
{
	unsigned int delay_fencing, result_wait, killed;
	char letter;

	if (st->type == DLMC_STATE_STARTUP_NODE)
		letter = 'U';
	else if (kv(str, "member"))
		letter = 'M';
	else
		letter = 'X';
	

	snprintf(node_line, DLMC_STATE_MAXSTR - 1,
		"node %d %c add %u rem %u fail %u fence %u at %u %u\n",
		st->nodeid,
		letter,
		kv(str, "add_time"),
		kv(str, "rem_time"),
		kv(str, "fail_monotime"),
		kv(str, "fence_monotime"),
		kv(str, "actor_done"),
		kv(str, "fence_walltime"));

	if (!kv(str, "need_fencing"))
		return;

	delay_fencing = kv(str, "delay_fencing");
	result_wait = kv(str, "fence_result_wait");
	killed = kv(str, "killed");

	if (delay_fencing)
		snprintf(fence_line, DLMC_STATE_MAXSTR - 1,
			"fence %d %s delay actor %u fail %u fence %u now %u%s%s\n",
			st->nodeid,
			ks(str, "left_reason"),
			kv(str, "actor_last"),
			kv(str, "fail_walltime"),
			kv(str, "fence_walltime"),
			(unsigned int)time(NULL),
			result_wait ? " result_wait" : "",
			killed ? " killed" : "");
	else
		snprintf(fence_line, DLMC_STATE_MAXSTR - 1,
			"fence %d %s pid %d actor %u fail %u fence %u now %u%s%s\n",
			st->nodeid,
			ks(str, "left_reason"),
			kv(str, "fence_pid"),
			kv(str, "actor_last"),
			kv(str, "fail_walltime"),
			kv(str, "fence_walltime"),
			(unsigned int)time(NULL),
			result_wait ? " result_wait" : "",
			killed ? " killed" : "");
}

#define MAX_SORT 64

int dlmc_print_status(uint32_t flags)
{
	struct dlmc_header h;
	struct dlmc_state state;
	struct dlmc_state *st;
	char maxstr[DLMC_STATE_MAXSTR];
	char maxbin[DLMC_STATE_MAXBIN];
	char *str;
	char *bin;
	int all_count, node_count, fence_count, startup_count;
	int all_ids[MAX_SORT];
	int node_ids[MAX_SORT];
	int fence_ids[MAX_SORT];
	int startup_ids[MAX_SORT];
	char *node_lines[MAX_SORT];
	char *fence_lines[MAX_SORT];
	char *node_line;
	char *fence_line;
	int found_node;
	int fd, rv;
	int i, j;

	init_header(&h, DLMC_CMD_DUMP_STATUS, NULL, 0);

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		printf("cannot connect to dlm_controld\n");
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0) {
		printf("cannot send to dlm_controld\n");
		goto out_close;
	}

	st = &state;
	str = maxstr;
	bin = maxbin;

	all_count = 0;
	node_count = 0;
	fence_count = 0;
	startup_count = 0;
	memset(&all_ids, 0, sizeof(all_ids));
	memset(&node_ids, 0, sizeof(node_ids));
	memset(&fence_ids, 0, sizeof(fence_ids));
	memset(&startup_ids, 0, sizeof(startup_ids));
	memset(node_lines, 0, sizeof(node_lines));
	memset(fence_lines, 0, sizeof(fence_lines));

	while (1) {
		memset(&state, 0, sizeof(state));
		memset(maxstr, 0, sizeof(maxstr));
		memset(maxbin, 0, sizeof(maxbin));

		rv = recv(fd, st, sizeof(struct dlmc_state), MSG_WAITALL);
		if (!rv)
			break;
		if (rv != sizeof(struct dlmc_state))
			break;

		if (st->str_len) {
			rv = recv(fd, str, st->str_len, MSG_WAITALL);
			if (rv != st->str_len)
				break;
		}

		if (st->bin_len) {
			rv = recv(fd, bin, st->bin_len, MSG_WAITALL);
			if (rv != st->bin_len)
				break;
		}

		switch (st->type) {
		case DLMC_STATE_DAEMON:
			print_daemon(st, str, bin, flags);
			break;

		case DLMC_STATE_STARTUP_NODE:
			startup_ids[startup_count++] = st->nodeid;
			break;

		case DLMC_STATE_DAEMON_NODE:
			if (flags & DLMC_STATUS_VERBOSE) {
				printf("nodeid %d\n", st->nodeid);
				print_str(str, st->str_len);
			} else {
				node_line = malloc(DLMC_STATE_MAXSTR);
				if (!node_line)
					break;
				fence_line = malloc(DLMC_STATE_MAXSTR);
				if (!fence_line) {
					free(node_line);
					break;
				}
				memset(node_line, 0, DLMC_STATE_MAXSTR);
				memset(fence_line, 0, DLMC_STATE_MAXSTR);

				format_daemon_node(st, str, bin, flags,
						   node_line, fence_line);

				all_ids[all_count++] = st->nodeid;

				node_ids[node_count] = st->nodeid;
				node_lines[node_count] = node_line;
				node_count++;

				if (!fence_line[0]) {
					free(fence_line);
				} else {
					fence_ids[fence_count] = st->nodeid;
					fence_lines[fence_count] = fence_line;
					fence_count++;
				}
			}
			break;

		default:
			break;
		}

		if (rv < 0)
			break;
	}

	if (all_count)
		qsort(all_ids, all_count, sizeof(int), nodeid_compare);

	/* don't free any node_lines in this startup loop because we are just
	   borrowing them; they are needed in the real node loop below. */

	if (startup_count) {
		for (i = 0; i < startup_count; i++) {
			found_node = 0;
			for (j = 0; j < node_count; j++) {
				if (startup_ids[i] != node_ids[j])
					continue;
				found_node = 1;
				if (!node_lines[j])
					printf("startup node %d\n", st->nodeid);
				else
					printf("startup %s", node_lines[j]);
				break;
			}
			if (!found_node)
				printf("startup node %d\n", st->nodeid);
		}
	}

	if (all_count && fence_count) {
		for (i = 0; i < all_count; i++) {
			for (j = 0; j < fence_count; j++) {
				if (all_ids[i] != fence_ids[j])
					continue;
				if (!fence_lines[j]) {
					printf("fence %d no data\n", fence_ids[j]);
				} else {
					printf("%s", fence_lines[j]);
					free(fence_lines[j]);
					fence_lines[j] = NULL;
				}
				break;
			}
		}
	}

	if (all_count && node_count) {
		for (i = 0; i < all_count; i++) {
			for (j = 0; j < node_count; j++) {
				if (all_ids[i] != node_ids[j])
					continue;
				if (!node_lines[j]) {
					printf("node %d no data\n", node_ids[j]);
				} else {
					printf("%s", node_lines[j]);
					free(node_lines[j]);
					node_lines[j] = NULL;
				}
				break;
			}
		}
	}

 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_node_info(char *name, int nodeid, struct dlmc_node *node)
{
	struct dlmc_header h, *rh;
	char reply[sizeof(struct dlmc_header) + sizeof(struct dlmc_node)];
	int fd, rv;

	init_header(&h, DLMC_CMD_NODE_INFO, name, 0);
	h.data = nodeid;

	memset(reply, 0, sizeof(reply));

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	rv = do_read(fd, reply, sizeof(reply));
	if (rv < 0)
		goto out_close;

	rh = (struct dlmc_header *)reply;
	rv = rh->data;
	if (rv < 0)
		goto out_close;

	memcpy(node, (char *)reply + sizeof(struct dlmc_header),
	       sizeof(struct dlmc_node));
 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_lockspace_info(char *name, struct dlmc_lockspace *lockspace)
{
	struct dlmc_header h, *rh;
	char reply[sizeof(struct dlmc_header) + sizeof(struct dlmc_lockspace)];
	int fd, rv;

	init_header(&h, DLMC_CMD_LOCKSPACE_INFO, name, 0);

	memset(reply, 0, sizeof(reply));

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	rv = do_read(fd, reply, sizeof(reply));
	if (rv < 0)
		goto out_close;

	rh = (struct dlmc_header *)reply;
	rv = rh->data;
	if (rv < 0)
		goto out_close;

	memcpy(lockspace, (char *)reply + sizeof(struct dlmc_header),
	       sizeof(struct dlmc_lockspace));
 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_lockspaces(int max, int *count, struct dlmc_lockspace *lss)
{
	struct dlmc_header h, *rh;
	char *reply;
	int reply_len;
	int fd, rv, result, ls_count;

	init_header(&h, DLMC_CMD_LOCKSPACES, NULL, 0);
	h.data = max;

	reply_len = sizeof(struct dlmc_header) +
		    (max * sizeof(struct dlmc_lockspace));
	reply = malloc(reply_len);
	if (!reply) {
		rv = -1;
		goto out;
	}
	memset(reply, 0, reply_len);

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	/* won't usually get back the full reply_len */
	do_read(fd, reply, reply_len);

	rh = (struct dlmc_header *)reply;
	result = rh->data;
	if (result < 0 && result != -E2BIG) {
		rv = result;
		goto out_close;
	}

	if (result == -E2BIG) {
		*count = -E2BIG;
		ls_count = max;
	} else {
		*count = result;
		ls_count = result;
	}
	rv = 0;

	memcpy(lss, (char *)reply + sizeof(struct dlmc_header),
	       ls_count * sizeof(struct dlmc_lockspace));
 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_lockspace_nodes(char *name, int type, int max, int *count,
			 struct dlmc_node *nodes)
{
	struct dlmc_header h, *rh;
	char *reply;
	int reply_len;
	int fd, rv, result, node_count;

	init_header(&h, DLMC_CMD_LOCKSPACE_NODES, name, 0);
	h.option = type;
	h.data = max;

	reply_len = sizeof(struct dlmc_header) +
		    (max * sizeof(struct dlmc_node));
	reply = malloc(reply_len);
	if (!reply) {
		rv = -1;
		goto out;
	}
	memset(reply, 0, reply_len);

	fd = do_connect(DLMC_QUERY_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	/* won't usually get back the full reply_len */
	do_read(fd, reply, reply_len);

	rh = (struct dlmc_header *)reply;
	result = rh->data;
	if (result < 0 && result != -E2BIG) {
		rv = result;
		goto out_close;
	}

	if (result == -E2BIG) {
		*count = -E2BIG;
		node_count = max;
	} else {
		*count = result;
		node_count = result;
	}
	rv = 0;

	memcpy(nodes, (char *)reply + sizeof(struct dlmc_header),
	       node_count * sizeof(struct dlmc_node));
 out_close:
	close(fd);
 out:
	return rv;
}

int dlmc_fs_connect(void)
{
	return do_connect(DLMC_SOCK_PATH);
}

void dlmc_fs_disconnect(int fd)
{
	close(fd);
}

int dlmc_fs_register(int fd, char *name)
{
	struct dlmc_header h;

	init_header(&h, DLMC_CMD_FS_REGISTER, name, 0);

	return do_write(fd, &h, sizeof(h));
}

int dlmc_fs_unregister(int fd, char *name)
{
	struct dlmc_header h;

	init_header(&h, DLMC_CMD_FS_UNREGISTER, name, 0);

	return do_write(fd, &h, sizeof(h));
}

int dlmc_fs_notified(int fd, char *name, int nodeid)
{
	struct dlmc_header h;

	init_header(&h, DLMC_CMD_FS_NOTIFIED, name, 0);
	h.data = nodeid;

	return do_write(fd, &h, sizeof(h));
}

int dlmc_fs_result(int fd, char *name, int *type, int *nodeid, int *result)
{
	struct dlmc_header h;
	int rv;

	rv = do_read(fd, &h, sizeof(h));
	if (rv < 0)
		goto out;

	strncpy(name, h.name, DLM_LOCKSPACE_LEN);
	*nodeid = h.option;
	*result = h.data;

	switch (h.command) {
	case DLMC_CMD_FS_REGISTER:
		*type = DLMC_RESULT_REGISTER;
		break;
	case DLMC_CMD_FS_NOTIFIED:
		*type = DLMC_RESULT_NOTIFIED;
		break;
	default:
		*type = 0;
	}
 out:
	return rv;
}

int dlmc_deadlock_check(char *name)
{
	struct dlmc_header h;
	int fd, rv;

	init_header(&h, DLMC_CMD_DEADLOCK_CHECK, name, 0);

	fd = do_connect(DLMC_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	close(fd);
 out:
	return rv;
}

int dlmc_fence_ack(char *name)
{
	struct dlmc_header h;
	int fd, rv;

	init_header(&h, DLMC_CMD_FENCE_ACK, name, 0);

	fd = do_connect(DLMC_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	close(fd);
 out:
	return rv;
}


/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#define EXTERN
#include "dlm_daemon.h"
#include <ctype.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/dlm_netlink.h>

#ifdef USE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif

#include "copyright.cf"
#include "version.cf"

#define CLIENT_NALLOC	32
static int client_maxi;
static int client_size = 0;
static struct client *client = NULL;
static struct pollfd *pollfd = NULL;
static pthread_t query_thread;
static pthread_mutex_t query_mutex;
static struct list_head fs_register_list;
static int kernel_monitor_fd;

struct client {
	int fd;
	void *workfn;
	void *deadfn;
	struct lockspace *ls;
};

int do_read(int fd, void *buf, size_t count)
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

int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		log_error("write errno %d", errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

uint64_t monotime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static void client_alloc(void)
{
	int i;

	if (!client) {
		client = malloc(CLIENT_NALLOC * sizeof(struct client));
		pollfd = malloc(CLIENT_NALLOC * sizeof(struct pollfd));
	} else {
		client = realloc(client, (client_size + CLIENT_NALLOC) *
					 sizeof(struct client));
		pollfd = realloc(pollfd, (client_size + CLIENT_NALLOC) *
					 sizeof(struct pollfd));
		if (!pollfd)
			log_error("can't alloc for pollfd");
	}
	if (!client || !pollfd)
		log_error("can't alloc for client array");

	for (i = client_size; i < client_size + CLIENT_NALLOC; i++) {
		client[i].workfn = NULL;
		client[i].deadfn = NULL;
		client[i].fd = -1;
		pollfd[i].fd = -1;
		pollfd[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

void client_dead(int ci)
{
	close(client[ci].fd);
	client[ci].workfn = NULL;
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
}

int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	int i;

	if (!client)
		client_alloc();
 again:
	for (i = 0; i < client_size; i++) {
		if (client[i].fd == -1) {
			client[i].workfn = workfn;
			if (deadfn)
				client[i].deadfn = deadfn;
			else
				client[i].deadfn = client_dead;
			client[i].fd = fd;
			pollfd[i].fd = fd;
			pollfd[i].events = POLLIN;
			if (i > client_maxi)
				client_maxi = i;
			return i;
		}
	}

	client_alloc();
	goto again;
}

int client_fd(int ci)
{
	return client[ci].fd;
}

void client_ignore(int ci, int fd)
{
	pollfd[ci].fd = -1;
	pollfd[ci].events = 0;
}

void client_back(int ci, int fd)
{
	pollfd[ci].fd = fd;
	pollfd[ci].events = POLLIN;
}

static void sigterm_handler(int sig)
{
	daemon_quit = 1;
}

static void sigchld_handler(int sig)
{
}

static struct lockspace *create_ls(char *name)
{
	struct lockspace *ls;

	ls = malloc(sizeof(*ls));
	if (!ls)
		goto out;
	memset(ls, 0, sizeof(struct lockspace));
	strncpy(ls->name, name, DLM_LOCKSPACE_LEN);

	INIT_LIST_HEAD(&ls->changes);
	INIT_LIST_HEAD(&ls->node_history);
	INIT_LIST_HEAD(&ls->saved_messages);
	INIT_LIST_HEAD(&ls->plock_resources);
	ls->plock_resources_root = RB_ROOT;
#if 0
	INIT_LIST_HEAD(&ls->deadlk_nodes);
	INIT_LIST_HEAD(&ls->transactions);
	INIT_LIST_HEAD(&ls->resources);
#endif
	setup_lockspace_config(ls);
 out:
	return ls;
}

struct lockspace *find_ls(char *name)
{
	struct lockspace *ls;

	list_for_each_entry(ls, &lockspaces, list) {
		if ((strlen(ls->name) == strlen(name)) &&
		    !strncmp(ls->name, name, strlen(name)))
			return ls;
	}
	return NULL;
}

struct lockspace *find_ls_id(uint32_t id)
{
	struct lockspace *ls;

	list_for_each_entry(ls, &lockspaces, list) {
		if (ls->global_id == id)
			return ls;
	}
	return NULL;
}

struct fs_reg {
	struct list_head list;
	char name[DLM_LOCKSPACE_LEN+1];
};

static int fs_register_check(char *name)
{
	struct fs_reg *fs;
	list_for_each_entry(fs, &fs_register_list, list) {
		if (!strcmp(name, fs->name))
			return 1;
	}
	return 0;
}

static int fs_register_add(char *name)
{
	struct fs_reg *fs;

	if (fs_register_check(name))
		return -EALREADY;

	fs = malloc(sizeof(struct fs_reg));
	if (!fs)
		return -ENOMEM;
	strncpy(fs->name, name, DLM_LOCKSPACE_LEN);
	list_add(&fs->list, &fs_register_list);
	return 0;
}

static void fs_register_del(char *name)
{
	struct fs_reg *fs;
	list_for_each_entry(fs, &fs_register_list, list) {
		if (!strcmp(name, fs->name)) {
			list_del(&fs->list);
			free(fs);
			return;
		}
	}
}

#define MAXARGS 8

static char *get_args(char *buf, int *argc, char **argv, char sep, int want)
{
	char *p = buf, *rp = NULL;
	int i;

	argv[0] = p;

	for (i = 1; i < MAXARGS; i++) {
		p = strchr(buf, sep);
		if (!p)
			break;
		*p = '\0';

		if (want == i) {
			rp = p + 1;
			break;
		}

		argv[i] = p + 1;
		buf = p + 1;
	}
	*argc = i;

	/* we ended by hitting \0, return the point following that */
	if (!rp)
		rp = strchr(buf, '\0') + 1;

	return rp;
}

const char *dlm_mode_str(int mode)
{
	switch (mode) {
	case DLM_LOCK_IV:
		return "IV";
	case DLM_LOCK_NL:
		return "NL";
	case DLM_LOCK_CR:
		return "CR";
	case DLM_LOCK_CW:
		return "CW";
	case DLM_LOCK_PR:
		return "PR";
	case DLM_LOCK_PW:
		return "PW";
	case DLM_LOCK_EX:
		return "EX";
	}
	return "??";
}

/* recv "online" (join) and "offline" (leave) messages from dlm via uevents */

#define MAX_LINE_UEVENT 256

static void process_uevent(int ci)
{
	struct lockspace *ls;
	char buf[MAX_LINE_UEVENT];
	char *argv[MAXARGS], *act, *sys;
	int rv, argc = 0;

	memset(buf, 0, sizeof(buf));
	memset(argv, 0, sizeof(char *) * MAXARGS);

 retry_recv:
	rv = recv(client[ci].fd, &buf, sizeof(buf), 0);
	if (rv < 0) {
		if (errno == EINTR)
			goto retry_recv;
		if (errno != EAGAIN)
			log_error("uevent recv error %d errno %d", rv, errno);
		return;
	}

	if (!strstr(buf, "dlm"))
		return;

	log_debug("uevent: %s", buf);

	get_args(buf, &argc, argv, '/', 4);
	if (argc != 4)
		log_error("uevent message has %d args", argc);
	act = argv[0];
	sys = argv[2];

	if ((strlen(sys) != strlen("dlm")) || strcmp(sys, "dlm"))
		return;

	log_debug("kernel: %s %s", act, argv[3]);

	rv = 0;

	if (!strcmp(act, "online@")) {
		ls = find_ls(argv[3]);
		if (ls) {
			rv = -EEXIST;
			goto out;
		}

		ls = create_ls(argv[3]);
		if (!ls) {
			rv = -ENOMEM;
			goto out;
		}

		if (fs_register_check(ls->name))
			ls->fs_registered = 1;

		rv = dlm_join_lockspace(ls);
		if (rv) {
			/* ls already freed */
			goto out;
		}

	} else if (!strcmp(act, "offline@")) {
		ls = find_ls(argv[3]);
		if (!ls) {
			rv = -ENOENT;
			goto out;
		}

		dlm_leave_lockspace(ls);
	}
 out:
	if (rv < 0)
		log_error("process_uevent %s error %d errno %d",
			  act, rv, errno);
}

static int setup_uevent(void)
{
	struct sockaddr_nl snl;
	int s, rv;

	s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (s < 0) {
		log_error("uevent netlink socket");
		return s;
	}

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	rv = bind(s, (struct sockaddr *) &snl, sizeof(snl));
	if (rv < 0) {
		log_error("uevent bind error %d errno %d", rv, errno);
		close(s);
		return rv;
	}

	return s;
}

static void init_header(struct dlmc_header *h, int cmd, char *name, int result,
			int extra_len)
{
	memset(h, 0, sizeof(struct dlmc_header));

	h->magic = DLMC_MAGIC;
	h->version = DLMC_VERSION;
	h->len = sizeof(struct dlmc_header) + extra_len;
	h->command = cmd;
	h->data = result;

	if (name)
		strncpy(h->name, name, DLM_LOCKSPACE_LEN);
}

static char copy_buf[LOG_DUMP_SIZE];

static void query_dump_debug(int fd)
{
	struct dlmc_header h;
	int len = 0;

	copy_log_dump(copy_buf, &len);

	init_header(&h, DLMC_CMD_DUMP_DEBUG, NULL, 0, len);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (len)
		send(fd, copy_buf, len, MSG_NOSIGNAL);
}

static void copy_options(char *buf, int *len)
{
	struct dlm_option *o;
	char tmp[256];
	int i, ret, pos = 0;

	for (i = 0; i < dlm_options_max; i++) {
		o = &dlm_options[i];

		memset(tmp, 0, sizeof(tmp));

		if (o->req_arg == req_arg_str)
			snprintf(tmp, 255, "%s=%s\n", o->name, o->use_str);
		else
			snprintf(tmp, 255, "%s=%d\n", o->name, o->use_int);

		if (pos + strlen(tmp) >= LOG_DUMP_SIZE)
			break;

		ret = sprintf(buf + pos, "%s", tmp);
		pos += ret;
	}

	*len = pos;
}

static void query_dump_config(int fd)
{
	struct dlmc_header h;
	int len = 0;

	copy_options(copy_buf, &len);

	init_header(&h, DLMC_CMD_DUMP_CONFIG, NULL, 0, len);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (len)
		send(fd, copy_buf, len, MSG_NOSIGNAL);
}

static void query_dump_log_plock(int fd)
{
	struct dlmc_header h;
	int len = 0;

	copy_log_dump_plock(copy_buf, &len);

	init_header(&h, DLMC_CMD_DUMP_DEBUG, NULL, 0, len);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (len)
		send(fd, copy_buf, len, MSG_NOSIGNAL);
}

static void query_dump_plocks(int fd, char *name)
{
	struct lockspace *ls;
	struct dlmc_header h;
	int len = 0;
	int rv;

	ls = find_ls(name);
	if (!ls) {
		rv = -ENOENT;
		goto out;
	}

	rv = copy_plock_state(ls, copy_buf, &len);
 out:
	init_header(&h, DLMC_CMD_DUMP_PLOCKS, name, rv, len);
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);

	if (len)
		send(fd, copy_buf, len, MSG_NOSIGNAL);
}

/* combines a header and the data and sends it back to the client in
   a single do_write() call */

static void do_reply(int fd, int cmd, char *name, int result, int option,
		     char *buf, int buflen)
{
	struct dlmc_header *h;
	char *reply;
	int reply_len;

	reply_len = sizeof(struct dlmc_header) + buflen;
	reply = malloc(reply_len);
	if (!reply)
		return;
	memset(reply, 0, reply_len);
	h = (struct dlmc_header *)reply;

	init_header(h, cmd, name, result, buflen);
	h->option = option;

	if (buf && buflen)
		memcpy(reply + sizeof(struct dlmc_header), buf, buflen);

	do_write(fd, reply, reply_len);

	free(reply);
}

static void query_lockspace_info(int fd, char *name)
{
	struct lockspace *ls;
	struct dlmc_lockspace lockspace;
	int rv;

	ls = find_ls(name);
	if (!ls) {
		rv = -ENOENT;
		goto out;
	}

	memset(&lockspace, 0, sizeof(lockspace));

	rv = set_lockspace_info(ls, &lockspace);
 out:
	do_reply(fd, DLMC_CMD_LOCKSPACE_INFO, name, rv, 0,
		 (char *)&lockspace, sizeof(lockspace));
}

static void query_node_info(int fd, char *name, int nodeid)
{
	struct lockspace *ls;
	struct dlmc_node node;
	int rv;

	ls = find_ls(name);
	if (!ls) {
		rv = -ENOENT;
		goto out;
	}

	memset(&node, 0, sizeof(node));

	rv = set_node_info(ls, nodeid, &node);
 out:
	do_reply(fd, DLMC_CMD_NODE_INFO, name, rv, 0,
		 (char *)&node, sizeof(node));
}

static void query_lockspaces(int fd, int max)
{
	int ls_count = 0;
	struct dlmc_lockspace *lss = NULL;
	int rv, result;

	rv = set_lockspaces(&ls_count, &lss);
	if (rv < 0) {
		result = rv;
		ls_count = 0;
		goto out;
	}

	if (ls_count > max) {
		result = -E2BIG;
		ls_count = max;
	} else {
		result = ls_count;
	}
 out:
	do_reply(fd, DLMC_CMD_LOCKSPACES, NULL, result, 0,
		 (char *)lss, ls_count * sizeof(struct dlmc_lockspace));

	if (lss)
		free(lss);
}

static void query_lockspace_nodes(int fd, char *name, int option, int max)
{
	struct lockspace *ls;
	int node_count = 0;
	struct dlmc_node *nodes = NULL;
	int rv, result;

	ls = find_ls(name);
	if (!ls) {
		result = -ENOENT;
		node_count = 0;
		goto out;
	}

	rv = set_lockspace_nodes(ls, option, &node_count, &nodes);
	if (rv < 0) {
		result = rv;
		node_count = 0;
		goto out;
	}

	/* node_count is the number of structs copied/returned; the caller's
	   max may be less than that, in which case we copy as many as they
	   asked for and return -E2BIG */

	if (node_count > max) {
		result = -E2BIG;
		node_count = max;
	} else {
		result = node_count;
	}
 out:
	do_reply(fd, DLMC_CMD_LOCKSPACE_NODES, name, result, 0,
		 (char *)nodes, node_count * sizeof(struct dlmc_node));

	if (nodes)
		free(nodes);
}

static void process_connection(int ci)
{
	struct dlmc_header h;
	char *extra = NULL;
	int rv, extra_len;
	struct lockspace *ls;

	rv = do_read(client[ci].fd, &h, sizeof(h));
	if (rv < 0) {
		log_debug("connection %d read error %d", ci, rv);
		goto out;
	}

	if (h.magic != DLMC_MAGIC) {
		log_debug("connection %d magic error %x", ci, h.magic);
		goto out;
	}

	if ((h.version & 0xFFFF0000) != (DLMC_VERSION & 0xFFFF0000)) {
		log_debug("connection %d version error %x", ci, h.version);
		goto out;
	}

	if (h.len > sizeof(h)) {
		extra_len = h.len - sizeof(h);
		extra = malloc(extra_len);
		if (!extra) {
			log_error("process_connection no mem %d", extra_len);
			goto out;
		}
		memset(extra, 0, extra_len);

		rv = do_read(client[ci].fd, extra, extra_len);
		if (rv < 0) {
			log_debug("connection %d extra read error %d", ci, rv);
			goto out;
		}
	}

	switch (h.command) {
	case DLMC_CMD_FENCE_ACK:
		fence_ack_node(atoi(h.name));
		break;

	case DLMC_CMD_FS_REGISTER:
		if (opt(enable_fscontrol_ind)) {
			rv = fs_register_add(h.name);
			ls = find_ls(h.name);
			if (ls)
				ls->fs_registered = 1;
		} else {
			rv = -EOPNOTSUPP;
		}
		do_reply(client[ci].fd, DLMC_CMD_FS_REGISTER, h.name, rv, 0,
			 NULL, 0);
		break;

	case DLMC_CMD_FS_UNREGISTER:
		fs_register_del(h.name);
		ls = find_ls(h.name);
		if (ls)
			ls->fs_registered = 0;
		break;

	case DLMC_CMD_FS_NOTIFIED:
		ls = find_ls(h.name);
		if (ls)
			rv = set_fs_notified(ls, h.data);
		else
			rv = -ENOENT;
		/* pass back the nodeid provided by caller in option field */
		do_reply(client[ci].fd, DLMC_CMD_FS_NOTIFIED, h.name, rv,
			 h.data, NULL, 0);
		break;

#if 0
	case DLMC_CMD_DEADLOCK_CHECK:
		ls = find_ls(h.name);
		if (ls)
			send_cycle_start(ls);
		client_dead(ci);
		break;
#endif
	default:
		log_error("process_connection %d unknown command %d",
			  ci, h.command);
	}
 out:
	if (extra)
		free(extra);
}

static void process_listener(int ci)
{
	int fd, i;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0) {
		log_error("process_listener: accept error %d %d", fd, errno);
		return;
	}
	
	i = client_add(fd, process_connection, NULL);

	log_debug("client connection %d fd %d", i, fd);
}

static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, s;

	/* we listen for new client connections on socket s */

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		log_error("socket error %d %d", s, errno);
		return s;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strcpy(&addr.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		log_error("bind error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		log_error("listen error %d %d", rv, errno);
		close(s);
		return rv;
	}
	return s;
}

static void query_lock(void)
{
	pthread_mutex_lock(&query_mutex);
}

static void query_unlock(void)
{
	pthread_mutex_unlock(&query_mutex);
}

/* This is a thread, so we have to be careful, don't call log_ functions.
   We need a thread to process queries because the main thread may block
   for long periods when writing to sysfs to stop dlm-kernel (any maybe
   other places). */

static void *process_queries(void *arg)
{
	struct dlmc_header h;
	int s, f, rv;

	rv = setup_listener(DLMC_QUERY_SOCK_PATH);
	if (rv < 0)
		return NULL;

	s = rv;

	for (;;) {
		f = accept(s, NULL, NULL);
		if (f < 0)
			return NULL;

		rv = do_read(f, &h, sizeof(h));
		if (rv < 0) {
			goto out;
		}

		if (h.magic != DLMC_MAGIC) {
			goto out;
		}

		if ((h.version & 0xFFFF0000) != (DLMC_VERSION & 0xFFFF0000)) {
			goto out;
		}

		query_lock();

		switch (h.command) {
		case DLMC_CMD_DUMP_DEBUG:
			query_dump_debug(f);
			break;
		case DLMC_CMD_DUMP_CONFIG:
			query_dump_config(f);
			break;
		case DLMC_CMD_DUMP_LOG_PLOCK:
			query_dump_log_plock(f);
			break;
		case DLMC_CMD_DUMP_PLOCKS:
			query_dump_plocks(f, h.name);
			break;
		case DLMC_CMD_LOCKSPACE_INFO:
			query_lockspace_info(f, h.name);
			break;
		case DLMC_CMD_NODE_INFO:
			query_node_info(f, h.name, h.data);
			break;
		case DLMC_CMD_LOCKSPACES:
			query_lockspaces(f, h.data);
			break;
		case DLMC_CMD_LOCKSPACE_NODES:
			query_lockspace_nodes(f, h.name, h.option, h.data);
			break;
		case DLMC_CMD_DUMP_STATUS:
			send_state_daemon(f);
			send_state_daemon_nodes(f);
			send_state_startup_nodes(f);
			break;
		default:
			break;
		}
		query_unlock();

 out:
		close(f);
	}
}

static int setup_queries(void)
{
	int rv;

	pthread_mutex_init(&query_mutex, NULL);

	rv = pthread_create(&query_thread, NULL, process_queries, NULL);
	if (rv < 0) {
		log_error("can't create query thread");
		return rv;
	}
	return 0;
}

/* The dlm in kernels before 2.6.28 do not have the monitor device.  We
   keep this fd open as long as we're running.  If we exit/terminate while
   lockspaces exist in the kernel, the kernel will detect a close on this
   fd and stop the lockspaces. */

static void setup_monitor(void)
{
	if (!monitor_minor)
		return;

	kernel_monitor_fd = open("/dev/misc/dlm-monitor", O_RDONLY);
	log_debug("/dev/misc/dlm-monitor fd %d", kernel_monitor_fd);
}

void cluster_dead(int ci)
{
	if (!cluster_down)
		log_error("cluster is down, exiting");
	daemon_quit = 1;
	cluster_down = 1;
}

static void loop(void)
{
	struct lockspace *ls;
	int poll_timeout = -1;
	int rv, i;
	void (*workfn) (int ci);
	void (*deadfn) (int ci);

	rv = setup_queries();
	if (rv < 0)
		goto out;

	rv = setup_listener(DLMC_SOCK_PATH);
	if (rv < 0)
		goto out;
	client_add(rv, process_listener, NULL);

	rv = setup_cluster_cfg();
	if (rv < 0)
		goto out;
	if (rv > 0) 
		client_add(rv, process_cluster_cfg, cluster_dead);

	rv = check_uncontrolled_lockspaces();
	if (rv < 0)
		goto out;

	/*
	 * unfence needs to happen after checking for uncontrolled dlm kernel
	 * state (for which we are probably currently fenced, the state must
	 * be cleared by a reboot).  unfence needs to happen before joining
	 * the daemon cpg, after which it needs to be possible for someone to
	 * fence us.
	 */
	rv = unfence_node(our_nodeid);
	if (rv < 0)
		goto out;

	rv = setup_node_config();
	if (rv < 0)
		goto out;

	rv = setup_cluster();
	if (rv < 0)
		goto out;
	client_add(rv, process_cluster, cluster_dead);

	rv = setup_misc_devices();
	if (rv < 0)
		goto out;

	rv = setup_configfs_options();
	if (rv < 0)
		goto out;

	setup_monitor();

	rv = setup_configfs_members();		/* calls update_cluster() */
	if (rv < 0)
		goto out;

	rv = setup_uevent();
	if (rv < 0)
		goto out;
	client_add(rv, process_uevent, NULL);

	rv = setup_cpg_daemon();
	if (rv < 0)
		goto out;
	client_add(rv, process_cpg_daemon, cluster_dead);

	rv = set_protocol();
	if (rv < 0)
		goto out;

#if 0
	if (opt(enable_deadlk_ind)) {
		rv = setup_netlink();
		if (rv < 0)
			goto out;
		client_add(rv, process_netlink, NULL);

		setup_deadlock();
	}
#endif

	rv = setup_plocks();
	if (rv < 0)
		goto out;
	plock_fd = rv;
	plock_ci = client_add(rv, process_plocks, NULL);

#ifdef USE_SD_NOTIFY
	sd_notify(0, "READY=1");
#endif

	/* We want to wait for our protocol to be set before
	   we start to process fencing. */
	daemon_fence_allow = 1;

	for (;;) {
		rv = poll(pollfd, client_maxi + 1, poll_timeout);
		if (rv == -1 && errno == EINTR) {
			if (daemon_quit && list_empty(&lockspaces))
				goto out;
			if (daemon_quit) {
				log_error("shutdown ignored, active lockspaces");
				daemon_quit = 0;
			}
			continue;
		}
		if (rv < 0) {
			log_error("poll errno %d", errno);
			goto out;
		}

		query_lock();

		for (i = 0; i <= client_maxi; i++) {
			if (client[i].fd < 0)
				continue;
			if (pollfd[i].revents & POLLIN) {
				workfn = client[i].workfn;
				workfn(i);
			}
			if (pollfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				deadfn = client[i].deadfn;
				deadfn(i);
			}
		}
		query_unlock();

		if (daemon_quit)
			break;

		query_lock();

		poll_timeout = -1;

		if (retry_fencing) {
			process_fencing_changes();
			poll_timeout = 1000;
		}

		if (poll_lockspaces || poll_fs) {
			process_lockspace_changes();
			poll_timeout = 1000;
		}

		if (poll_ignore_plock) {
			if (!limit_plocks()) {
				poll_ignore_plock = 0;
				client_back(plock_ci, plock_fd);
			}
			poll_timeout = 1000;
		}

		if (poll_drop_plock) {
			drop_resources_all();
			if (poll_drop_plock)
				poll_timeout = 1000;
		}

		query_unlock();
	}
 out:
	log_debug("shutdown");
	close_plocks();
	close_cpg_daemon();
	clear_configfs();
	close_logging();
	close_cluster();
	close_cluster_cfg();

	list_for_each_entry(ls, &lockspaces, list)
		log_error("abandoned lockspace %s", ls->name);
}

static int lockfile(const char *dir, const char *name)
{
	char path[PATH_MAX];
	char buf[16];
	struct flock lock;
	mode_t old_umask;
	int fd, rv;

	old_umask = umask(0022);
	rv = mkdir(dir, 0775);
	if (rv < 0 && errno != EEXIST) {
		umask(old_umask);
		return rv;
	}
	umask(old_umask);

	snprintf(path, PATH_MAX, "%s/%s", dir, name);

	fd = open(path, O_CREAT|O_WRONLY|O_CLOEXEC, 0644);
	if (fd < 0) {
		log_error("lockfile open error %s: %s",
			  path, strerror(errno));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;

	rv = fcntl(fd, F_SETLK, &lock);
	if (rv < 0) {
		log_error("lockfile setlk error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error("lockfile truncate error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "%d\n", getpid());

	rv = write(fd, buf, strlen(buf));
	if (rv <= 0) {
		log_error("lockfile write error %s: %s",
			  path, strerror(errno));
		goto fail;
	}

	return fd;
 fail:
	close(fd);
	return -1;
}

static void unlink_lockfile(int fd, const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	unlink(path);
	close(fd);
}

static const char *req_arg_s(int a)
{
	switch (a) {
	case no_arg:
		return "";
	case req_arg_bool:
		return "0|1";
	case req_arg_int:
		return "<int>";
	case req_arg_str:
		return "<str>";
	default:
		return "<arg>";
	}
}

static void print_usage(void)
{
	struct dlm_option *o;
	int i;

	printf("Usage:\n");
	printf("\n");
	printf("dlm_controld [options]\n");
	printf("\n");
	printf("Option [arg]\n");
	printf("Description [default]\n");
	printf("\n");

	for (i = 0; i < dlm_options_max; i++) {
		o = &dlm_options[i];

		/* don't advertise options with no description */
		if (!strlen(o->desc))
			continue;

		printf("  --%s", o->name);

		if (o->letter) {
			printf(" | -%c", o->letter);
			if (o->req_arg)
				printf(" %s", req_arg_s(o->req_arg));
		} else {
			if (o->req_arg)
				printf(" %s", req_arg_s(o->req_arg));
		}

		printf("\n");

		printf("        %s", o->desc);

		if (o->req_arg == req_arg_str)
			printf(" [%s]\n", o->default_str ? o->default_str : "");
		else if (o->req_arg == req_arg_int)
			printf(" [%d]\n", o->default_int);
		else if (o->req_arg == req_arg_bool)
			printf(" [%d]\n", o->default_int);
		else if (o->req_arg == no_arg && !o->default_int)
			printf(" [0]\n");
		else
			printf("\n");

		printf("\n");
	}
}

static void set_opt_default(int ind, const char *name, char letter, int arg_type,
			    int default_int, const char *default_str, const char *desc)
{
	dlm_options[ind].name = name;
	dlm_options[ind].letter = letter;
	dlm_options[ind].req_arg = arg_type;
	dlm_options[ind].desc = desc;
	dlm_options[ind].default_int = default_int;
	dlm_options[ind].default_str = default_str;
	dlm_options[ind].use_int = default_int;
	dlm_options[ind].use_str = (char *)default_str;
}

static void set_opt_defaults(void)
{
	set_opt_default(daemon_debug_ind,
			"daemon_debug", 'D', no_arg,
			0, NULL,
			"enable debugging to stderr and don't fork");

	set_opt_default(foreground_ind,
			"foreground", '\0', no_arg,
			0, NULL,
			"don't fork");

	set_opt_default(log_debug_ind,
			"log_debug", 'K', no_arg,
			0, NULL,
			"enable kernel dlm debugging messages");

	set_opt_default(timewarn_ind,
			"timewarn", '\0', req_arg_int,
			0, NULL,
			""); /* do not advertise */

	set_opt_default(protocol_ind,
			"protocol", 'r', req_arg_str,
			-1, "detect",
			"dlm kernel lowcomms protocol: tcp, sctp, detect");

	set_opt_default(debug_logfile_ind,
			"debug_logfile", 'L', no_arg,
			0, NULL,
			"write debugging to log file");

	set_opt_default(enable_fscontrol_ind,
			"enable_fscontrol", '\0', req_arg_bool,
			0, NULL,
			""); /* do not advertise */

	set_opt_default(enable_plock_ind,
			"enable_plock", 'p', req_arg_bool,
			1, NULL,
			"enable/disable posix lock support for cluster fs");

	set_opt_default(plock_debug_ind,
			"plock_debug", 'P', no_arg,
			0, NULL,
			"enable plock debugging");

	set_opt_default(plock_rate_limit_ind,
			"plock_rate_limit", 'l', req_arg_int,
			0, NULL,
			"limit rate of plock operations (0 for none)");

	set_opt_default(plock_ownership_ind,
			"plock_ownership", 'o', req_arg_bool,
			0, NULL,
			"enable/disable plock ownership");

	set_opt_default(drop_resources_time_ind,
			"drop_resources_time", 't', req_arg_int,
			10000, NULL,
			"plock ownership drop resources time (milliseconds)");

	set_opt_default(drop_resources_count_ind,
			"drop_resources_count", 'c', req_arg_int,
			10, NULL,
			"plock ownership drop resources count");

	set_opt_default(drop_resources_age_ind,
			"drop_resources_age", 'a', req_arg_int,
			10000, NULL,
			"plock ownership drop resources age (milliseconds)");

	set_opt_default(post_join_delay_ind,
			"post_join_delay", 'j', req_arg_int,
			30, NULL,
			"seconds to delay fencing after cluster join");

	set_opt_default(enable_fencing_ind,
			"enable_fencing", 'f', req_arg_bool,
			1, NULL,
			"enable/disable fencing");

	set_opt_default(enable_concurrent_fencing_ind,
			"enable_concurrent_fencing", '\0', req_arg_bool,
			0, NULL,
			"enable/disable concurrent fencing");

	set_opt_default(enable_startup_fencing_ind,
			"enable_startup_fencing", 's', req_arg_bool,
			1, NULL,
			"enable/disable startup fencing");

	set_opt_default(enable_quorum_fencing_ind,
			"enable_quorum_fencing", 'q', req_arg_bool,
			1, NULL,
			"enable/disable quorum requirement for fencing");

	set_opt_default(enable_quorum_lockspace_ind,
			"enable_quorum_lockspace", '\0', req_arg_bool,
			1, NULL,
			"enable/disable quorum requirement for lockspace operations");

	set_opt_default(help_ind,
			"help", 'h', no_arg,
			-1, NULL,
			"print this help, then exit");

	set_opt_default(version_ind,
			"version", 'V', no_arg,
			-1, NULL,
			"Print program version information, then exit");
}

static int get_ind_name(char *s)
{
	char name[PATH_MAX];
	char *p = s;
	int i;

	memset(name, 0, sizeof(name));

	for (i = 0; i < strlen(s); i++) {
		if (*p == '=')
			break;
		if (*p == ' ')
			break;
		name[i] = *p;
		p++;
	}

	for (i = 0; i < dlm_options_max; i++) {
		if (!strcmp(dlm_options[i].name, name))
			return i;
	}
	return -1;
}

static int get_ind_letter(char c)
{
	int i;

	for (i = 0; i < dlm_options_max; i++) {
		if (dlm_options[i].letter == c)
			return i;
	}
	return -1;
}

struct dlm_option *get_dlm_option(char *name)
{
	int i;
	i = get_ind_name(name);
	if (i < 0)
		return NULL;
	return &dlm_options[i];
}

static void set_opt_cli(int argc, char **argv)
{
	struct dlm_option *o;
	char *arg1, *p, *arg_str;
	char bundled_letters[8];
	int b, blc = 0, blc_max = 8;
	int debug_options = 0;
	int i, ind;

	if (argc < 2)
		return;

	arg1 = argv[1];

	if (!strcmp(arg1, "help") || !strcmp(arg1, "--help") || !strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version") || !strcmp(arg1, "--version") || !strcmp(arg1, "-V")) {
		printf("dlm_controld %s (built %s %s)\n",
			RELEASE_VERSION, __DATE__, __TIME__);
			printf("%s\n", REDHAT_COPYRIGHT);
		exit(EXIT_SUCCESS);
	}

	for (i = 1; i < argc; ) {
		p = argv[i++];

		if (!strcmp(p, "--debug_options")) {
			debug_options = 1;
			continue;
		}

		if (p[0] == '-' && p[1] == '-')
			ind = get_ind_name(p + 2);
		else if (p[0] == '-')
			ind = get_ind_letter(p[1]);
		else {
			fprintf(stderr, "unknown option arg %s\n", p);
			exit(EXIT_FAILURE);
		}

		if (ind < 0) {
			fprintf(stderr, "unknown option %s\n", p);
			exit(EXIT_FAILURE);
		}

		o = &dlm_options[ind];
		o->cli_set++;

		if (!o->req_arg) {
			/* "-x" has same effect as "-x 1" */
			o->cli_int = 1;
			o->use_int = 1;

			/* save bundled, arg-less, single letters, e.g. -DKP */
			if ((p[0] == '-') && isalpha(p[1]) && (strlen(p) > 2)) {
				for (b = 2; b < strlen(p) && blc < blc_max; b++) {
					if (!isalpha(p[b]))
						break;
					bundled_letters[blc++] = p[b];
				}
			}
			continue;
		}

		arg_str = NULL;

		if (strstr(p, "=")) {
			/* arg starts after = for name or letter */
			arg_str = strstr(p, "=") + 1;

		} else if (strlen(p) > 2 && isalpha(p[1]) && isdigit(p[2])) {
			/* arg with no space between letter and digits */
			arg_str = p + 2;

		} else {
			/* space separates arg from name or letter */
			if (i >= argc) {
				fprintf(stderr, "option %s no arg", p);
				exit(EXIT_FAILURE);
			}
			arg_str = argv[i++];
		}

		if (!arg_str || arg_str[0] == '-' || arg_str[0] == '\0') {
			fprintf(stderr, "option %s requires arg", p);
			exit(EXIT_FAILURE);
		}

		if (o->req_arg == req_arg_str) {
			o->cli_str = strdup(arg_str);
			o->use_str = o->cli_str;
		} else if (o->req_arg == req_arg_int) {
			o->cli_int = atoi(arg_str);
			o->use_int = o->cli_int;
		} else if (o->req_arg == req_arg_bool) {
			o->cli_int = atoi(arg_str) ? 1 : 0;
			o->use_int = o->cli_int;
		}
	}

	/* process bundled letters saved above */

	for (i = 0; i < blc; i++) {
		ind = get_ind_letter(bundled_letters[i]);
		if (ind < 0) {
			fprintf(stderr, "unknown option char %c\n", bundled_letters[i]);
			exit(EXIT_FAILURE);
		}
		o = &dlm_options[ind];
		o->cli_set++;
		o->cli_int = 1;
		o->use_int = 1;
	}

	if (debug_options && opt(daemon_debug_ind)) {
		for (i = 0; i < dlm_options_max; i++) {
			o = &dlm_options[i];
			printf("%-25s cli_set %d cli_int %d cli_str %s use_int %d use_str %s\n",
			       o->name, o->cli_set, o->cli_int, o->cli_str, o->use_int, o->use_str);
		}
	}

	if (getenv("DLM_CONTROLD_DEBUG")) {
		dlm_options[daemon_debug_ind].use_int = 1;
	}
}

#if 0
/* When this is used, the systemd service file needs ControlGroup=cpu:/ */
static void set_scheduler(void)
{
	struct sched_param sched_param;
	int rv;

	rv = sched_get_priority_max(SCHED_RR);
	if (rv != -1) {
		sched_param.sched_priority = rv;
		rv = sched_setscheduler(0, SCHED_RR, &sched_param);
		if (rv == -1)
			log_error("could not set SCHED_RR priority %d err %d",
				   sched_param.sched_priority, errno);
	} else {
		log_error("could not get maximum scheduler priority err %d",
			  errno);
	}
}
#endif

int main(int argc, char **argv)
{
	struct sigaction act;
	int fd, rv;

	/*
	 * config priority: cli, config file, default
	 * - explicit cli setting will override default,
	 * - explicit file setting will override default
	 * - explicit file setting will not override explicit cli setting
	 */

	set_opt_defaults();
	set_opt_cli(argc, argv);
	set_opt_file(0);

	strcpy(fence_all_device.name, "fence_all");
	strcpy(fence_all_device.agent, "dlm_stonith");
	fence_all_device.unfence = 0;

	INIT_LIST_HEAD(&lockspaces);
	INIT_LIST_HEAD(&fs_register_list);
	init_daemon();

	if (!opt(daemon_debug_ind) && !opt(foreground_ind)) {
		if (daemon(0, 0) < 0) {
			perror("daemon error");
			exit(EXIT_FAILURE);
		}
	}

	init_logging();

	fd = lockfile(RUNDIR, RUN_FILE_NAME);
	if (fd < 0)
		return fd;

	log_level(NULL, LOG_INFO, "dlm_controld %s started", RELEASE_VERSION);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigterm_handler;
	rv = sigaction(SIGTERM, &act, NULL);
	if (rv < 0)
		return -rv;
	rv = sigaction(SIGINT, &act, NULL);
	if (rv < 0)
		return -rv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	rv = sigaction(SIGHUP, &act, NULL);
	if (rv < 0)
		return -rv;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigchld_handler;
	act.sa_flags = SA_NOCLDSTOP;
	rv = sigaction(SIGCHLD, &act, NULL);
	if (rv < 0)
		return -rv;

	/* set_scheduler(); */

	loop();

	unlink_lockfile(fd, RUNDIR, RUN_FILE_NAME);
	return 0;
}


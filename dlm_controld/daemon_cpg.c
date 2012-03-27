/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

/* protocol_version flags */
#define PV_STATEFUL 0x0001

struct protocol_version {
	uint16_t major;
	uint16_t minor;
	uint16_t patch;
	uint16_t flags;
};

struct protocol {
	union {
		struct protocol_version dm_ver;
		uint16_t                daemon_max[4];
	};
	union {
		struct protocol_version km_ver;
		uint16_t                kernel_max[4];
	};
	union {
		struct protocol_version dr_ver;
		uint16_t                daemon_run[4];
	};
	union {
		struct protocol_version kr_ver;
		uint16_t                kernel_run[4];
	};
};

/* fence_result flags */
#define FR_FIPU			0x00000001
#define FR_CLEAR_STARTUP	0x00000002
#define FR_CLEAR_FIPU		0x00000004

struct fence_result {
	uint32_t version;
	uint32_t flags;
	uint32_t nodeid;
	uint32_t result;
	uint64_t fence_walltime;
	char unused[1000];
};

struct node_daemon {
	struct list_head list;
	int nodeid;

	uint64_t daemon_add_time;
	uint64_t daemon_rem_time;
	int daemon_member;

	int killed;

	struct protocol proto;

	struct fence_config fence_config;

	int fence_in_progress_unknown;
	int left_reason;
	int recover_setup;
	int need_fence_clear;
	int need_fencing;
	int delay_fencing;
	int fence_pid;
	int fence_pid_wait;
	int fence_actor_done;
	int fence_actors[MAX_NODES];
	uint64_t fail_walltime;
	uint64_t fail_monotime;
	uint64_t fence_request_time;
	uint64_t fence_walltime;
	uint64_t fence_monotime;
};

#define REASON_STARTUP_FENCING -1

static cpg_handle_t cpg_handle_daemon;
static int cpg_fd_daemon;
static struct protocol our_protocol;
static struct list_head daemon_nodes;
static struct list_head startup_nodes;
static struct cpg_address daemon_member[MAX_NODES];
static struct cpg_address daemon_joined[MAX_NODES];
static struct cpg_address daemon_remove[MAX_NODES];
static int daemon_member_count;
static int daemon_joined_count;
static int daemon_remove_count;
static int daemon_ringid_wait;
static struct cpg_ring_id daemon_ringid;
static int daemon_clear_nodeid;
static int daemon_clear_pid;
static uint64_t daemon_last_join_monotime;
static uint32_t last_join_seq;
static uint32_t send_fipu_seq;
static int fence_in_progress_unknown = 1;

static void send_fence_result(int nodeid, int result, uint32_t flags, uint64_t walltime);
static void send_fence_clear(int nodeid, int result, uint32_t flags, uint64_t walltime);

void log_config(const struct cpg_name *group_name,
		const struct cpg_address *member_list,
		size_t member_list_entries,
		const struct cpg_address *left_list,
		size_t left_list_entries,
		const struct cpg_address *joined_list,
		size_t joined_list_entries)
{
	char m_buf[128];
	char j_buf[32];
	char l_buf[32];
	size_t i, len, pos;
	int ret;

	memset(m_buf, 0, sizeof(m_buf));
	memset(j_buf, 0, sizeof(j_buf));
	memset(l_buf, 0, sizeof(l_buf));

	len = sizeof(m_buf);
	pos = 0;
	for (i = 0; i < member_list_entries; i++) {
		ret = snprintf(m_buf + pos, len - pos, " %d",
			       member_list[i].nodeid);
		if (ret >= len - pos)
			break;
		pos += ret;
	}

	len = sizeof(j_buf);
	pos = 0;
	for (i = 0; i < joined_list_entries; i++) {
		ret = snprintf(j_buf + pos, len - pos, " %d",
			       joined_list[i].nodeid);
		if (ret >= len - pos)
			break;
		pos += ret;
	}

	len = sizeof(l_buf);
	pos = 0;
	for (i = 0; i < left_list_entries; i++) {
		ret = snprintf(l_buf + pos, len - pos, " %d",
			       left_list[i].nodeid);
		if (ret >= len - pos)
			break;
		pos += ret;
	}

	log_debug("%s conf %zu %zu %zu memb%s join%s left%s", group_name->value,
		  member_list_entries, joined_list_entries, left_list_entries,
		  m_buf, j_buf, l_buf);
}

void log_ringid(const char *name,
                struct cpg_ring_id *ringid,
                const uint32_t *member_list,
                size_t member_list_entries)
{
	char m_buf[128];
	size_t i, len, pos;
	int ret;

	memset(m_buf, 0, sizeof(m_buf));

	len = sizeof(m_buf);
	pos = 0;
	for (i = 0; i < member_list_entries; i++) {
		ret = snprintf(m_buf + pos, len - pos, " %u",
			       member_list[i]);
		if (ret >= len - pos)
			break;
		pos += ret;
	}

	log_debug("%s ring %u:%llu %zu memb%s",
		  name, ringid->nodeid, (unsigned long long)ringid->seq,
		  member_list_entries, m_buf);
}

const char *reason_str(int reason)
{
	switch (reason) {
	case CPG_REASON_JOIN:
		return "join";
	case CPG_REASON_LEAVE:
		return "leave";
	case CPG_REASON_NODEDOWN:
		return "nodedown";
	case CPG_REASON_NODEUP:
		return "nodeup";
	case CPG_REASON_PROCDOWN:
		return "procdown";
	default:
		return "unknown";
	};
}

const char *msg_name(int type)
{
	switch (type) {
	case DLM_MSG_PROTOCOL:
		return "protocol";
	case DLM_MSG_FENCE_RESULT:
		return "fence_result";
	case DLM_MSG_FENCE_CLEAR:
		return "fence_clear";

	case DLM_MSG_START:
		return "start";
	case DLM_MSG_PLOCK:
		return "plock";
	case DLM_MSG_PLOCK_OWN:
		return "plock_own";
	case DLM_MSG_PLOCK_DROP:
		return "plock_drop";
	case DLM_MSG_PLOCK_SYNC_LOCK:
		return "plock_sync_lock";
	case DLM_MSG_PLOCK_SYNC_WAITER:
		return "plock_sync_waiter";
	case DLM_MSG_PLOCKS_DATA:
		return "plocks_data";
	case DLM_MSG_PLOCKS_DONE:
		return "plocks_done";
	case DLM_MSG_DEADLK_CYCLE_START:
		return "deadlk_cycle_start";
	case DLM_MSG_DEADLK_CYCLE_END:
		return "deadlk_cycle_end";
	case DLM_MSG_DEADLK_CHECKPOINT_READY:
		return "deadlk_checkpoint_ready";
	case DLM_MSG_DEADLK_CANCEL_LOCK:
		return "deadlk_cancel_lock";
	default:
		return "unknown";
	}
}

static int _send_message(cpg_handle_t h, void *buf, int len, int type)
{
	struct iovec iov;
	cs_error_t error;
	int retries = 0;

	iov.iov_base = buf;
	iov.iov_len = len;

 retry:
	error = cpg_mcast_joined(h, CPG_TYPE_AGREED, &iov, 1);
	if (error == CS_ERR_TRY_AGAIN) {
		retries++;
		usleep(1000);
		if (!(retries % 100))
			log_error("cpg_mcast_joined retry %d %s",
				   retries, msg_name(type));
		goto retry;
	}
	if (error != CS_OK) {
		log_error("cpg_mcast_joined error %d handle %llx %s",
			  error, (unsigned long long)h, msg_name(type));
		return -1;
	}

	if (retries)
		log_debug("cpg_mcast_joined retried %d %s",
			  retries, msg_name(type));

	return 0;
}

/* header fields caller needs to set: type, to_nodeid, flags, msgdata */

void dlm_send_message(struct lockspace *ls, char *buf, int len)
{
	struct dlm_header *hd = (struct dlm_header *) buf;
	int type = hd->type;

	hd->version[0]  = cpu_to_le16(our_protocol.daemon_run[0]);
	hd->version[1]  = cpu_to_le16(our_protocol.daemon_run[1]);
	hd->version[2]  = cpu_to_le16(our_protocol.daemon_run[2]);
	hd->type	= cpu_to_le16(hd->type);
	hd->nodeid      = cpu_to_le32(our_nodeid);
	hd->to_nodeid   = cpu_to_le32(hd->to_nodeid);
	hd->global_id   = cpu_to_le32(ls->global_id);
	hd->flags       = cpu_to_le32(hd->flags);
	hd->msgdata     = cpu_to_le32(hd->msgdata);
	hd->msgdata2    = cpu_to_le32(hd->msgdata2);

	_send_message(ls->cpg_handle, buf, len, type);
}

void dlm_header_in(struct dlm_header *hd)
{
	hd->version[0]  = le16_to_cpu(hd->version[0]);
	hd->version[1]  = le16_to_cpu(hd->version[1]);
	hd->version[2]  = le16_to_cpu(hd->version[2]);
	hd->type        = le16_to_cpu(hd->type);
	hd->nodeid      = le32_to_cpu(hd->nodeid);
	hd->to_nodeid   = le32_to_cpu(hd->to_nodeid);
	hd->global_id   = le32_to_cpu(hd->global_id);
	hd->flags       = le32_to_cpu(hd->flags);
	hd->msgdata     = le32_to_cpu(hd->msgdata);
	hd->msgdata2    = le32_to_cpu(hd->msgdata2);
}

int dlm_header_validate(struct dlm_header *hd, int nodeid)
{
	if (hd->version[0] != our_protocol.daemon_run[0] ||
	    hd->version[1] != our_protocol.daemon_run[1]) {
		log_error("reject message from %d version %u.%u.%u vs %u.%u.%u",
			  nodeid, hd->version[0], hd->version[1],
			  hd->version[2], our_protocol.daemon_run[0],
			  our_protocol.daemon_run[1],
			  our_protocol.daemon_run[2]);
		return -1;
	}

	if (hd->nodeid != nodeid) {
		log_error("bad msg nodeid %d %d", hd->nodeid, nodeid);
		return -1;
	}

	return 0;
}

static struct node_daemon *get_node_daemon(int nodeid)
{
	struct node_daemon *node;

	list_for_each_entry(node, &daemon_nodes, list) {
		if (node->nodeid == nodeid)
			return node;
	}
	return NULL;
}

static int nodes_need_fencing(void)
{
	struct node_daemon *node;

	list_for_each_entry(node, &daemon_nodes, list) {
		if (node->need_fencing)
			return 1;
	}
	return 0;
}

static int all_daemon_members_fipu(void)
{
	struct node_daemon *node;

	list_for_each_entry(node, &daemon_nodes, list) {
		if (!node->daemon_member)
			continue;
		if (!node->fence_in_progress_unknown)
			return 0;
	}

	list_for_each_entry(node, &daemon_nodes, list) {
		if (!node->daemon_member)
			continue;
		node->fence_in_progress_unknown = 0;
	}

	return 1;
}

int fence_node_time(int nodeid, uint64_t *last_fenced)
{
	struct node_daemon *node;

	node = get_node_daemon(nodeid);
	if (!node)
		return -1;

	*last_fenced = node->fence_monotime;
	return 0;
}

int fence_in_progress(int *in_progress)
{
	if (fence_in_progress_unknown) {
		*in_progress = 1;
	} else if (!list_empty(&startup_nodes)) {
		*in_progress = 2;
	} else if (nodes_need_fencing()) {
		*in_progress = 3;
	} else {
		*in_progress = 0;
	}
	return 0;
}

void add_startup_node(int nodeid)
{
	struct node_daemon *node;

	node = malloc(sizeof(struct node_daemon));
	if (!node) {
		log_error("add_startup_node no mem");
		return;
	}
	memset(node, 0, sizeof(struct node_daemon));
	node->nodeid = nodeid;
	list_add_tail(&node->list, &startup_nodes);
}

static int clear_startup_node(int nodeid, int all)
{
	struct node_daemon *node, *safe;
	int count = 0;

	list_for_each_entry_safe(node, safe, &startup_nodes, list) {
		if (all || node->nodeid == nodeid) {
			list_del(&node->list);
			free(node);
			count++;
		}
	}
	return count;
}

static struct node_daemon *add_node_daemon(int nodeid)
{
	struct node_daemon *node;
	struct fence_config *fc;

	node = get_node_daemon(nodeid);
	if (node)
		return node;

	node = malloc(sizeof(struct node_daemon));
	if (!node) {
		log_error("add_node_daemon no mem");
		return NULL;
	}
	memset(node, 0, sizeof(struct node_daemon));
	node->nodeid = nodeid;
	list_add_tail(&node->list, &daemon_nodes);

	/* TODO: allow the config to be reread */

	fc = &node->fence_config;
	fc->nodeid = nodeid;

	/* explicit command line arg has first priority */

	if (optd_fence_all_agent) {
		fc->dev[0] = &fence_all_device;
		goto out;
	}

	/* explicit config file setting has second priority */

	fence_config_init(fc, (unsigned int)nodeid, (char *)CONF_FILE_PATH);

	/* no command line, no config file, use default, third priority */

	if (!fc->dev[0] && fence_all_agent[0])
		fc->dev[0] = &fence_all_device;
 out:
	return node;
}

/* A clean daemon member is a node that has joined the daemon cpg
   from a "clean state", i.e. not a stateful merge.  If would not
   have joined the daemon cpg if it found uncontrolled dlm kernel
   state (check_uncontrolled_lockspaces).  We would not have
   accepted and saved its protocol in node->proto.daemon if it
   was a stateful merge. */

static int is_clean_daemon_member(int nodeid)
{
	struct node_daemon *node;

	node = get_node_daemon(nodeid);
	if (node && node->daemon_member && node->proto.daemon_max[0])
		return 1;
	return 0;
}

static int in_daemon_list(int nodeid, struct cpg_address *daemon_list, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (daemon_list[i].nodeid == nodeid)
			return 1;
	}
	return 0;
}

/* save in node->fence_actors[] any nodeid present when the node
   failed which therefore saw it fail, knows it needs fencing, and
   can request fencing for it if it becomes the low actor.  A node
   added in the same change with the removed node does not qualify. */

static int set_fence_actors(struct node_daemon *node, int all_memb)
{
	int i, nodeid, count = 0, low = 0;

	memset(node->fence_actors, 0, sizeof(node->fence_actors));

	for (i = 0; i < daemon_member_count; i++) {
		nodeid = daemon_member[i].nodeid;

		if (!all_memb && in_daemon_list(nodeid, daemon_joined, daemon_joined_count))
			continue;

		node->fence_actors[count++] = nodeid;

		if (!low || nodeid < low)
			low = nodeid;
	}

	log_debug("set_fence_actors for %d low %d count %d",
		  node->nodeid, low, count);
	return low;
}

static int get_fence_actor(struct node_daemon *node)
{
	int i, low, low_i;

 retry:
	low = 0;

	for (i = 0; i < MAX_NODES; i++) {
		if (!node->fence_actors[i])
			continue;

		if (!low || node->fence_actors[i] < low) {
			low = node->fence_actors[i];
			low_i = i;
		}
	}

	if (low && !in_daemon_list(low, daemon_member, daemon_member_count)) {
		log_debug("get_fence_actor for %d low actor %d is gone",
			  node->nodeid, low);

		node->fence_actors[low_i] = 0;
		goto retry;
	}

	return low;
}

/* if an actor fails to fence, it will send that result, and others
   will clear it from the actors, which will cause the next lowest
   actor to try */

static void clear_fence_actor(int nodeid, int actor)
{
	struct node_daemon *node;
	int i;

	node = get_node_daemon(nodeid);
	if (!node)
		return;

	for (i = 0; i < MAX_NODES; i++) {
		if (node->fence_actors[i] == actor) {
			node->fence_actors[i] = 0;
			return;
		}
	}
}

/* TODO: handle delayed cleanup of more than one pid */

static void fence_pid_cancel(int nodeid, int pid)
{
	struct node_daemon *node;
	int rv, result;

	log_debug("fence_pid_cancel nodeid %d pid %d", nodeid, pid);

	kill(pid, SIGKILL);
	usleep(500000);

	rv = fence_result(nodeid, pid, &result);
	if (rv == -EAGAIN) {
		/* Try again later */
		daemon_clear_nodeid = nodeid;
		daemon_clear_pid = pid;
	} else {
		log_debug("fence_pid_cancel nodeid %d pid %d done %d",
			  nodeid, pid, result);

		daemon_clear_nodeid = 0;
		daemon_clear_pid = 0;

		node = get_node_daemon(nodeid);
		if (node && node->fence_pid == pid) {
			node->fence_pid_wait = 0;
			node->fence_pid = 0;
		}
	}
}

/*
 * fence_in_progress_unknown (fipu)
 *
 * If current daemon members are fencing someone, and a new node
 * joins, that new node needs to wait for the previous members to
 * finish any fencing they're doing before it can start a lockspace.
 *
 * The previous members may be fencing the last node that was using
 * the lockspace the new node is going to use, so if it doesn't wait,
 * it could start using a lockspace with an unfenced user.
 *
 * So, the daemon starts with fence_in_progress_unknown set to
 * indicate that other nodes may be fencing someone, and it won't
 * start any lockspaces until it is clear.
 *
 * A node starts with fence_in_progress_unknown set and won't
 * start any lockspaces until it's clear.
 *
 * When using startup_fencing:
 *
 * . When all nodes start up together, all have fipu set,
 * and will go through startup fencing, which will eventually
 * result in all nodes either being clean daemon members or fenced,
 * so everyone will clear fipu by seeing that.
 *
 * . The more common case is when a new node joins other previously
 * running nodes.  The new node needs to be told that the others
 * have no outstanding fencing ops before it can clear fipu.
 * A previous member does send_fence_clear(0) to a new node once
 * all fencing is complete.  The two flags in send_fence_clear are
 * usually sent together but may sometimes may be in separate messages:
 * send_fence_clear(0, CLEAR_STARTUP) to clear startup_nodes right away
 * send_fence_clear(0, CLEAR_FIPU) to clear fipu once all fencing is done
 *
 * When not using startup_fencing:
 *
 * . When all nodes start up together, all have fipu set, and all
 * will be waiting to receive_fence_clear from a previous node
 * in order to clear it.  The nodes need to detect this situation,
 * and when they do, they will know that everyone is in startup,
 * so there can be no pending fencing on a previous node, so all
 * can clear fipu.  To detect this case, when a node starts up
 * with !startup_fence, it sends a special send_fence_clear(-ENODATA, FIPU)
 * message about itself to indicate it has fipu set and needs it cleared.
 * After sending this, it checks to see if all present nodes have sent
 * this same message about themselves.  If so, then this startup
 * case has been detected, an all will clear fipu.
 *
 * . New nodes that join after this startup initialization will be
 * handled the same as when startup_fencing is set (above).
 *
 *
 * startup_fencing
 * ---------------
 *
 * case A
 * all nodes start up,
 * all have fipu set,
 * all wait for startup_nodes to be empty, (joined or moved to need_fencing)
 * all wait for no daemon_nodes to need_fencing, (joined or were fenced)
 * all clear fipu
 *
 * later,
 *
 * case B
 * new node starts,
 * new node has fipu set,
 * cur node sees need_fence_clear on new node
 * cur node sees no pending fencing ops,
 * cur node send_fence_clear(0) to new node,
 * new node clears startup_nodes and fipu
 *
 * !startup_fencing
 * ----------------
 *
 * case C
 * all nodes start up,
 * all have fipu set,
 * all send_fence_clear(-ENODATA,FIPU),
 * all receive_fence_clear(-ENODATA,FIPU) from everyone,
 * all_daemon_members_fipu() is 1,
 * all clear fipu
 *
 * later same as case B above
 */

/*
 * TODO: limit to one agent running at once, in case both
 * instances need to log into the same switch, for example.
 */

static void daemon_fence_work(void)
{
	struct node_daemon *node, *safe;
	int rv, nodeid, pid, need, low, actor, result;
	uint32_t flags;

	if (daemon_ringid_wait) {
		/* We've seen a nodedown confchg callback, but not the
		   corresponding ringid callback. */
		log_debug("fence work wait for cpg ringid");
		return;
	}

	if (cluster_ringid_seq != daemon_ringid.seq) {
		/* wait for ringids to be in sync */
		log_debug("fence work wait for cluster ringid");
		return;
	}

	/* poll_fencing++; */

	if (cfgd_enable_quorum_fencing && !cluster_quorate) {
		/* wait for quorum before doing any fencing, but if there
		   is none, send_fence_clear below can unblock new nodes */
		log_debug("fence work wait for quorum");
		goto out_fipu;
	}

	/*
	 * startup fencing
	 */

	list_for_each_entry_safe(node, safe, &startup_nodes, list) {
		if (is_clean_daemon_member(node->nodeid)) {
			log_debug("fence startup %d member skip", node->nodeid);
			list_del(&node->list);
			free(node);
			continue;
		}

		if (!cfgd_enable_startup_fencing)
			continue;

		if (monotime() - daemon_last_join_monotime < cfgd_post_join_delay) {
			log_debug("fence startup %d delay %d from %llu",
				  node->nodeid, cfgd_post_join_delay,
				  (unsigned long long)daemon_last_join_monotime);
			poll_fencing++;
			continue;
		}

		/* clear this entry and create a daemon_nodes entry with
		   need_fencing and the fence loops below will handle it */

		nodeid = node->nodeid;
		list_del(&node->list);
		free(node);

		node = add_node_daemon(nodeid);
		if (!node) {
			log_debug("fence startup %d add failed", nodeid);
			continue;
		}
		if (node->need_fencing) {
			/* don't think this should happen? */
			log_error("fence startup %d already set", nodeid);
			continue;
		}
		node->need_fencing = 1;
		node->fence_config.pos = 0;
		node->left_reason = REASON_STARTUP_FENCING;
		node->fail_monotime = cluster_joined_monotime - 1;
		node->fail_walltime = cluster_joined_walltime - 1;
		node->fence_monotime = 0;
		node->fence_walltime = 0;
		node->fence_request_time = 0;
		low = set_fence_actors(node, 1);

		log_debug("fence startup nodeid %d act %d", node->nodeid, low);
	}

	/*
	 * request fencing
	 */

	list_for_each_entry(node, &daemon_nodes, list) {
		if (!node->need_fencing)
			continue;

		if (node->fence_pid_wait)
			continue;

		if (is_clean_daemon_member(node->nodeid)) {
			/* node rejoined cleanly, doesn't need fencing */
			log_debug("fence request %d member skip", node->nodeid);
			node->need_fencing = 0;
			node->fence_walltime = time(NULL);
			node->fence_monotime = monotime();
			continue;
		}

		/*
		if (daemon_pid_wait) {
			log_debug("fence request %d delay for other pid %d",
				  node->nodeid, daemon_pid_wait);
			node->delay_fencing = 1;
			poll_fencing++;
			continue;
		}
		*/

		if (monotime() - cluster_last_join_monotime < cfgd_post_join_delay) {
			log_debug("fence request %d delay %d from %llu",
				  node->nodeid, cfgd_post_join_delay,
				  (unsigned long long)cluster_last_join_monotime);
			node->delay_fencing = 1;
			poll_fencing++;
			continue;
		}
		node->delay_fencing = 0;

		/* get_fence_actor picks the low nodeid that existed
		   when node failed and is still around.  if the current
		   actor fails, get_fence_actor will not find it in the
		   members list, will clear it, and return the next actor */

		actor = get_fence_actor(node);

		if (!actor) {
			log_error("fence request %d no actor", node->nodeid);
			continue;
		}

		if (actor != our_nodeid) {
			log_debug("fence request %d defer to %d",
				  node->nodeid, actor);
			continue;
		}

		log_debug("fence request %d", node->nodeid);

		rv = fence_request(node->nodeid,
				   node->fail_walltime, node->fail_monotime,
				   &node->fence_config, &pid);
		if (rv < 0) {
			send_fence_result(node->nodeid, rv, 0, time(NULL));
			continue;
		}

		node->fence_pid_wait = 1;
		node->fence_pid = pid;
		node->fence_request_time = monotime();
	}

	/*
	 * check outstanding fence requests
	 */

	list_for_each_entry(node, &daemon_nodes, list) {
		if (!node->need_fencing)
			continue;

		if (node->delay_fencing)
			continue;

		if (!node->fence_pid_wait) {
			/*
			 * another node is the actor, or we were actor,
			 * sent done msg and are waiting to recv it
			 */
			log_debug("fence wait %d for done", node->nodeid);
			continue;
		}

		if (is_clean_daemon_member(node->nodeid)) {
			/*
			 * node has rejoined in clean state so we can
			 * abort outstanding fence op for it.  all nodes
			 * will see and do this, so we don't need to send
			 * a fence result.
			 */
			log_debug("fence wait %d member skip", node->nodeid);
			node->need_fencing = 0;
			node->fence_walltime = time(NULL);
			node->fence_monotime = monotime();
			fence_pid_cancel(node->nodeid, node->fence_pid);
			continue;
		}

		poll_fencing++;

		rv = fence_result(node->nodeid, node->fence_pid, &result);
		if (rv == -EAGAIN) {
			/* agent pid is still running */
			log_debug("fence wait %d pid %d running",
				  node->nodeid, node->fence_pid);
			continue;
		}

		if (rv < 0) {
			/* shouldn't happen */
			log_error("fence wait %d pid %d error %d",
				  node->nodeid, node->fence_pid, rv);
			node->fence_pid_wait = 0;
			continue;
		}

		if (!result) {
			/* agent exit 0, if there's another agent to run in
			   parallel, set it to run next, otherwise success */

			log_debug("fence nodeid %d pid %d succeeded",
				  node->nodeid, node->fence_pid);

			node->fence_pid_wait = 0;
			node->fence_pid = 0;

			rv = fence_config_next_parallel(&node->fence_config);
			if (rv < 0)
				send_fence_result(node->nodeid, 0, 0, time(NULL));
		} else {
			/* agent exit 1, if there's another agent to run at
			   next priority, set it to run next, otherwise fail */

			log_debug("fence nodeid %d pid %d failed %d",
				  node->nodeid, node->fence_pid, result);

			node->fence_pid_wait = 0;
			node->fence_pid = 0;

			rv = fence_config_next_priority(&node->fence_config);
			if (rv < 0)
				send_fence_result(node->nodeid, result, 0, time(NULL));
		}
	}

	/*
	 * clear fence_in_progress_unknown
	 */
 out_fipu:
	need = nodes_need_fencing();

	if (cfgd_enable_startup_fencing && fence_in_progress_unknown && !need && list_empty(&startup_nodes)) {
		/*
		 * case A in comment above
		 * all nodes are starting and have fipu set, they all do
		 * startup fencing, and eventually see unknown nodes become
		 * members or get fenced, so all clear fipu for themselves.
		 */
		fence_in_progress_unknown = 0;
		log_debug("fence_in_progress_unknown 0 startup");
	}

	if (!fence_in_progress_unknown) {
		/*
		 * case B in comment above
		 * some cur nodes have fipu clear, new nodes have fipu set.
		 * A current node needs to send_fence_clear to the new nodes
		 * once all fencing is done so they clear fipu.
		 */
		low = 0;

		list_for_each_entry(node, &daemon_nodes, list) {
			if (!node->daemon_member || node->need_fence_clear)
				continue;
			if (!low || node->nodeid < low)
				low = node->nodeid;
		}

		list_for_each_entry(node, &daemon_nodes, list) {
			if (!node->daemon_member || !node->need_fence_clear)
				continue;
			if (node->nodeid == our_nodeid) {
				node->need_fence_clear = 0;
				continue;
			}
			if (low != our_nodeid)
				continue;

			flags = 0;

			if (node->need_fence_clear & FR_CLEAR_STARTUP) {
				flags |= FR_CLEAR_STARTUP;
				node->need_fence_clear &= ~FR_CLEAR_STARTUP;
			}

			if ((node->need_fence_clear & FR_CLEAR_FIPU) && !need) {
				flags |= FR_CLEAR_FIPU;
				node->need_fence_clear &= ~FR_CLEAR_FIPU;
			}

			if (!flags)
				continue;

			send_fence_clear(node->nodeid, 0, flags, 0);
		}
	}

	if (!cfgd_enable_startup_fencing && fence_in_progress_unknown) {
		/*
		 * case C in comment above
		 * all nodes are starting and have fipu set.  All expect a
		 * previous node to send_fence_clear so they can clear fipu.
		 * But there are no previous nodes. They need to detect this
		 * condition.  Each node does send_fence_clear(ENODATA,FIPU).
		 * When all have received this from all, condition is
		 * detected and all clear fipu.
		 */
		if (all_daemon_members_fipu()) {
			fence_in_progress_unknown = 0;
			log_debug("fence_in_progress_unknown 0 all_fipu");
		} else if (last_join_seq > send_fipu_seq) {
			/* the seq numbers keep us from spamming this msg */
			send_fence_clear(our_nodeid, -ENODATA, FR_FIPU, 0);
			log_debug("send_fence_clear %d fipu", our_nodeid);
			send_fipu_seq = last_join_seq;
		}
	}

	/*
	 * clean up a zombie pid from an agent we killed
	 */

	if (daemon_clear_pid)
		fence_pid_cancel(daemon_clear_nodeid, daemon_clear_pid);
}

void process_fencing_changes(void)
{
	poll_fencing = 0;
	daemon_fence_work();
}

static void receive_fence_clear(struct dlm_header *hd, int len)
{
	struct fence_result *fr;
	struct node_daemon *node;
	int count;

	fr = (struct fence_result *)((char *)hd + sizeof(struct dlm_header));

	fr->flags          = le32_to_cpu(fr->flags);
	fr->nodeid         = le32_to_cpu(fr->nodeid);
	fr->result         = le32_to_cpu(fr->result);
	fr->fence_walltime = le64_to_cpu(fr->fence_walltime);

	if (len < sizeof(struct dlm_header) + sizeof(struct fence_result)) {
		log_error("receive_fence_clear invalid len %d from %d",
			  len, hd->nodeid);
		return;
	}

	node = get_node_daemon(fr->nodeid);
	if (!node) {
		log_error("receive_fence_clear from %d no daemon node %d",
			  hd->nodeid, fr->nodeid);
		return;
	}

	log_debug("receive_fence_clear from %d for %d result %d flags %x",
		  hd->nodeid, fr->nodeid, fr->result, fr->flags);

	/*
	 * A node sends this message about itself indicating that it's in
	 * startup with fipu set.  The only time we care about node->fipu
	 * is when all nodes are fipu in startup. node->need_fence_clear
	 * and node->fipu are not related, they address different cases.
	 */
	if ((fr->result == -ENODATA) && (fr->flags & FR_FIPU)) {
		if (!fence_in_progress_unknown)
			return;

		node->fence_in_progress_unknown = 1;
		return;
	}

	/*
	 * An previous member sends this to new members to tell them that
	 * they can clear startup_nodes and clear fipu.  These two flags
	 * may come in separate messages if there is a pending fencing op
	 * when the new member joins (CLEAR_STARTUP will come right away,
	 * but CLEAR_FIPU will come once the fencing op is done.)
	 */
	if (!fr->result && (node->nodeid == our_nodeid)) {
		if ((fr->flags & FR_CLEAR_STARTUP) && !list_empty(&startup_nodes)) {
			count = clear_startup_node(0, 1);
			log_debug("clear_startup_nodes %d", count);
		}

		if ((fr->flags & FR_CLEAR_FIPU) && fence_in_progress_unknown) {
			fence_in_progress_unknown = 0;
			log_debug("fence_in_progress_unknown 0 recv");
		}
	}

	/* this node doesn't need these flags any more */
	if (!fr->result) {
		if (fr->flags & FR_CLEAR_STARTUP)
			node->need_fence_clear &= ~FR_CLEAR_STARTUP;
		if (fr->flags & FR_CLEAR_FIPU)
			node->need_fence_clear &= ~FR_CLEAR_FIPU;
	}
}

static void send_fence_clear(int nodeid, int result, uint32_t flags, uint64_t walltime)
{
	struct dlm_header *hd;
	struct fence_result *fr;
	char *buf;
	int len;

	len = sizeof(struct dlm_header) + sizeof(struct fence_result);
	buf = malloc(len);
	if (!buf) {
		log_error("send_fence_clear no mem %d", len);
		return;
	}
	memset(buf, 0, len);

	hd = (struct dlm_header *)buf;
	fr = (struct fence_result *)(buf + sizeof(*hd));

	hd->type = cpu_to_le16(DLM_MSG_FENCE_CLEAR);
	hd->nodeid = cpu_to_le32(our_nodeid);

	fr->flags          = cpu_to_le32(flags);
	fr->nodeid         = cpu_to_le32(nodeid);
	fr->result         = cpu_to_le32(result);
	fr->fence_walltime = cpu_to_le64(walltime);

	_send_message(cpg_handle_daemon, buf, len, DLM_MSG_FENCE_CLEAR);
}

static void receive_fence_result(struct dlm_header *hd, int len)
{
	struct fence_result *fr;
	struct node_daemon *node;
	int count;

	fr = (struct fence_result *)((char *)hd + sizeof(struct dlm_header));

	fr->flags          = le32_to_cpu(fr->flags);
	fr->nodeid         = le32_to_cpu(fr->nodeid);
	fr->result         = le32_to_cpu(fr->result);
	fr->fence_walltime = le64_to_cpu(fr->fence_walltime);

	if (len < sizeof(struct dlm_header) + sizeof(struct fence_result)) {
		log_error("receive_fence_result invalid len %d from %d",
			  len, hd->nodeid);
		return;
	}

	count = clear_startup_node(fr->nodeid, 0);
	if (count) {
		log_debug("receive_fence_result from %d for %d clear startup",
			  hd->nodeid, fr->nodeid);
	}

	node = get_node_daemon(fr->nodeid);
	if (!node) {
		log_error("receive_fence_result from %d for %d no daemon node",
			  hd->nodeid, fr->nodeid);
		return;
	}

	log_debug("receive_fence_result from %d for %d result %d walltime %llu",
		  hd->nodeid, fr->nodeid, fr->result,
		  (unsigned long long)fr->fence_walltime);

	if (!node->need_fencing) {
		/* should never happen */
		log_error("receive_fence_result from %d for %d result %d no need_fencing",
		  	  hd->nodeid, fr->nodeid, fr->result);
		return;
	}

	if (fr->result == -ECANCELED) {
		/* if an agent pid is running, kill it and clean up */
		if (node->fence_pid_wait && node->fence_pid)
			fence_pid_cancel(node->nodeid, node->fence_pid);
		fr->result = 0; /* force success below */
	}

	if (!fr->result) {
		node->need_fencing = 0;
		node->fence_walltime = fr->fence_walltime;
		node->fence_monotime = monotime();
		node->fence_actor_done = hd->nodeid;
	} else {
		clear_fence_actor(fr->nodeid, hd->nodeid);
	}
}

static void send_fence_result(int nodeid, int result, uint32_t flags, uint64_t walltime)
{
	struct dlm_header *hd;
	struct fence_result *fr;
	char *buf;
	int len;

	len = sizeof(struct dlm_header) + sizeof(struct fence_result);
	buf = malloc(len);
	if (!buf) {
		log_error("send_fence_result no mem %d", len);
		return;
	}
	memset(buf, 0, len);

	hd = (struct dlm_header *)buf;
	fr = (struct fence_result *)(buf + sizeof(*hd));

	hd->type = cpu_to_le16(DLM_MSG_FENCE_RESULT);
	hd->nodeid = cpu_to_le32(our_nodeid);

	fr->flags          = cpu_to_le32(flags);
	fr->nodeid         = cpu_to_le32(nodeid);
	fr->result         = cpu_to_le32(result);
	fr->fence_walltime = cpu_to_le64(walltime);

	_send_message(cpg_handle_daemon, buf, len, DLM_MSG_FENCE_RESULT);
}

void fence_ack_node(int nodeid)
{
	send_fence_result(nodeid, -ECANCELED, 0, time(NULL));
}

void set_protocol_stateful(void)
{
	our_protocol.dr_ver.flags |= PV_STATEFUL;
}

static void pv_in(struct protocol_version *pv)
{
	pv->major = le16_to_cpu(pv->major);
	pv->minor = le16_to_cpu(pv->minor);
	pv->patch = le16_to_cpu(pv->patch);
	pv->flags = le16_to_cpu(pv->flags);
}

static void pv_out(struct protocol_version *pv)
{
	pv->major = cpu_to_le16(pv->major);
	pv->minor = cpu_to_le16(pv->minor);
	pv->patch = cpu_to_le16(pv->patch);
	pv->flags = cpu_to_le16(pv->flags);
}

static void protocol_in(struct protocol *proto)
{
	pv_in(&proto->dm_ver);
	pv_in(&proto->km_ver);
	pv_in(&proto->dr_ver);
	pv_in(&proto->kr_ver);
}

static void protocol_out(struct protocol *proto)
{
	pv_out(&proto->dm_ver);
	pv_out(&proto->km_ver);
	pv_out(&proto->dr_ver);
	pv_out(&proto->kr_ver);
}

/* go through member list saved in last confchg, see if we have received a
   proto message from each */

static int all_protocol_messages(void)
{
	struct node_daemon *node;
	int i;

	if (!daemon_member_count)
		return 0;

	for (i = 0; i < daemon_member_count; i++) {
		node = get_node_daemon(daemon_member[i].nodeid);
		if (!node) {
			log_error("all_protocol_messages no node %d",
				  daemon_member[i].nodeid);
			return 0;
		}

		if (!node->proto.daemon_max[0])
			return 0;
	}
	return 1;
}

static int pick_min_protocol(struct protocol *proto)
{
	uint16_t mind[4];
	uint16_t mink[4];
	struct node_daemon *node;
	int i;

	memset(&mind, 0, sizeof(mind));
	memset(&mink, 0, sizeof(mink));

	/* first choose the minimum major */

	for (i = 0; i < daemon_member_count; i++) {
		node = get_node_daemon(daemon_member[i].nodeid);
		if (!node) {
			log_error("pick_min_protocol no node %d",
				  daemon_member[i].nodeid);
			return -1;
		}

		if (!mind[0] || node->proto.daemon_max[0] < mind[0])
			mind[0] = node->proto.daemon_max[0];

		if (!mink[0] || node->proto.kernel_max[0] < mink[0])
			mink[0] = node->proto.kernel_max[0];
	}

	if (!mind[0] || !mink[0]) {
		log_error("pick_min_protocol zero major number");
		return -1;
	}

	/* second pick the minimum minor with the chosen major */

	for (i = 0; i < daemon_member_count; i++) {
		node = get_node_daemon(daemon_member[i].nodeid);
		if (!node)
			continue;

		if (mind[0] == node->proto.daemon_max[0]) {
			if (!mind[1] || node->proto.daemon_max[1] < mind[1])
				mind[1] = node->proto.daemon_max[1];
		}

		if (mink[0] == node->proto.kernel_max[0]) {
			if (!mink[1] || node->proto.kernel_max[1] < mink[1])
				mink[1] = node->proto.kernel_max[1];
		}
	}

	if (!mind[1] || !mink[1]) {
		log_error("pick_min_protocol zero minor number");
		return -1;
	}

	/* third pick the minimum patch with the chosen major.minor */

	for (i = 0; i < daemon_member_count; i++) {
		node = get_node_daemon(daemon_member[i].nodeid);
		if (!node)
			continue;

		if (mind[0] == node->proto.daemon_max[0] &&
		    mind[1] == node->proto.daemon_max[1]) {
			if (!mind[2] || node->proto.daemon_max[2] < mind[2])
				mind[2] = node->proto.daemon_max[2];
		}

		if (mink[0] == node->proto.kernel_max[0] &&
		    mink[1] == node->proto.kernel_max[1]) {
			if (!mink[2] || node->proto.kernel_max[2] < mink[2])
				mink[2] = node->proto.kernel_max[2];
		}
	}

	if (!mind[2] || !mink[2]) {
		log_error("pick_min_protocol zero patch number");
		return -1;
	}

	memcpy(&proto->daemon_run, &mind, sizeof(mind));
	memcpy(&proto->kernel_run, &mink, sizeof(mink));
	return 0;
}

static void receive_protocol(struct dlm_header *hd, int len)
{
	struct protocol *p;
	struct node_daemon *node;
	int new = 0;

	p = (struct protocol *)((char *)hd + sizeof(struct dlm_header));
	protocol_in(p);

	if (len < sizeof(struct dlm_header) + sizeof(struct protocol)) {
		log_error("receive_protocol invalid len %d from %d",
			  len, hd->nodeid);
		return;
	}

	/* zero is an invalid version value */

	if (!p->daemon_max[0] || !p->daemon_max[1] || !p->daemon_max[2] ||
	    !p->kernel_max[0] || !p->kernel_max[1] || !p->kernel_max[2]) {
		log_error("receive_protocol invalid max value from %d "
			  "daemon %u.%u.%u kernel %u.%u.%u", hd->nodeid,
			  p->daemon_max[0], p->daemon_max[1], p->daemon_max[2],
			  p->kernel_max[0], p->kernel_max[1], p->kernel_max[2]);
		return;
	}

	/* the run values will be zero until a version is set, after
	   which none of the run values can be zero */

	if (p->daemon_run[0] && (!p->daemon_run[1] || !p->daemon_run[2] ||
	    !p->kernel_run[0] || !p->kernel_run[1] || !p->kernel_run[2])) {
		log_error("receive_protocol invalid run value from %d "
			  "daemon %u.%u.%u kernel %u.%u.%u", hd->nodeid,
			  p->daemon_run[0], p->daemon_run[1], p->daemon_run[2],
			  p->kernel_run[0], p->kernel_run[1], p->kernel_run[2]);
		return;
	}

	/* save this node's proto so we can tell when we've got all, and
	   use it to select a minimum protocol from all */

	node = get_node_daemon(hd->nodeid);
	if (!node) {
		log_error("receive_protocol no node %d", hd->nodeid);
		return;
	}

	if (!node->daemon_member) {
		log_error("receive_protocol node %d not member", hd->nodeid);
		return;
	}

	log_debug("receive_protocol %d max %u.%u.%u.%x run %u.%u.%u.%x",
		  hd->nodeid,
		  p->daemon_max[0], p->daemon_max[1],
		  p->daemon_max[2], p->daemon_max[3],
		  p->daemon_run[0], p->daemon_run[1],
		  p->daemon_run[2], p->daemon_run[3]);

	if (memcmp(&node->proto, p, sizeof(struct protocol))) {
		log_debug("daemon node %d prot max %u.%u.%u.%x run %u.%u.%u.%x",
			  hd->nodeid,
			  node->proto.daemon_max[0], node->proto.daemon_max[1],
			  node->proto.daemon_max[2], node->proto.daemon_max[3],
			  node->proto.daemon_run[0], node->proto.daemon_run[1],
			  node->proto.daemon_run[2], node->proto.daemon_run[3]);
		new = 1;
	}

	/* checking zero node->daemon_max[0] is a way to tell if we've received
	   an acceptable (non-stateful) proto message from the node since we
	   saw it join the daemon cpg */

	if (hd->nodeid != our_nodeid &&
	    !node->proto.daemon_max[0] &&
	    (p->dr_ver.flags & PV_STATEFUL) &&
	    (our_protocol.dr_ver.flags & PV_STATEFUL)) {

		log_debug("daemon node %d stateful merge", hd->nodeid);
		log_debug("daemon node %d join %llu left %llu local quorum %llu",
			  hd->nodeid,
			  (unsigned long long)node->daemon_add_time,
			  (unsigned long long)node->daemon_rem_time,
			  (unsigned long long)cluster_quorate_monotime);

		if (cluster_quorate && node->daemon_rem_time &&
		    cluster_quorate_monotime < node->daemon_rem_time) {
			log_debug("daemon node %d kill due to stateful merge", hd->nodeid);
			if (!node->killed)
				kick_node_from_cluster(hd->nodeid);
			node->killed = 1;
		}

		/* don't save p->proto into node->proto; we need to come
		   through here based on zero daemon_max[0] for other proto
		   messages like this one from the same node */

		return;
	}

	if (new) {
		memcpy(&node->proto, p, sizeof(struct protocol));

		log_debug("daemon node %d save max %u.%u.%u.%x run %u.%u.%u.%x",
			  node->nodeid,
			  node->proto.daemon_max[0], node->proto.daemon_max[1],
			  node->proto.daemon_max[2], node->proto.daemon_max[3],
			  node->proto.daemon_run[0], node->proto.daemon_run[1],
			  node->proto.daemon_run[2], node->proto.daemon_run[3]);
	}

	/* if we have zero run values, and this msg has non-zero run values,
	   then adopt them as ours; otherwise save this proto message */

	if (our_protocol.daemon_run[0])
		return;

	if (p->daemon_run[0]) {
		our_protocol.daemon_run[0] = p->daemon_run[0];
		our_protocol.daemon_run[1] = p->daemon_run[1];
		our_protocol.daemon_run[2] = p->daemon_run[2];

		our_protocol.kernel_run[0] = p->kernel_run[0];
		our_protocol.kernel_run[1] = p->kernel_run[1];
		our_protocol.kernel_run[2] = p->kernel_run[2];

		log_debug("run protocol from nodeid %d", hd->nodeid);
	}
}

static void send_protocol(struct protocol *proto)
{
	struct dlm_header *hd;
	struct protocol *pr;
	char *buf;
	int len;

	len = sizeof(struct dlm_header) + sizeof(struct protocol);
	buf = malloc(len);
	if (!buf) {
		log_error("send_protocol no mem %d", len);
		return;
	}
	memset(buf, 0, len);

	hd = (struct dlm_header *)buf;
	pr = (struct protocol *)(buf + sizeof(*hd));

	hd->type = cpu_to_le16(DLM_MSG_PROTOCOL);
	hd->nodeid = cpu_to_le32(our_nodeid);

	memcpy(pr, proto, sizeof(struct protocol));
	protocol_out(pr);

	_send_message(cpg_handle_daemon, buf, len, DLM_MSG_PROTOCOL);
}

int set_protocol(void)
{
	struct protocol proto;
	struct pollfd pollfd;
	int sent_proposal = 0;
	int rv;

	memset(&pollfd, 0, sizeof(pollfd));
	pollfd.fd = cpg_fd_daemon;
	pollfd.events = POLLIN;

	while (1) {
		if (our_protocol.daemon_run[0])
			break;

		if (!sent_proposal && all_protocol_messages()) {
			/* propose a protocol; look through info from all
			   nodes and pick the min for both daemon and kernel,
			   and propose that */

			sent_proposal = 1;

			/* copy our max values */
			memcpy(&proto, &our_protocol, sizeof(struct protocol));

			rv = pick_min_protocol(&proto);
			if (rv < 0)
				return rv;

			log_debug("set_protocol member_count %d propose "
				  "daemon %u.%u.%u kernel %u.%u.%u",
				  daemon_member_count,
				  proto.daemon_run[0], proto.daemon_run[1],
				  proto.daemon_run[2], proto.kernel_run[0],
				  proto.kernel_run[1], proto.kernel_run[2]);

			send_protocol(&proto);
		}

		/* only process messages/events from daemon cpg until protocol
		   is established */

		rv = poll(&pollfd, 1, -1);
		if (rv == -1 && errno == EINTR) {
			if (daemon_quit)
				return -1;
			continue;
		}
		if (rv < 0) {
			log_error("set_protocol poll errno %d", errno);
			return -1;
		}

		if (pollfd.revents & POLLIN)
			process_cpg_daemon(0);
		if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			log_error("set_protocol poll revents %u",
				  pollfd.revents);
			return -1;
		}
	}

	if (our_protocol.daemon_run[0] != our_protocol.daemon_max[0] ||
	    our_protocol.daemon_run[1] > our_protocol.daemon_max[1]) {
		log_error("incompatible daemon protocol run %u.%u.%u max %u.%u.%u",
			our_protocol.daemon_run[0],
			our_protocol.daemon_run[1],
			our_protocol.daemon_run[2],
			our_protocol.daemon_max[0],
			our_protocol.daemon_max[1],
			our_protocol.daemon_max[2]);
		return -1;
	}

	if (our_protocol.kernel_run[0] != our_protocol.kernel_max[0] ||
	    our_protocol.kernel_run[1] > our_protocol.kernel_max[1]) {
		log_error("incompatible kernel protocol run %u.%u.%u max %u.%u.%u",
			our_protocol.kernel_run[0],
			our_protocol.kernel_run[1],
			our_protocol.kernel_run[2],
			our_protocol.kernel_max[0],
			our_protocol.kernel_max[1],
			our_protocol.kernel_max[2]);
		return -1;
	}

	log_debug("daemon run %u.%u.%u max %u.%u.%u "
		  "kernel run %u.%u.%u max %u.%u.%u",
		  our_protocol.daemon_run[0],
		  our_protocol.daemon_run[1],
		  our_protocol.daemon_run[2],
		  our_protocol.daemon_max[0],
		  our_protocol.daemon_max[1],
		  our_protocol.daemon_max[2],
		  our_protocol.kernel_run[0],
		  our_protocol.kernel_run[1],
		  our_protocol.kernel_run[2],
		  our_protocol.kernel_max[0],
		  our_protocol.kernel_max[1],
		  our_protocol.kernel_max[2]);

	send_protocol(&our_protocol);
	return 0;
}

static void deliver_cb_daemon(cpg_handle_t handle,
			      const struct cpg_name *group_name,
			      uint32_t nodeid, uint32_t pid,
			      void *data, size_t len)
{
	struct dlm_header *hd;

	if (len < sizeof(*hd)) {
		log_error("deliver_cb short message %zd", len);
		return;
	}

	hd = (struct dlm_header *)data;
	dlm_header_in(hd);

	switch (hd->type) {
	case DLM_MSG_PROTOCOL:
		receive_protocol(hd, len);
		break;
	case DLM_MSG_FENCE_RESULT:
		receive_fence_result(hd, len);
		break;
	case DLM_MSG_FENCE_CLEAR:
		receive_fence_clear(hd, len);
		break;
	default:
		log_error("deliver_cb_daemon unknown msg type %d", hd->type);
	}

	daemon_fence_work();
}

static void confchg_cb_daemon(cpg_handle_t handle,
			      const struct cpg_name *group_name,
			      const struct cpg_address *member_list,
			      size_t member_list_entries,
			      const struct cpg_address *left_list,
			      size_t left_list_entries,
			      const struct cpg_address *joined_list,
			      size_t joined_list_entries)
{
	struct node_daemon *node;
	uint64_t now, now_wall;
	int nodedown = 0, procdown = 0, leave = 0;
	int we_joined = 0;
	int i, reason, low;

	now = monotime();
	now_wall = time(NULL);

	log_config(group_name, member_list, member_list_entries,
		   left_list, left_list_entries,
		   joined_list, joined_list_entries);

	memset(&daemon_member, 0, sizeof(daemon_member));
	daemon_member_count = member_list_entries;

	for (i = 0; i < member_list_entries; i++) {
		daemon_member[i] = member_list[i];
		/* add struct for nodes we've not seen before */
		add_node_daemon(member_list[i].nodeid);
	}

	memset(&daemon_joined, 0, sizeof(daemon_joined));
	daemon_joined_count = joined_list_entries;

	for (i = 0; i < joined_list_entries; i++) {
		daemon_joined[i] = joined_list[i];
		if (joined_list[i].nodeid == our_nodeid)
			we_joined = 1;
	}

	memset(&daemon_remove, 0, sizeof(daemon_remove));
	daemon_remove_count = left_list_entries;

	for (i = 0; i < left_list_entries; i++) {
		daemon_remove[i] = left_list[i];

		if (left_list[i].reason == CPG_REASON_NODEDOWN)
			nodedown++;
		else if (left_list[i].reason == CPG_REASON_PROCDOWN)
			procdown++;
		else if (left_list[i].reason == CPG_REASON_LEAVE)
			leave++;
	}

	if (nodedown || procdown || leave)
		log_debug("%s left nodedown %d procdown %d leave %d",
			  group_name->value, nodedown, procdown, leave);

	if (nodedown)
		daemon_ringid_wait = 1;

	if (joined_list_entries)
		send_protocol(&our_protocol);

	list_for_each_entry(node, &daemon_nodes, list) {
		if (in_daemon_list(node->nodeid, daemon_member, daemon_member_count)) {
			if (node->daemon_member)
				continue;

			/* node joined daemon cpg */
			node->daemon_member = 1;
			node->daemon_add_time = now;

			daemon_last_join_monotime = now;
			last_join_seq++;

			/* a joining node shows prev members in joined list */
			if (!we_joined)
				node->need_fence_clear = FR_CLEAR_STARTUP|FR_CLEAR_FIPU;

			if (node->need_fencing) {
				/* need_fencing will be cleared if we accept a
				   valid proto from it */
				log_error("daemon new nodeid %d needs fencing",
					  node->nodeid);
			}

		} else {
			if (!node->daemon_member)
				continue;

			/* node left daemon cpg */
			node->daemon_member = 0;
			node->killed = 0;
			memset(&node->proto, 0, sizeof(struct protocol));
			node->daemon_rem_time = now;

			/* tell loop below to look at this node */
			node->recover_setup = 1;
		}
	}

	/* set up recovery work for nodes that just failed */

	/* TODO: limit to nodes with a valid proto?
	 * node_history_lockspace_fail() would only set
	 * need_fencing if node->start_time was non-zero. */

	list_for_each_entry(node, &daemon_nodes, list) {
		if (!node->recover_setup)
			continue;

		node->recover_setup = 0;
		reason = 0;
		low = 0;

		if (!cfgd_enable_fencing)
			continue;

		if (node->need_fencing) {
			log_error("daemon remove nodeid %d already needs fencing",
				  node->nodeid);
			continue;
		}

		for (i = 0; i < left_list_entries; i++) {
			if (left_list[i].nodeid != node->nodeid)
				continue;
			reason = left_list[i].reason;
			break;
		}

		if (reason == CPG_REASON_NODEDOWN || reason == CPG_REASON_PROCDOWN) {
			node->need_fencing = 1;
			node->fence_config.pos = 0;
			node->left_reason = reason;
			node->fail_monotime = now;
			node->fail_walltime = now_wall;
			node->fence_monotime = 0;
			node->fence_walltime = 0;
			node->fence_request_time = 0;
			low = set_fence_actors(node, 0);
		}

		log_debug("daemon remove %d %s need_fencing %d low %d",
			  node->nodeid, reason_str(reason), node->need_fencing, low);
	}

	daemon_fence_work();
}

static void totem_cb_daemon(cpg_handle_t handle,
                            struct cpg_ring_id ring_id,
                            uint32_t member_list_entries,
                            const uint32_t *member_list)
{
	daemon_ringid.nodeid = ring_id.nodeid;
	daemon_ringid.seq = ring_id.seq;
	daemon_ringid_wait = 0;

	log_ringid("dlm:controld", &ring_id, member_list, member_list_entries);

	daemon_fence_work();
}

static cpg_model_v1_data_t cpg_callbacks_daemon = {
	.cpg_deliver_fn = deliver_cb_daemon,
	.cpg_confchg_fn = confchg_cb_daemon,
	.cpg_totem_confchg_fn = totem_cb_daemon,
	.flags = CPG_MODEL_V1_DELIVER_INITIAL_TOTEM_CONF,
};

void process_cpg_daemon(int ci)
{
	cs_error_t error;

	error = cpg_dispatch(cpg_handle_daemon, CS_DISPATCH_ALL);
	if (error != CS_OK)
		log_error("daemon cpg_dispatch error %d", error);
}

int setup_cpg_daemon(void)
{
	cs_error_t error;
	struct cpg_name name;
	int i = 0;

	/* daemon 1.1.1 was cluster3/STABLE3/RHEL6 which is incompatible
	   with cluster4/RHEL7 */ 

	memset(&our_protocol, 0, sizeof(our_protocol));

	if (cfgd_enable_fscontrol)
		our_protocol.daemon_max[0] = 2;
	else
		our_protocol.daemon_max[0] = 3;

	our_protocol.daemon_max[1] = 1;
	our_protocol.daemon_max[2] = 1;
	our_protocol.kernel_max[0] = 1;
	our_protocol.kernel_max[1] = 1;
	our_protocol.kernel_max[2] = 1;

	error = cpg_model_initialize(&cpg_handle_daemon, CPG_MODEL_V1,
				     (cpg_model_data_t *)&cpg_callbacks_daemon,
				     NULL);
	if (error != CS_OK) {
		log_error("daemon cpg_initialize error %d", error);
		return -1;
	}

	cpg_fd_get(cpg_handle_daemon, &cpg_fd_daemon);

	memset(&name, 0, sizeof(name));
	sprintf(name.value, "dlm:controld");
	name.length = strlen(name.value) + 1;

	log_debug("cpg_join %s ...", name.value);
 retry:
	error = cpg_join(cpg_handle_daemon, &name);
	if (error == CS_ERR_TRY_AGAIN) {
		sleep(1);
		if (!(++i % 10))
			log_error("daemon cpg_join error retrying");
		goto retry;
	}
	if (error != CS_OK) {
		log_error("daemon cpg_join error %d", error);
		goto fail;
	}

	log_debug("setup_cpg_daemon %d", cpg_fd_daemon);
	return cpg_fd_daemon;

 fail:
	cpg_finalize(cpg_handle_daemon);
	return -1;
}

void close_cpg_daemon(void)
{
	struct lockspace *ls;
	cs_error_t error;
	struct cpg_name name;
	int i = 0;

	if (!cpg_handle_daemon)
		return;
	if (cluster_down)
		goto fin;

	memset(&name, 0, sizeof(name));
	sprintf(name.value, "dlm:controld");
	name.length = strlen(name.value) + 1;

	log_debug("cpg_leave %s ...", name.value);
 retry:
	error = cpg_leave(cpg_handle_daemon, &name);
	if (error == CS_ERR_TRY_AGAIN) {
		sleep(1);
		if (!(++i % 10))
			log_error("daemon cpg_leave error retrying");
		goto retry;
	}
	if (error != CS_OK)
		log_error("daemon cpg_leave error %d", error);
 fin:
	list_for_each_entry(ls, &lockspaces, list) {
		if (ls->cpg_handle)
			cpg_finalize(ls->cpg_handle);
	}
	cpg_finalize(cpg_handle_daemon);
}

void init_daemon(void)
{
	INIT_LIST_HEAD(&daemon_nodes);
	INIT_LIST_HEAD(&startup_nodes);

}

/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

#define log_limit(ls, fmt, args...) ({        \
	static uint32_t __change_nr;          \
	if (ls->change_seq > __change_nr) {   \
		__change_nr = ls->change_seq; \
		log_group(ls, fmt, ##args);   \
	}                                     \
})

/* retries are once a second */
#define log_retry(ls, fmt, args...) ({ \
	if (ls->wait_retry < 60) \
		log_group(ls, fmt, ##args); \
	else if (ls->wait_retry == 60) \
		log_erros(ls, fmt, ##args); \
        else if (!(ls->wait_retry % 3600)) \
                log_erros(ls, fmt, ##args); \
})

/* per lockspace cpg: ls->node_history */

struct node {
	struct list_head list;
	int nodeid;

	uint64_t lockspace_add_time;
	uint64_t lockspace_rem_time;
	uint64_t lockspace_fail_time;
	uint32_t lockspace_add_seq;
	uint32_t lockspace_rem_seq;
	uint32_t lockspace_fail_seq;
	int lockspace_member;
	int lockspace_fail_reason;

	uint32_t last_match_seq;

	uint64_t start_time;

	int check_fs;
	int fs_notified;

	int need_fencing;
	uint32_t fence_queries;	/* for debug */
	uint64_t fail_walltime;
	uint64_t fail_monotime;
};

/* per lockspace confchg: ls->changes */

#define CGST_WAIT_CONDITIONS 1
#define CGST_WAIT_MESSAGES   2

struct change {
	struct list_head list;
	struct list_head members;
	struct list_head removed; /* nodes removed by this change */
	int member_count;
	int joined_count;
	int remove_count;
	int failed_count;
	int state;
	int we_joined;
	uint32_t seq; /* used as a reference for debugging, and for queries */
	uint32_t combined_seq; /* for queries */
	uint64_t create_time;
};

/* per lockspace change member: cg->members */

struct member {
	struct list_head list;
	int nodeid;
	int start;   /* 1 if we received a start message for this change */
	int added;   /* 1 if added by this change */
	int failed;  /* 1 if failed in this change */
	int disallowed;
	uint32_t start_flags;
};

struct ls_info {
	uint32_t ls_info_size;
	uint32_t id_info_size;
	uint32_t id_info_count;

	uint32_t started_count;

	int member_count;
	int joined_count;
	int remove_count;
	int failed_count;
};

struct id_info {
	int nodeid;
};

static void ls_info_in(struct ls_info *li)
{
	li->ls_info_size  = le32_to_cpu(li->ls_info_size);
	li->id_info_size  = le32_to_cpu(li->id_info_size);
	li->id_info_count = le32_to_cpu(li->id_info_count);
	li->started_count = le32_to_cpu(li->started_count);
	li->member_count  = le32_to_cpu(li->member_count);
	li->joined_count  = le32_to_cpu(li->joined_count);
	li->remove_count  = le32_to_cpu(li->remove_count);
	li->failed_count  = le32_to_cpu(li->failed_count);
}

static void id_info_in(struct id_info *id)
{
	id->nodeid = le32_to_cpu(id->nodeid);
}

static void ids_in(struct ls_info *li, struct id_info *ids)
{
	struct id_info *id;
	int i;

	id = ids;
	for (i = 0; i < li->id_info_count; i++) {
		id_info_in(id);
		id = (struct id_info *)((char *)id + li->id_info_size);
	}
}

static struct member *find_memb(struct change *cg, int nodeid)
{
	struct member *memb;

	list_for_each_entry(memb, &cg->members, list) {
		if (memb->nodeid == nodeid)
			return memb;
	}
	return NULL;
}

static struct lockspace *find_ls_handle(cpg_handle_t h)
{
	struct lockspace *ls;

	list_for_each_entry(ls, &lockspaces, list) {
		if (ls->cpg_handle == h)
			return ls;
	}
	return NULL;
}

static struct lockspace *find_ls_ci(int ci)
{
	struct lockspace *ls;

	list_for_each_entry(ls, &lockspaces, list) {
		if (ls->cpg_client == ci)
			return ls;
	}
	return NULL;
}

static void free_cg(struct change *cg)
{
	struct member *memb, *safe;

	list_for_each_entry_safe(memb, safe, &cg->members, list) {
		list_del(&memb->list);
		free(memb);
	}
	list_for_each_entry_safe(memb, safe, &cg->removed, list) {
		list_del(&memb->list);
		free(memb);
	}
	free(cg);
}

static void free_ls(struct lockspace *ls)
{
	struct change *cg, *cg_safe;
	struct node *node, *node_safe;

	list_for_each_entry_safe(cg, cg_safe, &ls->changes, list) {
		list_del(&cg->list);
		free_cg(cg);
	}

	if (ls->started_change)
		free_cg(ls->started_change);

	list_for_each_entry_safe(node, node_safe, &ls->node_history, list) {
		list_del(&node->list);
		free(node);
	}

	free(ls);
}


/* Problem scenario:
   nodes A,B,C are in fence domain
   node C has gfs foo mounted
   node C fails
   nodes A,B begin fencing C (slow, not completed)
   node B mounts gfs foo

   We may end up having gfs foo mounted and being used on B before
   C has been fenced.  C could wake up corrupt fs.

   So, we need to prevent any new gfs mounts while there are any
   outstanding, incomplete fencing operations.

   We also need to check that the specific failed nodes we know about have
   been fenced (since fenced may not even have been notified that the node
   has failed yet).

   So, check that:
   1. has fenced fenced the node since we saw it fail?
   2. fenced has no outstanding fencing ops

   For 1:
   - node X fails
   - we see node X fail and X has non-zero start_time,
     set need_fencing and record the fail time
   - wait for X to be removed from all dlm cpg's  (probably not necessary)
   - check that the fencing time is later than the recorded time above

   Tracking fencing state when there are spurious partitions/merges...

   from a spurious leave/join of node X, a lockspace will see:
   - node X is a lockspace member
   - node X fails, may be waiting for all cpgs to see failure or for fencing to
     complete
   - node X joins the lockspace - we want to process the change as usual, but
     don't want to disrupt the code waiting for the fencing, and we want to
     continue running properly once the remerged node is properly reset

   ls->node_history
   when we see a node not in this list, add entry for it with zero start_time
   record the time we get a good start message from the node, start_time
   clear start_time if the node leaves
   if node fails with non-zero start_time, set need_fencing
   when a node is fenced, clear start_time and clear need_fencing
   if a node remerges after this, no good start message, no new start_time set
   if a node fails with zero start_time, it doesn't need fencing
   if a node remerges before it's been fenced, no good start message, no new
   start_time set 
*/

static struct node *get_node_history(struct lockspace *ls, int nodeid)
{
	struct node *node;

	list_for_each_entry(node, &ls->node_history, list) {
		if (node->nodeid == nodeid)
			return node;
	}
	return NULL;
}

static struct node *get_node_history_create(struct lockspace *ls, int nodeid)
{
	struct node *node;

	node = get_node_history(ls, nodeid);
	if (node)
		return node;

	node = malloc(sizeof(struct node));
	if (!node)
		return NULL;
	memset(node, 0, sizeof(struct node));

	node->nodeid = nodeid;
	list_add_tail(&node->list, &ls->node_history);
	return node;
}

static void node_history_lockspace_add(struct lockspace *ls, int nodeid,
				       struct change *cg, uint64_t now)
{
	struct node *node;

	node = get_node_history_create(ls, nodeid);
	if (!node) {
		log_error("node_history_lockspace_add no nodeid %d", nodeid);
		return;
	}

	node->lockspace_add_time = now;
	node->lockspace_add_seq = cg->seq;
	node->lockspace_member = 1;
}

static void node_history_lockspace_left(struct lockspace *ls, int nodeid,
					struct change *cg, uint64_t now)
{
	struct node *node;

	node = get_node_history(ls, nodeid);
	if (!node) {
		log_error("node_history_lockspace_left no nodeid %d", nodeid);
		return;
	}

	node->start_time = 0;

	node->lockspace_rem_time = now;
	node->lockspace_rem_seq = cg->seq;	/* for queries */
	node->lockspace_member = 0;
}

static void node_history_lockspace_fail(struct lockspace *ls, int nodeid,
					struct change *cg, int reason,
					uint64_t now)
{
	struct node *node;

	node = get_node_history(ls, nodeid);
	if (!node) {
		log_error("node_history_lockspace_fail no nodeid %d", nodeid);
		return;
	}

	if (opt(enable_fencing_ind) && node->start_time) {
		node->need_fencing = 1;
		node->fence_queries = 0;
	}

	if (ls->fs_registered) {
		log_group(ls, "check_fs nodeid %d set", nodeid);
		node->check_fs = 1;
	}

	node->lockspace_rem_time = now;
	node->lockspace_rem_seq = cg->seq;	/* for queries */
	node->lockspace_member = 0;
	node->lockspace_fail_time = now;
	node->lockspace_fail_seq = node->lockspace_rem_seq;
	node->lockspace_fail_reason = reason;	/* for queries */

	node->fail_monotime = now;
	node->fail_walltime = time(NULL);
}

static void node_history_start(struct lockspace *ls, int nodeid)
{
	struct node *node;
	
	node = get_node_history(ls, nodeid);
	if (!node) {
		log_error("node_history_start no nodeid %d", nodeid);
		return;
	}

	node->start_time = monotime();
}

/* wait for cluster ringid and cpg ringid to be the same so we know our
   information from each service is based on the same node state */

static int check_ringid_done(struct lockspace *ls)
{
	/* If we've received a confchg due to a nodedown, but not
	   the corresponding ringid callback, then we should wait
	   for the ringid callback.  Once we have both conf and ring
	   callbacks, we can compare cpg/quorum ringids.
	   
	   Otherwise, there's a possible problem if we receive a
	   confchg before both ringid callback and quorum callback.
	   Then we'd get through this function by comparing the old,
	   matching ringids.

	   (We seem to usually get the quorum callback before any cpg
	   callbacks, in which case we wouldn't need cpg_ringid_wait,
	   but that's probably not guaranteed.) */

	if (ls->cpg_ringid_wait) {
		log_group(ls, "check_ringid wait cluster %u cpg %u:%llu",
			  cluster_ringid_seq, ls->cpg_ringid.nodeid,
			  (unsigned long long)ls->cpg_ringid.seq);
		return 0;
	}

	if (cluster_ringid_seq != (uint32_t)ls->cpg_ringid.seq) {
		log_group(ls, "check_ringid cluster %u cpg %u:%llu",
			  cluster_ringid_seq, ls->cpg_ringid.nodeid,
			  (unsigned long long)ls->cpg_ringid.seq);
		return 0;
	}

	log_limit(ls, "check_ringid done cluster %u cpg %u:%llu",
		  cluster_ringid_seq, ls->cpg_ringid.nodeid,
		  (unsigned long long)ls->cpg_ringid.seq);

	return 1;
}

static int check_fencing_done(struct lockspace *ls)
{
	struct node *node;
	uint64_t fence_monotime;
	int wait_count = 0;
	int rv, in_progress;

	if (!opt(enable_fencing_ind)) {
		log_group(ls, "check_fencing disabled");
		return 1;
	}

	list_for_each_entry(node, &ls->node_history, list) {
		if (!node->need_fencing)
			continue;

		rv = fence_node_time(node->nodeid, &fence_monotime);
		if (rv < 0) {
			log_error("fenced_node_time error %d", rv);
			continue;
		}

		if (fence_monotime >= node->fail_monotime) {
			log_group(ls, "check_fencing %d done start %llu fail %llu fence %llu",
				  node->nodeid,
				  (unsigned long long)node->start_time,
				  (unsigned long long)node->fail_monotime,
				  (unsigned long long)fence_monotime);

			node->need_fencing = 0;
			node->start_time = 0;
			continue;
		} else {
			if (!node->fence_queries) {
				log_group(ls, "check_fencing %d wait start %llu fail %llu",
					  node->nodeid,
					 (unsigned long long)node->start_time,
					 (unsigned long long)node->fail_monotime);
				node->fence_queries++;
			}
			wait_count++;
			continue;
		}
	}

	if (wait_count) {
		log_limit(ls, "check_fencing wait_count %d", wait_count);
		return 0;
	}

	/* now check if there are any outstanding fencing ops (for nodes
	   we may not have seen in any lockspace), and return 0 if there
	   are any */

	rv = fence_in_progress(&in_progress);
	if (rv < 0) {
		log_error("fenced_domain_info error %d", rv);
		return 0;
	}

	if (in_progress) {
		log_limit(ls, "check_fencing in progress %d", in_progress);
		return 0;
	}

	log_group(ls, "check_fencing done");
	return 1;
}

/* wait for local fs_controld to ack each failed node */

static int check_fs_done(struct lockspace *ls)
{
	struct node *node;
	int wait_count = 0;

	/* no corresponding fs for this lockspace */
	if (!ls->fs_registered)
		return 1;

	list_for_each_entry(node, &ls->node_history, list) {
		if (!node->check_fs)
			continue;

		if (node->fs_notified) {
			log_group(ls, "check_fs nodeid %d clear", node->nodeid);
			node->check_fs = 0;
			node->fs_notified = 0;
		} else {
			log_group(ls, "check_fs nodeid %d needs fs notify",
				  node->nodeid);
			wait_count++;
		}
	}

	if (wait_count)
		return 0;

	log_group(ls, "check_fs done");
	return 1;
}

static int member_ids[MAX_NODES];
static int member_count;
static int renew_ids[MAX_NODES];
static int renew_count;

static void format_member_ids(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);
	struct member *memb;

	memset(member_ids, 0, sizeof(member_ids));
	member_count = 0;

	list_for_each_entry(memb, &cg->members, list)
		member_ids[member_count++] = memb->nodeid;
}

/* list of nodeids that have left and rejoined since last start_kernel;
   is any member of startcg in the left list of any other cg's?
   (if it is, then it presumably must be flagged added in another) */

static void format_renew_ids(struct lockspace *ls)
{
	struct change *cg, *startcg;
	struct member *memb, *leftmemb;

	startcg = list_first_entry(&ls->changes, struct change, list);

	memset(renew_ids, 0, sizeof(renew_ids));
	renew_count = 0;

	list_for_each_entry(memb, &startcg->members, list) {
		list_for_each_entry(cg, &ls->changes, list) {
			if (cg == startcg)
				continue;
			list_for_each_entry(leftmemb, &cg->removed, list) {
				if (memb->nodeid == leftmemb->nodeid) {
					renew_ids[renew_count++] = memb->nodeid;
				}
			}
		}
	}

}

static void start_kernel(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);

	if (!ls->kernel_stopped) {
		log_error("start_kernel cg %u not stopped", cg->seq);
		return;
	}

	log_group(ls, "start_kernel cg %u member_count %d",
		  cg->seq, cg->member_count);

	/* needs to happen before setting control which starts recovery */
	if (ls->joining)
		set_sysfs_id(ls->name, ls->global_id);

	if (ls->nodir)
		set_sysfs_nodir(ls->name, 1);

	format_member_ids(ls);
	format_renew_ids(ls);
	set_configfs_members(ls, ls->name, member_count, member_ids,
			     renew_count, renew_ids);
	set_sysfs_control(ls->name, 1);
	ls->kernel_stopped = 0;

	if (ls->joining) {
		set_sysfs_event_done(ls->name, 0);
		ls->joining = 0;
	}
}

static void stop_kernel(struct lockspace *ls, uint32_t seq)
{
	if (!ls->kernel_stopped) {
		log_group(ls, "stop_kernel cg %u", seq);
		set_sysfs_control(ls->name, 0);
		ls->kernel_stopped = 1;
	}
}

/* the first condition is that the local lockspace is stopped which we
   don't need to check for because stop_kernel(), which is synchronous,
   was done when the change was created */

/* the fencing/quorum/fs conditions need to account for all the changes
   that have occured since the last change applied to dlm-kernel, not
   just the latest change */

/* we know that the cluster_quorate value here is consistent with the cpg events
   because the ringid's are in sync per the check_ringid_done */

static int wait_conditions_done(struct lockspace *ls)
{
	if (!check_ringid_done(ls)) {
		if (ls->wait_debug != DLMC_LS_WAIT_RINGID) {
			ls->wait_debug = DLMC_LS_WAIT_RINGID;
			ls->wait_retry = 0;
		}
		ls->wait_retry++;
		/* the check function logs a message */

		poll_lockspaces++;
		return 0;
	}

	if (opt(enable_quorum_lockspace_ind) && !cluster_quorate) {
		if (ls->wait_debug != DLMC_LS_WAIT_QUORUM) {
			ls->wait_debug = DLMC_LS_WAIT_QUORUM;
			ls->wait_retry = 0;
		}
		ls->wait_retry++;
		log_retry(ls, "wait for quorum");

		poll_lockspaces++;
		return 0;
	}

	if (!check_fencing_done(ls)) {
		if (ls->wait_debug != DLMC_LS_WAIT_FENCING) {
			ls->wait_debug = DLMC_LS_WAIT_FENCING;
			ls->wait_retry = 0;
		}
		ls->wait_retry++;
		log_retry(ls, "wait for fencing");

		poll_lockspaces++;
		return 0;
	}

	if (!check_fs_done(ls)) {
		if (ls->wait_debug != DLMC_LS_WAIT_FSDONE) {
			ls->wait_debug = DLMC_LS_WAIT_FSDONE;
			ls->wait_retry = 0;
		}
		ls->wait_retry++;
		log_retry(ls, "wait for fsdone");

		poll_fs++;
		return 0;
	}

	ls->wait_debug = 0;
	ls->wait_retry = 0;

	return 1;
}

static int wait_messages_done(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);
	struct member *memb;
	int need = 0, total = 0;

	list_for_each_entry(memb, &cg->members, list) {
		if (!memb->start)
			need++;
		total++;
	}

	if (need) {
		log_group(ls, "wait_messages cg %u need %d of %d",
			  cg->seq, need, total);
		ls->wait_debug = need;
		return 0;
	}

	log_group(ls, "wait_messages cg %u got all %d", cg->seq, total);

	ls->wait_debug = 0;

	return 1;
}

static void cleanup_changes(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);
	struct change *safe;

	list_del(&cg->list);
	if (ls->started_change)
		free_cg(ls->started_change);
	ls->started_change = cg;

	ls->started_count++;
	if (!ls->started_count)
		ls->started_count++;

	cg->combined_seq = cg->seq; /* for queries */

	list_for_each_entry_safe(cg, safe, &ls->changes, list) {
		ls->started_change->combined_seq = cg->seq; /* for queries */
		list_del(&cg->list);
		free_cg(cg);
	}
}

/* There's a stream of confchg and messages. At one of these
   messages, the low node needs to store plocks and new nodes
   need to begin saving plock messages.  A second message is
   needed to say that the plocks are ready to be read.

   When the last start message is recvd for a change, the low node
   stores plocks and the new nodes begin saving messages.  When the
   store is done, low node sends plocks_stored message.  When
   new nodes recv this, they read the plocks and their saved messages.
   plocks_stored message should identify a specific change, like start
   messages do; if it doesn't match ls->started_change, then it's ignored.

   If a confchg adding a new node arrives after plocks are stored but
   before plocks_stored msg recvd, then the message is ignored.  The low
   node will send another plocks_stored message for the latest change
   (although it may be able to reuse the ckpt if no plock state has changed).
*/

static void set_plock_data_node(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);
	struct member *memb;
	int low = 0;

	list_for_each_entry(memb, &cg->members, list) {
		if (!(memb->start_flags & DLM_MFLG_HAVEPLOCK))
			continue;

		if (!low || memb->nodeid < low)
			low = memb->nodeid;
	}

	log_dlock(ls, "set_plock_data_node from %d to %d",
		  ls->plock_data_node, low);

	ls->plock_data_node = low;
}

static struct id_info *get_id_struct(struct id_info *ids, int count, int size,
				     int nodeid)
{
	struct id_info *id = ids;
	int i;

	for (i = 0; i < count; i++) {
		if (id->nodeid == nodeid)
			return id;
		id = (struct id_info *)((char *)id + size);
	}
	return NULL;
}

/* do the change details in the message match the details of the given change */

static int match_change(struct lockspace *ls, struct change *cg,
			struct dlm_header *hd, struct ls_info *li,
			struct id_info *ids)
{
	struct id_info *id;
	struct member *memb;
	struct node *node;
	uint64_t t;
	uint32_t seq = hd->msgdata;
	int i, members_mismatch;

	/* We can ignore messages if we're not in the list of members.
	   The one known time this will happen is after we've joined
	   the cpg, we can get messages for changes prior to the change
	   in which we're added. */

	id = get_id_struct(ids, li->id_info_count, li->id_info_size,our_nodeid);

	if (!id) {
		log_group(ls, "match_change %d:%u skip %u we are not in members",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	memb = find_memb(cg, hd->nodeid);
	if (!memb) {
		log_group(ls, "match_change %d:%u skip %u sender not member",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	if (memb->start_flags & DLM_MFLG_NACK) {
		log_group(ls, "match_change %d:%u skip %u is nacked",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	if (memb->start && hd->type == DLM_MSG_START) {
		log_group(ls, "match_change %d:%u skip %u already start",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	/* a node's start can't match a change if the node joined the cluster
	   more recently than the change was created */

	node = get_node_history(ls, hd->nodeid);
	if (!node) {
		log_group(ls, "match_change %d:%u skip cg %u no node history",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	t = cluster_add_time(node->nodeid);
	if (t > cg->create_time) {
		log_group(ls, "match_change %d:%u skip cg %u created %llu "
			  "cluster add %llu", hd->nodeid, seq, cg->seq,
			  (unsigned long long)cg->create_time,
			  (unsigned long long)t);

		/* nacks can apply to older cg's */
		if (!(hd->flags & DLM_MFLG_NACK)) {
			return 0;
		} else {
			log_group(ls, "match_change %d:%u unskip cg %u for nack",
				  hd->nodeid, seq, cg->seq);
		}
	}

	if (node->last_match_seq > cg->seq) {
		log_group(ls, "match_change %d:%u skip cg %u last matched cg %u",
			  hd->nodeid, seq, cg->seq, node->last_match_seq);
		return 0;
	}

	/* verify this is the right change by matching the counts
	   and the nodeids of the current members */

	if (li->member_count != cg->member_count ||
	    li->joined_count != cg->joined_count ||
	    li->remove_count != cg->remove_count ||
	    li->failed_count != cg->failed_count) {
		log_group(ls, "match_change %d:%u skip %u expect counts "
			  "%d %d %d %d", hd->nodeid, seq, cg->seq,
			  cg->member_count, cg->joined_count,
			  cg->remove_count, cg->failed_count);
		return 0;
	}

	members_mismatch = 0;
	id = ids;

	for (i = 0; i < li->id_info_count; i++) {
		memb = find_memb(cg, id->nodeid);
		if (!memb) {
			log_group(ls, "match_change %d:%u skip %u no memb %d",
			  	  hd->nodeid, seq, cg->seq, id->nodeid);
			members_mismatch = 1;
			break;
		}
		id = (struct id_info *)((char *)id + li->id_info_size);
	}

	if (members_mismatch)
		return 0;

	/* Not completely sure if this is a valid assertion or not, i.e. not
	   sure if we really never want to nack our first and only cg.  I have
	   seen one case in which a node incorrectly accepted nacks for cg seq
	   1 and ls change_seq 1.  (It was the secondary effect of another bug.)

	   Or, it's possible that this should apply a little more broadly as:
	   don't nack our most recent cg, i.e. cg->seq == ls->change_seq (1 or
	   otherwise).  I'm hoping to find a test case that will exercise this
	   to clarify the situation here, and then update this comment. */

	if (cg->seq == 1 && ls->change_seq == 1 && (hd->flags & DLM_MFLG_NACK)) {
		log_group(ls, "match_change %d:%u skip cg %u for nack",
			  hd->nodeid, seq, cg->seq);
		return 0;
	}

	node->last_match_seq = cg->seq;

	log_group(ls, "match_change %d:%u matches cg %u", hd->nodeid, seq,
		  cg->seq);
	return 1;
}

/* Unfortunately, there's no really simple way to match a message with the
   specific change that it was sent for.  We hope that by passing all the
   details of the change in the message, we will be able to uniquely match the
   it to the correct change. */

/* A start message will usually be for the first (current) change on our list.
   In some cases it will be for a non-current change, and we can ignore it:

   1. A,B,C get confchg1 adding C
   2. C sends start for confchg1
   3. A,B,C get confchg2 adding D
   4. A,B,C,D recv start from C for confchg1 - ignored
   5. C,D send start for confchg2
   6. A,B send start for confchg2
   7. A,B,C,D recv all start messages for confchg2, and start kernel
 
   In step 4, how do the nodes know whether the start message from C is
   for confchg1 or confchg2?  Hopefully by comparing the counts and members. */

static struct change *find_change(struct lockspace *ls, struct dlm_header *hd,
				  struct ls_info *li, struct id_info *ids)
{
	struct change *cg;

	list_for_each_entry_reverse(cg, &ls->changes, list) {
		if (!match_change(ls, cg, hd, li, ids))
			continue;
		return cg;
	}

	log_group(ls, "find_change %d:%u no match", hd->nodeid, hd->msgdata);
	return NULL;
}

static int is_added(struct lockspace *ls, int nodeid)
{
	struct change *cg;
	struct member *memb;

	list_for_each_entry(cg, &ls->changes, list) {
		memb = find_memb(cg, nodeid);
		if (memb && memb->added)
			return 1;
	}
	return 0;
}

static void receive_start(struct lockspace *ls, struct dlm_header *hd, int len)
{
	struct change *cg;
	struct member *memb;
	struct ls_info *li;
	struct id_info *ids;
	uint32_t seq = hd->msgdata;
	int added;

	log_group(ls, "receive_start %d:%u len %d", hd->nodeid, seq, len);

	li = (struct ls_info *)((char *)hd + sizeof(struct dlm_header));
	ids = (struct id_info *)((char *)li + sizeof(struct ls_info));

	ls_info_in(li);
	ids_in(li, ids);

	cg = find_change(ls, hd, li, ids);
	if (!cg)
		return;

	memb = find_memb(cg, hd->nodeid);
	if (!memb) {
		/* this should never happen since match_change checks it */
		log_error("receive_start no member %d", hd->nodeid);
		return;
	}

	memb->start_flags = hd->flags;

	added = is_added(ls, hd->nodeid);

	if (added && li->started_count && ls->started_count) {
		log_error("receive_start %d:%u add node with started_count %u",
			  hd->nodeid, seq, li->started_count);

		/* see comment in fence/fenced/cpg.c */
		memb->disallowed = 1;
		return;
	}

	if (memb->start_flags & DLM_MFLG_NACK) {
		log_group(ls, "receive_start %d:%u is NACK", hd->nodeid, seq);
		return;
	}

	node_history_start(ls, hd->nodeid);
	memb->start = 1;
}

static void receive_plocks_done(struct lockspace *ls, struct dlm_header *hd,
				int len)
{
	struct ls_info *li;
	struct id_info *ids;

	log_dlock(ls, "receive_plocks_done %d:%u flags %x plocks_data %u need %d save %d",
		  hd->nodeid, hd->msgdata, hd->flags, hd->msgdata2,
		  ls->need_plocks, ls->save_plocks);

	if (!ls->need_plocks)
		return;

	if (ls->need_plocks && !ls->save_plocks)
		return;

	if (!ls->started_change) {
		/* don't think this should happen */
		log_elock(ls, "receive_plocks_done %d:%u no started_change",
			  hd->nodeid, hd->msgdata);
		return;
	}

	li = (struct ls_info *)((char *)hd + sizeof(struct dlm_header));
	ids = (struct id_info *)((char *)li + sizeof(struct ls_info));
	ls_info_in(li);
	ids_in(li, ids);

	if (!match_change(ls, ls->started_change, hd, li, ids)) {
		/* don't think this should happen */
		log_elock(ls, "receive_plocks_done %d:%u no match_change",
			  hd->nodeid, hd->msgdata);

		/* remove/free anything we've saved from
		   receive_plocks_data messages that weren't for us */
		clear_plocks_data(ls);
		return;
	}

	if (ls->recv_plocks_data_count != hd->msgdata2) {
		log_elock(ls, "receive_plocks_done plocks_data %u recv %u",
			  hd->msgdata2, ls->recv_plocks_data_count);
	}

	process_saved_plocks(ls);
	ls->need_plocks = 0;
	ls->save_plocks = 0;

	log_dlock(ls, "receive_plocks_done %d:%u plocks_data_count %u",
		  hd->nodeid, hd->msgdata, ls->recv_plocks_data_count);
}

static void send_info(struct lockspace *ls, struct change *cg, int type,
		      uint32_t flags, uint32_t msgdata2)
{
	struct dlm_header *hd;
	struct ls_info *li;
	struct id_info *id;
	struct member *memb;
	char *buf;
	int len, id_count;

	id_count = cg->member_count;

	len = sizeof(struct dlm_header) + sizeof(struct ls_info) +
	      id_count * sizeof(struct id_info);

	buf = malloc(len);
	if (!buf) {
		log_error("send_info len %d no mem", len);
		return;
	}
	memset(buf, 0, len);

	hd = (struct dlm_header *)buf;
	li = (struct ls_info *)(buf + sizeof(*hd));
	id = (struct id_info *)(buf + sizeof(*hd) + sizeof(*li));

	/* fill in header (dlm_send_message handles part of header) */

	hd->type = type;
	hd->msgdata = cg->seq;
	hd->flags = flags;
	hd->msgdata2 = msgdata2;

	if (ls->joining)
		hd->flags |= DLM_MFLG_JOINING;
	if (!ls->need_plocks)
		hd->flags |= DLM_MFLG_HAVEPLOCK;

	/* fill in ls_info */

	li->ls_info_size  = cpu_to_le32(sizeof(struct ls_info));
	li->id_info_size  = cpu_to_le32(sizeof(struct id_info));
	li->id_info_count = cpu_to_le32(id_count);
	li->started_count = cpu_to_le32(ls->started_count);
	li->member_count  = cpu_to_le32(cg->member_count);
	li->joined_count  = cpu_to_le32(cg->joined_count);
	li->remove_count  = cpu_to_le32(cg->remove_count);
	li->failed_count  = cpu_to_le32(cg->failed_count);

	/* fill in id_info entries */

	list_for_each_entry(memb, &cg->members, list) {
		id->nodeid = cpu_to_le32(memb->nodeid);
		id++;
	}

	dlm_send_message(ls, buf, len);

	free(buf);
}

/* fenced used the DUPLICATE_CG flag instead of sending nacks like we
   do here.  I think the nacks didn't work for fenced for some reason,
   but I don't remember why (possibly because the node blocked doing
   the fencing hadn't created the cg to nack yet). */

static void send_start(struct lockspace *ls, struct change *cg)
{
	log_group(ls, "send_start %d:%u counts %u %d %d %d %d",
		  our_nodeid, cg->seq, ls->started_count,
		  cg->member_count, cg->joined_count, cg->remove_count,
		  cg->failed_count);

	send_info(ls, cg, DLM_MSG_START, 0, 0);
}

static void send_plocks_done(struct lockspace *ls, struct change *cg, uint32_t plocks_data)
{
	log_dlock(ls, "send_plocks_done %d:%u counts %u %d %d %d %d plocks_data %u",
		  our_nodeid, cg->seq, ls->started_count,
		  cg->member_count, cg->joined_count, cg->remove_count,
		  cg->failed_count, plocks_data);

	send_info(ls, cg, DLM_MSG_PLOCKS_DONE, 0, plocks_data);
}

static int same_members(struct change *cg1, struct change *cg2)
{
	struct member *memb;

	list_for_each_entry(memb, &cg1->members, list) {
		if (!find_memb(cg2, memb->nodeid))
			return 0;
	}
	return 1;
}

static void send_nacks(struct lockspace *ls, struct change *startcg)
{
	struct change *cg;

	list_for_each_entry(cg, &ls->changes, list) {
		if (cg->seq < startcg->seq &&
		    cg->member_count == startcg->member_count &&
		    cg->joined_count == startcg->joined_count &&
		    cg->remove_count == startcg->remove_count &&
		    cg->failed_count == startcg->failed_count &&
		    same_members(cg, startcg)) {
			log_group(ls, "send nack old cg %u new cg %u",
				   cg->seq, startcg->seq);
			send_info(ls, cg, DLM_MSG_START, DLM_MFLG_NACK, 0);
		}
	}
}

static int nodes_added(struct lockspace *ls)
{
	struct change *cg;

	list_for_each_entry(cg, &ls->changes, list) {
		if (cg->joined_count)
			return 1;
	}
	return 0;
}

static void prepare_plocks(struct lockspace *ls)
{
	struct change *cg = list_first_entry(&ls->changes, struct change, list);
	struct member *memb;
	uint32_t plocks_data;

	if (!opt(enable_plock_ind) || ls->disable_plock)
		return;

	log_dlock(ls, "prepare_plocks");

	/* if we're the only node in the lockspace, then we are the data_node
	   and we don't need plocks */

	if (cg->member_count == 1) {
		list_for_each_entry(memb, &cg->members, list) {
			if (memb->nodeid != our_nodeid) {
				log_elock(ls, "prepare_plocks other member %d",
					  memb->nodeid);
			}
		}
		ls->plock_data_node = our_nodeid;
		ls->need_plocks = 0;
		return;
	}

	/* the low node that indicated it had plock state in its last
	   start message is the data_node */

	set_plock_data_node(ls);

	/* there is no node with plock state, so there's no syncing to do */

	if (!ls->plock_data_node) {
		ls->need_plocks = 0;
		ls->save_plocks = 0;
		return;
	}

	/* We save all plock messages received after our own confchg and
	   apply them after we receive the plocks_done message from the
	   data_node. */

	if (ls->need_plocks) {
		log_dlock(ls, "save_plocks start");
		ls->save_plocks = 1;
		return;
	}

	if (ls->plock_data_node != our_nodeid)
		return;

	if (nodes_added(ls))
		send_all_plocks_data(ls, cg->seq, &plocks_data);

	send_plocks_done(ls, cg, plocks_data);
}

static void apply_changes(struct lockspace *ls)
{
	struct change *cg;

	if (list_empty(&ls->changes))
		return;
	cg = list_first_entry(&ls->changes, struct change, list);

	switch (cg->state) {

	case CGST_WAIT_CONDITIONS:
		if (wait_conditions_done(ls)) {
			send_nacks(ls, cg);
			send_start(ls, cg);
			cg->state = CGST_WAIT_MESSAGES;
		}
		break;

	case CGST_WAIT_MESSAGES:
		if (wait_messages_done(ls)) {
			set_protocol_stateful();
			start_kernel(ls);
			prepare_plocks(ls);
			cleanup_changes(ls);
		}
		break;

	default:
		log_error("apply_changes invalid state %d", cg->state);
	}
}

void process_lockspace_changes(void)
{
	struct lockspace *ls, *safe;

	poll_lockspaces = 0;
	poll_fs = 0;

	list_for_each_entry_safe(ls, safe, &lockspaces, list) {
		if (!list_empty(&ls->changes))
			apply_changes(ls);
	}
}

static int add_change(struct lockspace *ls,
		      const struct cpg_address *member_list,
		      size_t member_list_entries,
		      const struct cpg_address *left_list,
		      size_t left_list_entries,
		      const struct cpg_address *joined_list,
		      size_t joined_list_entries,
		      struct change **cg_out)
{
	struct change *cg;
	struct member *memb;
	int i, error;
	uint64_t now = monotime();

	cg = malloc(sizeof(struct change));
	if (!cg)
		goto fail_nomem;
	memset(cg, 0, sizeof(struct change));
	INIT_LIST_HEAD(&cg->members);
	INIT_LIST_HEAD(&cg->removed);
	cg->state = CGST_WAIT_CONDITIONS;
	cg->create_time = now;
	cg->seq = ++ls->change_seq;
	if (!cg->seq)
		cg->seq = ++ls->change_seq;

	cg->member_count = member_list_entries;
	cg->joined_count = joined_list_entries;
	cg->remove_count = left_list_entries;

	for (i = 0; i < member_list_entries; i++) {
		memb = malloc(sizeof(struct member));
		if (!memb)
			goto fail_nomem;
		memset(memb, 0, sizeof(struct member));
		memb->nodeid = member_list[i].nodeid;
		list_add_tail(&memb->list, &cg->members);
	}

	for (i = 0; i < left_list_entries; i++) {
		memb = malloc(sizeof(struct member));
		if (!memb)
			goto fail_nomem;
		memset(memb, 0, sizeof(struct member));
		memb->nodeid = left_list[i].nodeid;
		if (left_list[i].reason == CPG_REASON_NODEDOWN ||
		    left_list[i].reason == CPG_REASON_PROCDOWN) {
			memb->failed = 1;
			cg->failed_count++;
		}
		list_add_tail(&memb->list, &cg->removed);

		if (left_list[i].reason == CPG_REASON_NODEDOWN)
			ls->cpg_ringid_wait = 1;

		if (memb->failed) {
			node_history_lockspace_fail(ls, memb->nodeid, cg,
						    left_list[i].reason, now);
		} else {
			node_history_lockspace_left(ls, memb->nodeid, cg, now);
		}

		log_group(ls, "add_change cg %u remove nodeid %d reason %s",
			  cg->seq, memb->nodeid, reason_str(left_list[i].reason));

		if (left_list[i].reason == CPG_REASON_PROCDOWN)
			kick_node_from_cluster(memb->nodeid);
	}

	for (i = 0; i < joined_list_entries; i++) {
		memb = find_memb(cg, joined_list[i].nodeid);
		if (!memb) {
			log_error("no member %d", joined_list[i].nodeid);
			error = -ENOENT;
			goto fail;
		}
		memb->added = 1;

		if (memb->nodeid == our_nodeid) {
			cg->we_joined = 1;
		} else {
			node_history_lockspace_add(ls, memb->nodeid, cg, now);
		}

		log_group(ls, "add_change cg %u joined nodeid %d", cg->seq,
			  memb->nodeid);
	}

	if (cg->we_joined) {
		log_group(ls, "add_change cg %u we joined", cg->seq);
		list_for_each_entry(memb, &cg->members, list) {
			node_history_lockspace_add(ls, memb->nodeid, cg, now);
		}
	}

	log_group(ls, "add_change cg %u counts member %d joined %d remove %d "
		  "failed %d", cg->seq, cg->member_count, cg->joined_count,
		  cg->remove_count, cg->failed_count);

	list_add(&cg->list, &ls->changes);
	*cg_out = cg;
	return 0;

 fail_nomem:
	log_error("no memory");
	error = -ENOMEM;
 fail:
	free_cg(cg);
	return error;
}

static int we_left(const struct cpg_address *left_list,
		   size_t left_list_entries)
{
	int i;

	for (i = 0; i < left_list_entries; i++) {
		if (left_list[i].nodeid == our_nodeid)
			return 1;
	}
	return 0;
}

static void confchg_cb(cpg_handle_t handle,
		       const struct cpg_name *group_name,
		       const struct cpg_address *member_list,
		       size_t member_list_entries,
		       const struct cpg_address *left_list,
		       size_t left_list_entries,
		       const struct cpg_address *joined_list,
		       size_t joined_list_entries)
{
	struct lockspace *ls;
	struct change *cg;
	struct member *memb;
	int rv;

	log_config(group_name, member_list, member_list_entries,
		   left_list, left_list_entries,
		   joined_list, joined_list_entries);

	ls = find_ls_handle(handle);
	if (!ls) {
		log_error("confchg_cb no lockspace for cpg %s",
			  group_name->value);
		return;
	}

	if (ls->leaving && we_left(left_list, left_list_entries)) {
		/* we called cpg_leave(), and this should be the final
		   cpg callback we receive */
		log_group(ls, "confchg for our leave");
		stop_kernel(ls, 0);
		set_configfs_members(ls, ls->name, 0, NULL, 0, NULL);
		set_sysfs_event_done(ls->name, 0);
		cpg_finalize(ls->cpg_handle);
		client_dead(ls->cpg_client);
		purge_plocks(ls, our_nodeid, 1);
		list_del(&ls->list);
		free_ls(ls);
		return;
	}

	rv = add_change(ls, member_list, member_list_entries,
			left_list, left_list_entries,
			joined_list, joined_list_entries, &cg);
	if (rv)
		return;

	stop_kernel(ls, cg->seq);

	list_for_each_entry(memb, &cg->removed, list)
		purge_plocks(ls, memb->nodeid, 0);

	apply_changes(ls);

#if 0
	deadlk_confchg(ls, member_list, member_list_entries,
		       left_list, left_list_entries,
		       joined_list, joined_list_entries);
#endif
}

/* after our join confchg, we want to ignore plock messages (see need_plocks
   checks below) until the point in time where the ckpt_node saves plock
   state (final start message received); at this time we want to shift from
   ignoring plock messages to saving plock messages to apply on top of the
   plock state that we read. */

static void deliver_cb(cpg_handle_t handle,
		       const struct cpg_name *group_name,
		       uint32_t nodeid, uint32_t pid,
		       void *data, size_t len)
{
	struct lockspace *ls;
	struct dlm_header *hd;
	int ignore_plock;
	int rv;

	int enable_plock = opt(enable_plock_ind);
	int plock_ownership = opt(plock_ownership_ind);

	ls = find_ls_handle(handle);
	if (!ls) {
		log_error("deliver_cb no ls for cpg %s", group_name->value);
		return;
	}

	if (len < sizeof(struct dlm_header)) {
		log_error("deliver_cb short message %zd", len);
		return;
	}

	hd = (struct dlm_header *)data;
	dlm_header_in(hd);

	rv = dlm_header_validate(hd, nodeid);
	if (rv < 0)
		return;

	ignore_plock = 0;

	switch (hd->type) {
	case DLM_MSG_START:
		receive_start(ls, hd, len);
		break;

	case DLM_MSG_PLOCK:
		if (ls->disable_plock)
			break;
		if (ls->need_plocks && !ls->save_plocks) {
			ignore_plock = 1;
			break;
		}
		if (enable_plock)
			receive_plock(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d",
				  hd->type, nodeid, enable_plock);
		break;

	case DLM_MSG_PLOCK_OWN:
		if (ls->disable_plock)
			break;
		if (ls->need_plocks && !ls->save_plocks) {
			ignore_plock = 1;
			break;
		}
		if (enable_plock && plock_ownership)
			receive_own(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d owner %d",
				  hd->type, nodeid, enable_plock, plock_ownership);
		break;

	case DLM_MSG_PLOCK_DROP:
		if (ls->disable_plock)
			break;
		if (ls->need_plocks && !ls->save_plocks) {
			ignore_plock = 1;
			break;
		}
		if (enable_plock && plock_ownership)
			receive_drop(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d owner %d",
				  hd->type, nodeid, enable_plock, plock_ownership);
		break;

	case DLM_MSG_PLOCK_SYNC_LOCK:
	case DLM_MSG_PLOCK_SYNC_WAITER:
		if (ls->disable_plock)
			break;
		if (ls->need_plocks && !ls->save_plocks) {
			ignore_plock = 1;
			break;
		}
		if (enable_plock && plock_ownership)
			receive_sync(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d owner %d",
				  hd->type, nodeid, enable_plock, plock_ownership);
		break;

	case DLM_MSG_PLOCKS_DATA:
		if (ls->disable_plock)
			break;
		if (enable_plock)
			receive_plocks_data(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d",
				  hd->type, nodeid, enable_plock);
		break;

	case DLM_MSG_PLOCKS_DONE:
		if (ls->disable_plock)
			break;
		if (enable_plock)
			receive_plocks_done(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_plock %d",
				  hd->type, nodeid, enable_plock);
		break;

#if 0
	case DLM_MSG_DEADLK_CYCLE_START:
		if (opt(enable_deadlk))
			receive_cycle_start(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_deadlk %d",
				  hd->type, nodeid, opt(enable_deadlk));
		break;

	case DLM_MSG_DEADLK_CYCLE_END:
		if (opt(enable_deadlk))
			receive_cycle_end(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_deadlk %d",
				  hd->type, nodeid, opt(enable_deadlk));
		break;

	case DLM_MSG_DEADLK_CHECKPOINT_READY:
		if (opt(enable_deadlk))
			receive_checkpoint_ready(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_deadlk %d",
				  hd->type, nodeid, opt(enable_deadlk));
		break;

	case DLM_MSG_DEADLK_CANCEL_LOCK:
		if (opt(enable_deadlk))
			receive_cancel_lock(ls, hd, len);
		else
			log_error("msg %d nodeid %d enable_deadlk %d",
				  hd->type, nodeid, opt(enable_deadlk));
		break;
#endif

	default:
		log_error("unknown msg type %d", hd->type);
	}

	if (ignore_plock)
		log_plock(ls, "msg %s nodeid %d need_plock ignore",
			  msg_name(hd->type), nodeid);

	apply_changes(ls);
}

/* save ringid to compare with cman's.
   also save member_list to double check with cman's member list?
   they should match */

static void totem_cb(cpg_handle_t handle,
		     struct cpg_ring_id ring_id,
		     uint32_t member_list_entries,
		     const uint32_t *member_list)
{
	struct lockspace *ls;
	char name[128];

	ls = find_ls_handle(handle);
	if (!ls) {
		log_error("totem_cb no lockspace for handle");
		return;
	}

	memset(&name, 0, sizeof(name));
	sprintf(name, "dlm:ls:%s", ls->name);

	log_ringid(name, &ring_id, member_list, member_list_entries);

	ls->cpg_ringid.nodeid = ring_id.nodeid;
	ls->cpg_ringid.seq = ring_id.seq;
	ls->cpg_ringid_wait = 0;

	apply_changes(ls);
}

static cpg_model_v1_data_t cpg_callbacks = {
	.cpg_deliver_fn = deliver_cb,
	.cpg_confchg_fn = confchg_cb,
	.cpg_totem_confchg_fn = totem_cb,
	.flags = CPG_MODEL_V1_DELIVER_INITIAL_TOTEM_CONF,
};

static void process_cpg_lockspace(int ci)
{
	struct lockspace *ls;
	cs_error_t error;

	ls = find_ls_ci(ci);
	if (!ls) {
		log_error("process_lockspace_cpg no lockspace for ci %d", ci);
		return;
	}

	error = cpg_dispatch(ls->cpg_handle, CS_DISPATCH_ALL);
	if (error != CS_OK) {
		log_error("cpg_dispatch error %d", error);
		return;
	}
}

/* received an "online" uevent from dlm-kernel */

int dlm_join_lockspace(struct lockspace *ls)
{
	cs_error_t error;
	cpg_handle_t h;
	struct cpg_name name;
	int i = 0, fd, ci, rv;

	error = cpg_model_initialize(&h, CPG_MODEL_V1,
				     (cpg_model_data_t *)&cpg_callbacks, NULL);
	if (error != CS_OK) {
		log_error("cpg_model_initialize error %d", error);
		rv = -1;
		goto fail_free;
	}

	cpg_fd_get(h, &fd);

	ci = client_add(fd, process_cpg_lockspace, NULL);

	list_add(&ls->list, &lockspaces);

	ls->cpg_handle = h;
	ls->cpg_client = ci;
	ls->cpg_fd = fd;
	ls->kernel_stopped = 1;
	ls->need_plocks = 1;
	ls->joining = 1;

	memset(&name, 0, sizeof(name));
	sprintf(name.value, "dlm:ls:%s", ls->name);
	name.length = strlen(name.value) + 1;

	/* TODO: allow global_id to be set in cluster.conf? */
	ls->global_id = cpgname_to_crc(name.value, name.length);

	log_group(ls, "cpg_join %s ...", name.value);
 retry:
	error = cpg_join(h, &name);
	if (error == CS_ERR_TRY_AGAIN) {
		sleep(1);
		if (!(++i % 10))
			log_error("cpg_join error retrying");
		goto retry;
	}
	if (error != CS_OK) {
		log_error("cpg_join error %d", error);
		cpg_finalize(h);
		rv = -1;
		goto fail;
	}

	return 0;

 fail:
	list_del(&ls->list);
	client_dead(ci);
	cpg_finalize(h);
 fail_free:
	set_sysfs_event_done(ls->name, rv);
	free_ls(ls);
	return rv;
}

/* received an "offline" uevent from dlm-kernel */

int dlm_leave_lockspace(struct lockspace *ls)
{
	cs_error_t error;
	struct cpg_name name;
	int i = 0;

	ls->leaving = 1;

	memset(&name, 0, sizeof(name));
	sprintf(name.value, "dlm:ls:%s", ls->name);
	name.length = strlen(name.value) + 1;

 retry:
	error = cpg_leave(ls->cpg_handle, &name);
	if (error == CS_ERR_TRY_AGAIN) {
		sleep(1);
		if (!(++i % 10))
			log_error("cpg_leave error retrying");
		goto retry;
	}
	if (error != CS_OK)
		log_error("cpg_leave error %d", error);

	return 0;
}

int set_fs_notified(struct lockspace *ls, int nodeid)
{
	struct node *node;

	/* this shouldn't happen */
	node = get_node_history(ls, nodeid);
	if (!node) {
		log_error("set_fs_notified no nodeid %d", nodeid);
		return -ESRCH;
	}

	if (!find_memb(ls->started_change, nodeid)) {
		log_group(ls, "set_fs_notified %d not in ls", nodeid);
		return 0;
	}

	/* this can happen, we haven't seen a nodedown for this node yet,
	   but we should soon */
	if (!node->check_fs) {
		log_group(ls, "set_fs_notified %d zero check_fs", nodeid);
		return -EAGAIN;
	}

	log_group(ls, "set_fs_notified nodeid %d", nodeid);
	node->fs_notified = 1;
	return 0;
}

int set_lockspace_info(struct lockspace *ls, struct dlmc_lockspace *lockspace)
{
	struct change *cg, *last = NULL;

	strncpy(lockspace->name, ls->name, DLM_LOCKSPACE_LEN);
	lockspace->global_id = ls->global_id;

	if (ls->joining)
		lockspace->flags |= DLMC_LF_JOINING;
	if (ls->leaving)
		lockspace->flags |= DLMC_LF_LEAVING;
	if (ls->kernel_stopped)
		lockspace->flags |= DLMC_LF_KERNEL_STOPPED;
	if (ls->fs_registered)
		lockspace->flags |= DLMC_LF_FS_REGISTERED;
	if (ls->need_plocks)
		lockspace->flags |= DLMC_LF_NEED_PLOCKS;
	if (ls->save_plocks)
		lockspace->flags |= DLMC_LF_SAVE_PLOCKS;

	if (!ls->started_change)
		goto next;

	cg = ls->started_change;

	lockspace->cg_prev.member_count = cg->member_count;
	lockspace->cg_prev.joined_count = cg->joined_count;
	lockspace->cg_prev.remove_count = cg->remove_count;
	lockspace->cg_prev.failed_count = cg->failed_count;
	lockspace->cg_prev.combined_seq = cg->combined_seq;
	lockspace->cg_prev.seq = cg->seq;

 next:
	if (list_empty(&ls->changes))
		goto out;

	list_for_each_entry(cg, &ls->changes, list)
		last = cg;

	cg = list_first_entry(&ls->changes, struct change, list);

	lockspace->cg_next.member_count = cg->member_count;
	lockspace->cg_next.joined_count = cg->joined_count;
	lockspace->cg_next.remove_count = cg->remove_count;
	lockspace->cg_next.failed_count = cg->failed_count;
	lockspace->cg_next.combined_seq = last->seq;
	lockspace->cg_next.seq = cg->seq;
	lockspace->cg_next.wait_condition = ls->wait_debug;
	if (cg->state == CGST_WAIT_MESSAGES)
		lockspace->cg_next.wait_messages = 1;
 out:
	return 0;
}

static int _set_node_info(struct lockspace *ls, struct change *cg, int nodeid,
			  struct dlmc_node *node)
{
	struct member *m = NULL;
	struct node *n;

	node->nodeid = nodeid;

	if (cg)
		m = find_memb(cg, nodeid);
	if (!m)
		goto history;

	node->flags |= DLMC_NF_MEMBER;

	if (m->start)
		node->flags |= DLMC_NF_START;
	if (m->disallowed)
		node->flags |= DLMC_NF_DISALLOWED;

 history:
	n = get_node_history(ls, nodeid);
	if (!n)
		goto out;

	if (n->need_fencing)
		node->flags |= DLMC_NF_NEED_FENCING;
	if (n->check_fs)
		node->flags |= DLMC_NF_CHECK_FS;

	node->added_seq = n->lockspace_add_seq;
	node->removed_seq = n->lockspace_rem_seq;

	node->fail_reason = n->lockspace_fail_reason;
	node->fail_walltime = n->fail_walltime;
	node->fail_monotime = n->fail_monotime;
 out:
	return 0;
}

int set_node_info(struct lockspace *ls, int nodeid, struct dlmc_node *node)
{
	struct change *cg;

	if (!list_empty(&ls->changes)) {
		cg = list_first_entry(&ls->changes, struct change, list);
		return _set_node_info(ls, cg, nodeid, node);
	}

	return _set_node_info(ls, ls->started_change, nodeid, node);
}

int set_lockspaces(int *count, struct dlmc_lockspace **lss_out)
{
	struct lockspace *ls;
	struct dlmc_lockspace *lss, *lsp;
	int ls_count = 0;

	list_for_each_entry(ls, &lockspaces, list)
		ls_count++;

	lss = malloc(ls_count * sizeof(struct dlmc_lockspace));
	if (!lss)
		return -ENOMEM;
	memset(lss, 0, ls_count * sizeof(struct dlmc_lockspace));

	lsp = lss;
	list_for_each_entry(ls, &lockspaces, list) {
		set_lockspace_info(ls, lsp++);
	}

	*count = ls_count;
	*lss_out = lss;
	return 0;
}

int set_lockspace_nodes(struct lockspace *ls, int option, int *node_count,
                        struct dlmc_node **nodes_out)
{
	struct change *cg;
	struct node *n;
	struct dlmc_node *nodes = NULL, *nodep;
	struct member *memb;
	int count = 0;

	if (option == DLMC_NODES_ALL) {
		if (!list_empty(&ls->changes))
			cg = list_first_entry(&ls->changes, struct change,list);
		else
			cg = ls->started_change;

		list_for_each_entry(n, &ls->node_history, list)
			count++;

	} else if (option == DLMC_NODES_MEMBERS) {
		if (!ls->started_change)
			goto out;
		cg = ls->started_change;
		count = cg->member_count;

	} else if (option == DLMC_NODES_NEXT) {
		if (list_empty(&ls->changes))
			goto out;
		cg = list_first_entry(&ls->changes, struct change, list);
		count = cg->member_count;
	} else
		goto out;

	nodes = malloc(count * sizeof(struct dlmc_node));
	if (!nodes)
		return -ENOMEM;
	memset(nodes, 0, count * sizeof(struct dlmc_node));
	nodep = nodes;

	if (option == DLMC_NODES_ALL) {
		list_for_each_entry(n, &ls->node_history, list)
			_set_node_info(ls, cg, n->nodeid, nodep++);
	} else {
		list_for_each_entry(memb, &cg->members, list)
			_set_node_info(ls, cg, memb->nodeid, nodep++);
	}
 out:
	*node_count = count;
	*nodes_out = nodes;
	return 0;
}


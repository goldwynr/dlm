/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __DLM_DAEMON_DOT_H__
#define __DLM_DAEMON_DOT_H__

#include <asm/types.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>

#include <corosync/cpg.h>

#include <linux/dlmconstants.h>
#include "libdlmcontrol.h"
#include "dlm_controld.h"
#include "fence_config.h"
#include "list.h"
#include "rbtree.h"
#include "linux_endian.h"

#ifndef EXTERN
#define EXTERN extern
#else
#undef EXTERN
#define EXTERN
#endif

#define DAEMON_NAME              "dlm_controld"

/* TODO: get CONFDIR, LOGDIR, RUNDIR from build */

#define RUNDIR                   "/var/run/dlm_controld"
#define LOGDIR                   "/var/log/dlm_controld"
#define CONFDIR                  "/etc/dlm"

#define RUN_FILE_NAME            "dlm_controld.pid"
#define LOG_FILE_NAME            "dlm_controld.log"
#define CONF_FILE_NAME           "dlm.conf"

#define RUN_FILE_PATH            RUNDIR "/" RUN_FILE_NAME
#define LOG_FILE_PATH            LOGDIR "/" LOG_FILE_NAME
#define CONF_FILE_PATH           CONFDIR "/" CONF_FILE_NAME

#define DEFAULT_LOG_MODE         LOG_MODE_OUTPUT_FILE | LOG_MODE_OUTPUT_SYSLOG
#define DEFAULT_SYSLOG_FACILITY  LOG_LOCAL4
#define DEFAULT_SYSLOG_PRIORITY  LOG_INFO
#define DEFAULT_LOGFILE_PRIORITY LOG_INFO
#define DEFAULT_LOGFILE          LOG_FILE_PATH

enum {
        no_arg = 0,
        req_arg_bool = 1,
        req_arg_int = 2,
        req_arg_str = 3,
};

enum {
        daemon_debug_ind = 0,
        foreground_ind,
        log_debug_ind,
        timewarn_ind,
        protocol_ind,
        debug_logfile_ind,
        enable_fscontrol_ind,
        enable_plock_ind,
        plock_debug_ind,
        plock_rate_limit_ind,
        plock_ownership_ind,
        drop_resources_time_ind,
        drop_resources_count_ind,
        drop_resources_age_ind,
        post_join_delay_ind,
        enable_fencing_ind,
        enable_concurrent_fencing_ind,
        enable_startup_fencing_ind,
        enable_quorum_fencing_ind,
        enable_quorum_lockspace_ind,
        help_ind,
        version_ind,
        dlm_options_max,
};

struct dlm_option {
	const char *name;
	char letter;
	int req_arg;
	const char *desc;

	int use_int;
	char *use_str;

	int default_int;
	const char *default_str;

	int cli_set;
	int cli_int;
	char *cli_str;

	int file_set;
	int file_int;
	char *file_str;
};

EXTERN struct dlm_option dlm_options[dlm_options_max];
#define opt(x) dlm_options[x].use_int
#define opts(x) dlm_options[x].use_str


/* DLM_LOCKSPACE_LEN: maximum lockspace name length, from linux/dlmconstants.h.
   Copied in libdlm.h so apps don't need to include the kernel header.
   The libcpg limit is larger at CPG_MAX_NAME_LENGTH 128.  Our cpg name includes
   a "dlm:" prefix before the lockspace name. */

/* Maximum members of a ls, should match CPG_MEMBERS_MAX in corosync/cpg.h.
   There are no max defines in dlm-kernel for lockspace members. */

#define MAX_NODES	128

/* Maximum number of IP addresses per node, when using SCTP and multi-ring in
   corosync  In dlm-kernel this is DLM_MAX_ADDR_COUNT, currently 3. */

#define MAX_NODE_ADDRESSES 4

#define PROTO_TCP  0
#define PROTO_SCTP 1
#define PROTO_DETECT 2

EXTERN int daemon_quit;
EXTERN int cluster_down;
EXTERN int poll_lockspaces;
EXTERN unsigned int retry_fencing;
EXTERN int daemon_fence_allow;
EXTERN int poll_fs;
EXTERN int poll_ignore_plock;
EXTERN int poll_drop_plock;
EXTERN int plock_fd;
EXTERN int plock_ci;
EXTERN struct list_head lockspaces;
EXTERN int cluster_quorate;
EXTERN int cluster_two_node;
EXTERN uint64_t fence_delay_begin;
EXTERN uint64_t cluster_quorate_monotime;
EXTERN uint64_t cluster_joined_monotime;
EXTERN uint64_t cluster_joined_walltime;
EXTERN uint32_t cluster_ringid_seq;
EXTERN char cluster_name[DLM_LOCKSPACE_LEN+1];
EXTERN int our_nodeid;
EXTERN uint32_t control_minor;
EXTERN uint32_t monitor_minor;
EXTERN uint32_t plock_minor;
EXTERN struct fence_device fence_all_device;

#define LOG_DUMP_SIZE DLMC_DUMP_SIZE

#define LOG_PLOCK 0x00010000
#define LOG_NONE  0x00001111

void log_level(char *name_in, uint32_t level_in, const char *fmt, ...);

#define log_error(fmt, args...) log_level(NULL, LOG_ERR, fmt, ##args)
#define log_debug(fmt, args...) log_level(NULL, LOG_DEBUG, fmt, ##args)
#define log_erros(ls, fmt, args...) log_level((ls)->name, LOG_ERR, fmt, ##args)
#define log_group(ls, fmt, args...) log_level((ls)->name, LOG_DEBUG, fmt, ##args)

#define log_plock(ls, fmt, args...) log_level((ls)->name, LOG_PLOCK|LOG_NONE, fmt, ##args)
#define log_dlock(ls, fmt, args...) log_level((ls)->name, LOG_PLOCK|LOG_DEBUG, fmt, ##args)
#define log_elock(ls, fmt, args...) log_level((ls)->name, LOG_PLOCK|LOG_ERR, fmt, ##args)

/* dlm_header types */
enum {
	DLM_MSG_PROTOCOL = 1,
	DLM_MSG_START,
	DLM_MSG_PLOCK,
	DLM_MSG_PLOCK_OWN,
	DLM_MSG_PLOCK_DROP,
	DLM_MSG_PLOCK_SYNC_LOCK,
	DLM_MSG_PLOCK_SYNC_WAITER,
	DLM_MSG_PLOCKS_DONE,
	DLM_MSG_PLOCKS_DATA,
	DLM_MSG_DEADLK_CYCLE_START,
	DLM_MSG_DEADLK_CYCLE_END,
	DLM_MSG_DEADLK_CHECKPOINT_READY,
	DLM_MSG_DEADLK_CANCEL_LOCK,
	DLM_MSG_FENCE_RESULT,
	DLM_MSG_FENCE_CLEAR,
};

/* dlm_header flags */
#define DLM_MFLG_JOINING   1  /* accompanies start, we are joining */
#define DLM_MFLG_HAVEPLOCK 2  /* accompanies start, we have plock state */
#define DLM_MFLG_NACK      4  /* accompanies start, prevent wrong match when
				 two outstanding changes are the same */

struct dlm_header {
	uint16_t version[3];
	uint16_t type;	  	/* DLM_MSG_ */
	uint32_t nodeid;	/* sender */
	uint32_t to_nodeid;     /* recipient, 0 for all */
	uint32_t global_id;     /* global unique id for this lockspace */
	uint32_t flags;		/* DLM_MFLG_ */
	uint32_t msgdata;       /* in-header payload depends on MSG type; lkid
				   for deadlock, seq for lockspace membership */
	uint32_t msgdata2;	/* second MSG-specific data */
	uint64_t pad;
};

struct lockspace {
	struct list_head	list;
	char			name[DLM_LOCKSPACE_LEN+1];
	uint32_t		global_id;

	/* dlm.conf config */

	int			nodir;
	int			master_count;
	int			master_nodeid[MAX_NODES];
	int			master_weight[MAX_NODES];

	/* lockspace membership stuff */

	cpg_handle_t		cpg_handle;
	struct cpg_ring_id	cpg_ringid;
	int			cpg_ringid_wait;
	int			cpg_client;
	int			cpg_fd;
	int			joining;
	int			leaving;
	int			kernel_stopped;
	int			fs_registered;
	int			wait_debug; /* for status/debugging */
	uint32_t		wait_retry; /* for debug rate limiting */
	uint32_t		change_seq;
	uint32_t		started_count;
	struct change		*started_change;
	struct list_head	changes;
	struct list_head	node_history;

	/* plock stuff */

	int			plock_data_node;
	int			need_plocks;
	int			save_plocks;
	int			disable_plock;
	uint32_t		recv_plocks_data_count;
	struct list_head	saved_messages;
	struct list_head	plock_resources;
	struct rb_root		plock_resources_root;
	time_t			last_plock_time;
	struct timeval		drop_resources_last;

#if 0
	/* deadlock stuff */

	int			deadlk_low_nodeid;
	struct list_head	deadlk_nodes;
	uint64_t		deadlk_ckpt_handle;
	int			deadlk_confchg_init;
	struct list_head	transactions;
	struct list_head	resources;
	struct timeval		cycle_start_time;
	struct timeval		cycle_end_time;
	struct timeval		last_send_cycle_start;
	int			cycle_running;
	int			all_checkpoints_ready;
#endif
};

/* action.c */
int set_sysfs_control(char *name, int val);
int set_sysfs_event_done(char *name, int val);
int set_sysfs_id(char *name, uint32_t id);
int set_sysfs_nodir(char *name, int val);
int set_configfs_members(struct lockspace *ls, char *name,
			 int new_count, int *new_members,
			 int renew_count, int *renew_members);
int add_configfs_node(int nodeid, char *addr, int addrlen, int local);
void del_configfs_node(int nodeid);
void clear_configfs(void);
int setup_configfs_options(void);
int setup_configfs_members(void);
int check_uncontrolled_lockspaces(void);
int setup_misc_devices(void);
int path_exists(const char *path);

/* config.c */
void set_opt_file(int update);
int get_weight(struct lockspace *ls, int nodeid);
void setup_lockspace_config(struct lockspace *ls);

/* cpg.c */
void process_lockspace_changes(void);
void process_fencing_changes(void);
int dlm_join_lockspace(struct lockspace *ls);
int dlm_leave_lockspace(struct lockspace *ls);
void update_flow_control_status(void);
int set_node_info(struct lockspace *ls, int nodeid, struct dlmc_node *node);
int set_lockspace_info(struct lockspace *ls, struct dlmc_lockspace *lockspace);
int set_lockspaces(int *count, struct dlmc_lockspace **lss_out);
int set_lockspace_nodes(struct lockspace *ls, int option, int *node_count,
			struct dlmc_node **nodes_out);
int set_fs_notified(struct lockspace *ls, int nodeid);

/* daemon_cpg.c */
void init_daemon(void);
void fence_ack_node(int nodeid);
void add_startup_node(int nodeid);
const char *reason_str(int reason);
const char *msg_name(int type);
void dlm_send_message(struct lockspace *ls, char *buf, int len);
void dlm_header_in(struct dlm_header *hd);
int dlm_header_validate(struct dlm_header *hd, int nodeid);
int fence_node_time(int nodeid, uint64_t *last_fenced);
int fence_in_progress(int *in_progress);
int setup_cpg_daemon(void);
void close_cpg_daemon(void);
void process_cpg_daemon(int ci);
void set_protocol_stateful(void);
int set_protocol(void);
void send_state_daemon_nodes(int fd);
void send_state_daemon(int fd);
void send_state_startup_nodes(int fd);

void log_config(const struct cpg_name *group_name,
                const struct cpg_address *member_list,
                size_t member_list_entries,
                const struct cpg_address *left_list,
                size_t left_list_entries,
                const struct cpg_address *joined_list,
                size_t joined_list_entries);

void log_ringid(const char *name,
                struct cpg_ring_id *ringid,
                const uint32_t *member_list,
                size_t member_list_entries);

/* deadlock.c */
void setup_deadlock(void);
void send_cycle_start(struct lockspace *ls);
void receive_checkpoint_ready(struct lockspace *ls, struct dlm_header *hd,
			int len);
void receive_cycle_start(struct lockspace *ls, struct dlm_header *hd, int len);
void receive_cycle_end(struct lockspace *ls, struct dlm_header *hd, int len);
void receive_cancel_lock(struct lockspace *ls, struct dlm_header *hd, int len);
void deadlk_confchg(struct lockspace *ls,
		const struct cpg_address *member_list,
		size_t member_list_entries,
		const struct cpg_address *left_list,
		size_t left_list_entries,
		const struct cpg_address *joined_list,
		size_t joined_list_entries);

/* main.c */
int do_read(int fd, void *buf, size_t count);
int do_write(int fd, void *buf, size_t count);
uint64_t monotime(void);
void client_dead(int ci);
int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci));
int client_fd(int ci);
void client_ignore(int ci, int fd);
void client_back(int ci, int fd);
struct lockspace *find_ls(char *name);
struct lockspace *find_ls_id(uint32_t id);
const char *dlm_mode_str(int mode);
void cluster_dead(int ci);
struct dlm_option *get_dlm_option(char *name);

/* member.c */
int setup_cluster(void);
void close_cluster(void);
void process_cluster(int ci);
void update_cluster(void);
uint64_t cluster_add_time(int nodeid);
int is_cluster_member(uint32_t nodeid);
int setup_cluster_cfg(void);
void close_cluster_cfg(void);
void process_cluster_cfg(int ci);
void kick_node_from_cluster(int nodeid);
int setup_node_config(void);

/* fence.c */
int fence_request(int nodeid, uint64_t fail_walltime, uint64_t fail_monotime,
                  struct fence_config *fc, int reason, int *pid_out);
int fence_result(int nodeid, int pid, int *result);
int unfence_node(int nodeid);

/* netlink.c */
int setup_netlink(void);
void process_netlink(int ci);

/* plock.c */
int setup_plocks(void);
void close_plocks(void);
void process_plocks(int ci);
void drop_resources_all(void);
int limit_plocks(void);
void receive_plock(struct lockspace *ls, struct dlm_header *hd, int len);
void receive_own(struct lockspace *ls, struct dlm_header *hd, int len);
void receive_sync(struct lockspace *ls, struct dlm_header *hd, int len);
void receive_drop(struct lockspace *ls, struct dlm_header *hd, int len);
void process_saved_plocks(struct lockspace *ls);
void purge_plocks(struct lockspace *ls, int nodeid, int unmount);
int copy_plock_state(struct lockspace *ls, char *buf, int *len_out);

void send_all_plocks_data(struct lockspace *ls, uint32_t seq, uint32_t *plocks_data);
void receive_plocks_data(struct lockspace *ls, struct dlm_header *hd, int len);
void clear_plocks_data(struct lockspace *ls);

/* logging.c */

void init_logging(void);
void close_logging(void);
void copy_log_dump(char *buf, int *len);
void copy_log_dump_plock(char *buf, int *len);

/* crc.c */
uint32_t cpgname_to_crc(const char *data, int len);

#endif


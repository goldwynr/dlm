/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef _FENCE_CONFIG_H_
#define _FENCE_CONFIG_H_

#define FENCE_CONFIG_DEVS_MAX 4     /* max devs per node */
#define FENCE_CONFIG_NAME_MAX 256   /* including terminating \0 */
#define FENCE_CONFIG_ARGS_MAX 4096  /* including terminating \0 */

struct fence_device {
	char name[FENCE_CONFIG_NAME_MAX];
	char agent[FENCE_CONFIG_NAME_MAX];
	char args[FENCE_CONFIG_ARGS_MAX];
	int unfence;
};

struct fence_connect {
	char name[FENCE_CONFIG_NAME_MAX];
	char args[FENCE_CONFIG_ARGS_MAX];
};

/* describes fence config for one node */

struct fence_config {
	struct fence_device *dev[FENCE_CONFIG_DEVS_MAX];
	struct fence_connect *con[FENCE_CONFIG_DEVS_MAX];
	unsigned int nodeid;
	int pos;
};


/*
 * Returns -ENOENT if path does not exist or there is no
 * config for nodeid in the file.
 *
 * Returns -EXYZ if there's a problem with the config.
 *
 * Returns 0 if a config was found with no problems.
 */

int fence_config_init(struct fence_config *fc, unsigned int nodeid, char *path);

void fence_config_free(struct fence_config *fc);

/*
 * Iterate through fence_config, sets pos to indicate next to try.
 * Based on two rules:
 *
 * - next_parallel is the next device with the same base name
 *   as the current device (base name is name preceding ":")
 *
 * - next_priority is the next device without the same base name
 *   as the current device
 */

int fence_config_next_parallel(struct fence_config *fc);
int fence_config_next_priority(struct fence_config *fc);

/*
 * Combine dev->args and con->args, replacing ' ' with '\n'.
 * Also add "node=nodeid" if "node=" does not already exist.
 */

int fence_config_agent_args(struct fence_config *fc, char *extra, char *args);

#endif

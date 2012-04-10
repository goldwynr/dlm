/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

#if 0

lockspace ls_name [ls_args]
master    ls_name node=nodeid [node_args]
master    ls_name node=nodeid [node_args]
master    ls_name node=nodeid [node_args]

lockspace foo nodir=1
master node=1 weight=2
master node=2 weight=1

#endif

/* The max line length in dlm.conf */

#define MAX_LINE 256

int get_weight(struct lockspace *ls, int nodeid)
{
	int i;

	/* if no masters are defined, everyone defaults to weight 1 */

	if (!ls->master_count)
		return 1;

	for (i = 0; i < ls->master_count; i++) {
		if (ls->master_nodeid[i] == nodeid)
			return ls->master_weight[i];
	}

	/* if masters are defined, non-masters default to weight 0 */

	return 0;
}

static void read_master_config(struct lockspace *ls, FILE *file)
{
	char line[MAX_LINE];
	char name[MAX_LINE];
	char args[MAX_LINE];
	char *k;
	int nodeid, weight, i;

	while (fgets(line, MAX_LINE, file)) {
		if (line[0] == '\n')
			break;
		if (line[0] == ' ')
			break;
		if (line[0] == '#')
			continue;

		if (strncmp(line, "master", strlen("master")))
			break;

		memset(name, 0, sizeof(name));
		memset(args, 0, sizeof(args));
		nodeid = 0;
		weight = 1;

		sscanf(line, "master %s %[^\n]s", name, args);

		if (strcmp(name, ls->name))
			break;

		k = strstr(args, "node=");
		if (!k)
			break;

		sscanf(k, "node=%d", &nodeid);
		if (!nodeid)
			break;

		k = strstr(args, "weight=");
		if (k)
			sscanf(k, "weight=%d", &weight);

		log_debug("config lockspace %s nodeid %d weight %d",
			  ls->name, nodeid, weight);

		i = ls->master_count++;
		ls->master_nodeid[i] = nodeid;
		ls->master_weight[i] = weight;

		if (ls->master_count >= MAX_NODES)
			break;
	}
}

void setup_lockspace_config(struct lockspace *ls)
{
	FILE *file;
	char line[MAX_LINE];
	char name[MAX_LINE];
	char args[MAX_LINE];
	char *k;
	int val;

	if (!path_exists(CONF_FILE_PATH))
		return;

	file = fopen(CONF_FILE_PATH, "r");
	if (!file)
		return;

	while (fgets(line, MAX_LINE, file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '\n')
			continue;

		if (strncmp(line, "lockspace", strlen("lockspace")))
			continue;

		memset(name, 0, sizeof(name));
		memset(args, 0, sizeof(args));
		val = 0;

		sscanf(line, "lockspace %s %[^\n]s", name, args);

		if (strcmp(name, ls->name))
			continue;

		k = strstr(args, "nodir=");
		if (k) {
			sscanf(k, "nodir=%d", &val);
			ls->nodir = val;
		}

		read_master_config(ls, file);
	}

	fclose(file);
}

static void get_val_int(char *line, int *val_out)
{
	char key[MAX_LINE];
	char val[MAX_LINE];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	*val_out = atoi(val);
}

static void get_val_str(char *line, char *val_out)
{
	char key[MAX_LINE];
	char val[MAX_LINE];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	strcpy(val_out, val);
}

void set_opt_file(int update)
{
	struct dlm_option *o;
	FILE *file;
	char line[MAX_LINE];
	char str[MAX_LINE];
	int i, val;

	if (!path_exists(CONF_FILE_PATH))
		return;

	file = fopen(CONF_FILE_PATH, "r");
	if (!file)
		return;

	while (fgets(line, MAX_LINE, file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '\n')
			continue;

		memset(str, 0, sizeof(str));

		for (i = 0; i < MAX_LINE; i++) {
			if (line[i] == ' ')
				break;
			if (line[i] == '=')
				break;
			if (line[i] == '\0')
				break;
			if (line[i] == '\n')
				break;
			if (line[i] == '\t')
				break;
			str[i] = line[i];
		}

		o = get_dlm_option(str);
		if (!o)
			continue;

		o->file_set++;

		if (!o->req_arg) {
			/* ignore any = x */

			o->file_int = 1;

			if (!o->cli_set)
				o->use_int = o->file_int;

			log_debug("config file %s = %d cli_set %d use %d",
				  o->name, o->file_int, o->cli_set, o->use_int);

		} else if (o->req_arg == req_arg_int) {
			get_val_int(line, &val);

			o->file_int = val;

			if (!o->cli_set)
				o->use_int = o->file_int;

			log_debug("config file %s = %d cli_set %d use %d",
				  o->name, o->file_int, o->cli_set, o->use_int);

		} else if (o->req_arg == req_arg_bool) {
			get_val_int(line, &val);

			o->file_int = val ? 1 : 0;

			if (!o->cli_set)
				o->use_int = o->file_int;

			log_debug("config file %s = %d cli_set %d use %d",
				  o->name, o->file_int, o->cli_set, o->use_int);
		} else if (o->req_arg == req_arg_str) {
			memset(str, 0, sizeof(str));
			get_val_str(line, str);

			o->file_str = strdup(str);

			if (!o->cli_set)
				o->use_str = o->file_str;

			log_debug("config file %s = %s cli_set %d use %s",
				  o->name, o->file_str, o->cli_set, o->use_str);
		}
	}

	fclose(file);
}


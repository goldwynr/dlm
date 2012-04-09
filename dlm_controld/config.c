/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

/*
 * TODO: lockspace master/nodir/weight
 */

int get_weight(int nodeid, char *lockspace)
{
	/* default weight is 1 */
	return 1;
}

static void get_val_int(char *line, int *val_out)
{
	char key[PATH_MAX];
	char val[PATH_MAX];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	*val_out = atoi(val);
}

static void get_val_str(char *line, char *val_out)
{
	char key[PATH_MAX];
	char val[PATH_MAX];
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
	char line[PATH_MAX];
	char str[PATH_MAX];
	int i, val;

	if (!path_exists(CONF_FILE_PATH))
		return;

	file = fopen(CONF_FILE_PATH, "r");
	if (!file)
		return;

	while (fgets(line, PATH_MAX, file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '\n')
			continue;

		memset(str, 0, sizeof(str));

		for (i = 0; i < PATH_MAX; i++) {
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


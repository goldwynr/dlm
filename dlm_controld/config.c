/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

/* TODO:
 <dlm>
 <lockspace name="foo" nodir="1">
   <master nodeid="1" weight="2"/>
   <master nodeid="2" weight="3"/>
 </lockspace>
 </dlm>
*/

int get_weight(int nodeid, char *lockspace)
{
	/* default weight is 1 */
	return 1;
}

static void proto_val(char *str, int *val)
{
	if (!strncasecmp(str, "tcp", 3))
		*val = PROTO_TCP;
	else if (!strncasecmp(str, "sctp", 4))
		*val = PROTO_SCTP;
	else if (!strncasecmp(str, "detect", 6))
		*val = PROTO_DETECT;
	else {
		log_error("invalid protocol value %s", str);
	}
}

static void set_val(char *line, int *val_out)
{
	char key[PATH_MAX];
	char val[PATH_MAX];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	*val_out = atoi(val);

	log_debug("config %s=%d", key, *val_out);
}

static void get_val(char *line, char *val_out)
{
	char key[PATH_MAX];
	char val[PATH_MAX];
	int rv;

	rv = sscanf(line, "%[^=]=%s", key, val);
	if (rv != 2)
		return;

	strcpy(val_out, val);
}

void setup_config(int update)
{
	FILE *file;
	char line[PATH_MAX];
	char str[PATH_MAX];

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

		if (!optk_debug && !strncmp(line, "log_debug", strlen("log_debug")))
			set_val(line, &cfgk_debug);

		else if (!optk_timewarn && !strncmp(line, "timewarn", strlen("timewarn")) && !update)
			set_val(line, &cfgk_timewarn);

		else if (!optd_post_join_delay && !strncmp(line, "post_join_delay", strlen("post_join_delay")))
			set_val(line, &cfgd_post_join_delay);

		else if (!optd_enable_fencing && !strncmp(line, "enable_fencing", strlen("enable_fencing")) && !update)
			set_val(line, &cfgd_enable_fencing);

		else if (!optd_enable_startup_fencing && !strncmp(line, "enable_startup_fencing", strlen("enable_startup_fencing")) && !update)
			set_val(line, &cfgd_enable_startup_fencing);

		else if (!optd_enable_quorum_fencing && !strncmp(line, "enable_quorum_fencing", strlen("enable_quorum_fencing")) && !update)
			set_val(line, &cfgd_enable_quorum_fencing);

		else if (!optd_enable_quorum_lockspace && !strncmp(line, "enable_quorum_lockspace", strlen("enable_quorum_lockspace")) && !update)
			set_val(line, &cfgd_enable_quorum_lockspace);

		else if (!optd_enable_fscontrol && !strncmp(line, "enable_fscontrol", strlen("enable_fscontrol")) && !update)
			set_val(line, &cfgd_enable_fscontrol);

		else if (!optd_enable_plock && !strncmp(line, "enable_plock", strlen("enable_plock")) && !update)
			set_val(line, &cfgd_enable_plock);

		else if (!optd_plock_ownership && !strncmp(line, "plock_ownership", strlen("plock_ownership")) && !update)
			set_val(line, &cfgd_plock_ownership);

		else if (!optd_plock_debug && !strncmp(line, "plock_debug", strlen("plock_debug")))
			set_val(line, &cfgd_plock_debug);

		else if (!optd_plock_rate_limit && !strncmp(line, "plock_rate_limit", strlen("plock_rate_limit")))
			set_val(line, &cfgd_plock_rate_limit);

		else if (!optd_drop_resources_time && !strncmp(line, "drop_resources_time", strlen("drop_resources_time")))
			set_val(line, &cfgd_drop_resources_time);

		else if (!optd_drop_resources_count && !strncmp(line, "drop_resources_count", strlen("drop_resources_count")))
			set_val(line, &cfgd_drop_resources_count);

		else if (!optd_drop_resources_age && !strncmp(line, "drop_resources_age", strlen("drop_resources_age")))
			set_val(line, &cfgd_drop_resources_age);

		else if (!optk_protocol && !strncmp(line, "protocol", strlen("protocol")) && !update) {
			memset(str, 0, sizeof(str));
			get_val(line, str);
			proto_val(str, &cfgk_protocol);
			log_debug("config protocol = %d", cfgk_protocol);
		}
	}

	fclose(file);
}


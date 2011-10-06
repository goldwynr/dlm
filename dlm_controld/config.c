/*
 * Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include "dlm_daemon.h"
#include <libxml/tree.h>

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

static void set_val(xmlNode *root, const char *name, int *opt, int *val)
{
	xmlChar *str;

	str = xmlGetProp(root, BAD_CAST name);
	if (str && !(*opt)) {
		*val = atoi((char *)str);
		log_debug("config %s = %d", name, *val);
	}
}

void setup_config(int update)
{
	xmlDoc *doc;
	xmlNode *root;
	xmlChar *str;

	if (!path_exists(CONF_FILE_PATH))
		return;

	doc = xmlParseFile(CONF_FILE_PATH);
	if (!doc) {
		log_error("xml parse error %d %s", errno, CONF_FILE_PATH);
		return;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		log_error("xml root error %d %s", errno, CONF_FILE_PATH);
		xmlFreeDoc(doc);
		return;
	}

	if (update)
		goto do_update;

	/* These config values are set from dlm.conf only if they haven't
	   already been set on the command line. */

	str = xmlGetProp(root, BAD_CAST "protocol");
	if (str && !optk_protocol) {
		proto_val((char *)str, &cfgk_protocol);
		log_debug("config protocol = %d", cfgk_protocol);
	}

	set_val(root, "log_debug", &optk_debug, &cfgk_debug);
	set_val(root, "timewarn", &optk_timewarn, &cfgk_timewarn);
	set_val(root, "enable_fencing", &optd_enable_fencing, &cfgd_enable_fencing);
	set_val(root, "enable_quorum", &optd_enable_quorum, &cfgd_enable_quorum);
	set_val(root, "enable_plock", &optd_enable_plock, &cfgd_enable_plock);
	set_val(root, "plock_ownership", &optd_plock_ownership, &cfgd_plock_ownership);
 do_update:
	/* The following can be changed while running */
	set_val(root, "plock_debug", &optd_plock_debug, &cfgd_plock_debug);
	set_val(root, "plock_rate_limit", &optd_plock_rate_limit, &cfgd_plock_rate_limit);
	set_val(root, "drop_resources_time", &optd_drop_resources_time, &cfgd_drop_resources_time);
	set_val(root, "drop_resources_count", &optd_drop_resources_count, &cfgd_drop_resources_count);
	set_val(root, "drop_resources_age", &optd_drop_resources_age, &cfgd_drop_resources_age);

	xmlFreeDoc(doc);
}


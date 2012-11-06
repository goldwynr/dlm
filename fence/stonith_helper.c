/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <pacemaker/crm/stonith-ng.h>

int nodeid;
uint64_t fail_time;

#define MAX_ARG_LEN 1024

static int get_options(int argc, char *argv[])
{
	char arg[MAX_ARG_LEN];
	char key[MAX_ARG_LEN];
	char val[MAX_ARG_LEN];
	char c;
	int rv;

	if (argc > 1) {
		while ((c = getopt(argc, argv, "n:t:")) != -1) {
			switch (c) {
			case 'n':
				nodeid = atoi(optarg);
				break;
			case 't':
				fail_time = strtoull(optarg, NULL, 0);
				break;
			}
		}
	} else {
		while (fgets(arg, sizeof(arg), stdin)) {
			rv = sscanf(arg, "%[^=]=%s\n", key, val);
			if (rv != 2)
				continue;

			if (!strcmp(key, "node"))
				nodeid = atoi(val);
			else if (!strcmp(key, "fail_time"))
				fail_time = strtoull(val, NULL, 0);
		}
	}

	if (!nodeid) {
		fprintf(stderr, "no node\n");
		return -1;
	}

	if (!fail_time) {
		fprintf(stderr, "no fail_time\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	uint64_t t;
	int rv;

	rv = get_options(argc, argv);
	if (rv)
		return rv;

	t = stonith_api_time_helper(nodeid, 0);
	if (t >= fail_time)
		return 0;

	rv = stonith_api_kick_helper(nodeid, 300, 0);
	if (rv) {
		fprintf(stderr, "kick_helper error %d nodeid %d\n", rv, nodeid);
		openlog("dlm_stonith", LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_ERR, "kick_helper error %d nodeid %d\n", rv, nodeid);
		return rv;
	}

	while (1) {
		t = stonith_api_time_helper(nodeid, 0);
		if (t >= fail_time)
			return 0;
		sleep(1);
	}

	return -1;
}


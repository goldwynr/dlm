/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"
#include <pacemaker/crm/stonith-ng.h>

int fence_request(int nodeid)
{
	int rv;
	rv = stonith_api_kick_helper(nodeid, 300, 1);
	if (rv) {
		log_error("stonith_api_kick_helper %d error %d", nodeid, rv);
		return rv;
	}
	return 0;
}

int fence_node_time(int nodeid, uint64_t *last_fenced_time)
{
	*last_fenced_time = stonith_api_time_helper(nodeid, 0);
	return 0;
}

int fence_in_progress(int *count)
{
	*count = 0;
	return 0;
}


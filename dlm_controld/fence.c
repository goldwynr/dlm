/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"
#ifdef STONITH
#include <pacemaker/crm/stonith-ng.h>
#endif

void fence_request(int nodeid)
{
#ifdef STONITH
	int rv;
	rv = stonith_api_kick_cs_helper(nodeid, 300, 1);
	if (rv)
		log_error("stonith_api_kick_cs_helper %d error %d", nodeid, rv);
#endif
}

int fence_node_time(int nodeid, uint64_t *last_fenced_time)
{
#ifdef STONITH
	*last_fenced_time = stonith_api_time_cs_helper(nodeid, 0);
#endif
	return 0;
}

int fence_in_progress(int *count)
{
	return 0;
}


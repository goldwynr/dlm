/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include "dlm_daemon.h"
//#include "libfenced.h"

int fence_node_time(int nodeid, uint64_t *last_fenced_time)
{
/*
	struct fenced_node nodeinfo;
	int rv;

	memset(&nodeinfo, 0, sizeof(nodeinfo));

	rv = fenced_node_info(nodeid, &nodeinfo);
	if (rv < 0)
		return rv;

	*last_fenced_time = nodeinfo.last_fenced_time;
*/
	return 0;
}

int fence_in_progress(int *count)
{
/*	struct fenced_domain domain;
	int rv;

	memset(&domain, 0, sizeof(domain));

	rv = fenced_domain_info(&domain);
	if (rv < 0)
		return rv;

	*count = domain.victim_count;
*/
	return 0;
}


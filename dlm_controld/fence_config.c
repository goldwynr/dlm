/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "fence_config.h"

#if 0

Empty new line separates the config for each fence device.

-

fence_all fence_foo key=val ...

Special fence config format that applies to all nodes and allows
no per node config parameters.  Multiple fence devices (parallel
or priority) cannot be used with fence_all.

fence_all fence_foo ...
unfence_all

Apply unfencing to all nodes.

-

device  <dev_name> <agent> <dev_args>
connect <dev_name> node=<nodeid> <con_args>

General fence config format, allowing per node config
parameters.

device  <dev_name> <agent> <dev_args>
connect <dev_name> node=<nodeid> <con_args>
unfence <dev_name>

Apply unfencing to all nodes connected to this device.

-

device  foo fence_foo ipaddr=1.1.1.1 login=x password=y
connect foo node=1 port=1
connect foo node=2 port=2
connect foo node=3 port=3

Simple example of nodes connected to switch ports.
If fencing with the device fails, the next device
listed for the node, if any, will be tried.

-

device  foo:1 fence_foo ipaddr=1.1.1.1 login=x password=y
connect foo:1 node=1 port=1
connect foo:1 node=2 port=2
connect foo:1 node=3 port=3

device  foo:2 fence_foo ipaddr=2.2.2.2 login=x password=y
connect foo:2 node=1 port=1
connect foo:2 node=2 port=2
connect foo:2 node=3 port=3

Associate two parallel path/power devices that must both
succeed for fencing to succeed.  Devices have same base
name with :1 :2 suffix.

-

device  foo fence_foo ipaddr=1.1.1.1 login=x password=y
connect foo node=1 port=1
connect foo node=2 port=2
connect foo node=3 port=3
unfence foo

Add unfence line to indicate nodes connected to the device
should be unfenced.

#endif

#define MAX_LINE (FENCE_CONFIG_ARGS_MAX + (3 * FENCE_CONFIG_NAME_MAX))

static unsigned int con_args_nodeid(char *args)
{
	char *k;
	unsigned int v;
	int rv;

	k = strstr(args, "node=");

	rv = sscanf(k, "node=%u", &v);
	if (rv != 1)
		return 0;
	return v;
}

static int read_config_section(unsigned int nodeid, FILE *file, char *dev_line,
			       struct fence_device **dev_out,
			       struct fence_connect **con_out)
{
	struct fence_device *dev = NULL;
	struct fence_connect *con;
	char line[MAX_LINE];
	char unused[FENCE_CONFIG_NAME_MAX];
	char agent[FENCE_CONFIG_NAME_MAX];
	char dev_name[FENCE_CONFIG_NAME_MAX];
	char con_name[FENCE_CONFIG_NAME_MAX];
	char dev_args[FENCE_CONFIG_ARGS_MAX];
	char con_args[FENCE_CONFIG_ARGS_MAX];
	int rv, unfence = 0;

	if (strlen(dev_line) > MAX_LINE)
		return -1;

	memset(dev_name, 0, sizeof(dev_name));
	memset(agent, 0, sizeof(agent));
	memset(dev_args, 0, sizeof(dev_args));

	rv = sscanf(dev_line, "%s %s %s %[^\n]s\n", unused, dev_name, agent, dev_args);
	if (rv < 3)
		return -1;

	while (fgets(line, MAX_LINE, file)) {
		if (line[0] == '\n')
			break;
		if (line[0] == ' ')
			break;
		if (line[0] == '#')
			continue;

		if (!strncmp(line, "unfence", strlen("unfence"))) {
			if (!strstr(line, dev_name))
				return -EINVAL;
			unfence = 1;
			continue;
		}

		/* invalid config */
		if (strncmp(line, "connect", strlen("connect")))
			return -EINVAL;

		/* once we've found the connect line we want, continue
		   scanning lines until end of section so we pick up an
		   unfence line at the end */

		if (dev)
			continue;

		memset(con_name, 0, sizeof(con_name));
		memset(con_args, 0, sizeof(con_args));

		sscanf(line, "%s %s %[^\n]s", unused, con_name, con_args);

		/* invalid config */
		if (strncmp(dev_name, con_name, FENCE_CONFIG_NAME_MAX))
			return -EINVAL;

		/* skip connection for another node */
		if (con_args_nodeid(con_args) != nodeid)
			continue;

		dev = malloc(sizeof(struct fence_device));
		if (!dev)
			return -ENOMEM;

		con = malloc(sizeof(struct fence_connect));
		if (!con) {
			free(dev);
			return -ENOMEM;
		}

		memset(dev, 0, sizeof(struct fence_device));
		memset(con, 0, sizeof(struct fence_connect));

		strncpy(dev->name, dev_name, FENCE_CONFIG_NAME_MAX-1);
		strncpy(dev->agent, agent, FENCE_CONFIG_NAME_MAX-1);
		strncpy(dev->args, dev_args, FENCE_CONFIG_ARGS_MAX-1);
		strncpy(con->name, con_name, FENCE_CONFIG_NAME_MAX-1);
		strncpy(con->args, con_args, FENCE_CONFIG_ARGS_MAX-1);
		dev->unfence = unfence;

		*dev_out = dev;
		*con_out = con;
	}

	if (dev && unfence)
		dev->unfence = 1;

	if (dev)
		return 0;
	else
		return -ENOENT;
}

void fence_config_free(struct fence_config *fc)
{
	struct fence_device *dev;
	struct fence_connect *con;
	int i;

	for (i = 0; i < FENCE_CONFIG_DEVS_MAX; i++) {
		dev = fc->dev[i];
		con = fc->con[i];
		if (dev)
			free(dev);
		if (con)
			free(con);
	}

	memset(fc, 0, sizeof(struct fence_config));
}

int fence_config_init(struct fence_config *fc, unsigned int nodeid, char *path)
{
	char line[MAX_LINE];
	struct fence_device *dev;
	struct fence_connect *con;
	FILE *file;
	int pos = 0;
	int rv;

	fc->nodeid = nodeid;

	file = fopen(path, "r");
	if (!file)
		return -ENOENT;

	while (fgets(line, MAX_LINE, file)) {
		if (line[0] == '#')
			continue;
		if (line[0] == '\n')
			continue;

		if (!strncmp(line, "fence_all", strlen("fence_all"))) {
			/* fence_all cannot be used with other fence devices */
			if (pos) {
				rv = -EINVAL;
				goto out;
			}

			dev = malloc(sizeof(struct fence_device));
			if (!dev) {
				rv = -ENOMEM;
				goto out;
			}
			memset(dev, 0, sizeof(struct fence_device));

			rv = sscanf(line, "%s %s %[^\n]s\n", dev->name, dev->agent, dev->args);
			if (rv < 2) {
				rv = -EINVAL;
				goto out;
			}

			if (fgets(line, MAX_LINE, file) &&
			    !strncmp(line, "unfence_all", strlen("unfence_all")))
				dev->unfence = 1;

			fc->dev[0] = dev;
			fc->pos = 0;
			rv = 0;
			goto out;
		}

		if (strncmp(line, "device", strlen("device")))
			continue;

		dev = NULL;
		con = NULL;

		/* read connect and unfence lines following a device line */
		rv = read_config_section(nodeid, file, line, &dev, &con);

		/* nodeid not listed in this section */
		if (rv == -ENOENT)
			continue;

		/* an error parsing the section, may be config to free */
		if (rv < 0) {
			if (dev)
				free(dev);
			if (con)
				free(con);
			goto out;
		}

		fc->dev[pos] = dev;
		fc->con[pos] = con;
		pos++;
	}

	if (!pos)
		rv = -ENOENT;
	else
		rv = 0;
 out:
	fclose(file);
	return rv;
}

static int same_base_name(struct fence_device *a,
			  struct fence_device *b)
{
	int len, i;

	len = strlen(a->name);
	if (len > strlen(b->name))
		len = strlen(b->name);

	for (i = 0; i < len; i++) {
		if (a->name[i] == ':' && b->name[i] == ':')
			return 1;
		if (a->name[i] == b->name[i])
			continue;
		return 0;
	}
	return 0;
}

/*
 * if next dev is in parallel with last one,
 * set d,c return 0, else -1
 *
 * two consecutive devs with same basename are parallel
 */

int fence_config_next_parallel(struct fence_config *fc)
{
	struct fence_device *prev, *next;
	int d = fc->pos;

	if (d >= FENCE_CONFIG_DEVS_MAX)
		return -1;

	prev = fc->dev[d];
	next = fc->dev[d+1];

	if (!next)
		return -1;

	if (same_base_name(prev, next)) {
		fc->pos = d+1;
		return 0;
	}
	return -1;
}

/*
 * if there's a dev with the next priority,
 * set d,c return 0, else -1
 *
 * look for another dev with a non-matching basename
 */

int fence_config_next_priority(struct fence_config *fc)
{
	struct fence_device *prev, *next;
	int d = fc->pos;
	int i;

	if (d >= FENCE_CONFIG_DEVS_MAX)
		return -1;

	prev = fc->dev[d];

	for (i = d+1; i < FENCE_CONFIG_DEVS_MAX; i++) {
		next = fc->dev[i];

		if (!next)
			return -1;

		if (same_base_name(prev, next))
			continue;

		fc->pos = d+1;
		return 0;
	}
	return -1;
}

int fence_config_agent_args(struct fence_config *fc, char *extra, char *args)
{
	struct fence_device *dev;
	struct fence_connect *con;
	char node[FENCE_CONFIG_NAME_MAX];
	char *p;
	int n = 0;
	int i, len;

	dev = fc->dev[fc->pos];
	con = fc->con[fc->pos];

	memset(node, 0, sizeof(node));
	snprintf(node, FENCE_CONFIG_NAME_MAX-1, "node=%u\n", fc->nodeid);
	len = strlen(node);

	if (dev)
		len += strlen(dev->args) + 1; /* +1 for \n */
	if (con)
		len += strlen(con->args) + 1;
	if (extra)
		len += strlen(extra) + 1;

	if (len > FENCE_CONFIG_ARGS_MAX - 1)
		return -1;

	if (dev && dev->args[0]) {
		p = dev->args;

		for (i = 0; i < strlen(dev->args); i++) {
			if (*p == ' ')
				args[n++] = '\n';
			else
				args[n++] = *p;
			p++;
		}
		args[n++] = '\n';
	}

	if (con && con->args[0]) {
		p = con->args;

		for (i = 0; i < strlen(con->args); i++) {
			if (*p == ' ')
				args[n++] = '\n';
			else
				args[n++] = *p;
			p++;
		}
		args[n++] = '\n';
	}

	if (!strstr(args, "node="))
		strcat(args, node);
	if (extra)
		strcat(args, extra);

	return 0;
}


/*
 * Copyright 2004-2012 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

static int syslog_facility;
static int syslog_priority;
static int logfile_priority;
static char logfile[PATH_MAX];
static FILE *logfile_fp;

void init_logging(void)
{
	syslog_facility = DEFAULT_SYSLOG_FACILITY;
	syslog_priority = DEFAULT_SYSLOG_PRIORITY;
	logfile_priority = DEFAULT_LOGFILE_PRIORITY;
	strcpy(logfile, DEFAULT_LOGFILE);

	/* logfile_priority is the only one of these options that
	   can be controlled from command line or environment variable */

	if (opt(debug_logfile_ind))
		logfile_priority = LOG_DEBUG;

	if (logfile[0]) {
		logfile_fp = fopen(logfile, "a+");
		if (logfile_fp != NULL) {
			int fd = fileno(logfile_fp);
			fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
		}
	}

	openlog(DAEMON_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

void close_logging(void)
{
	closelog();
	if (logfile_fp)
		fclose(logfile_fp);
}

#define NAME_ID_SIZE 32
#define LOG_STR_LEN 512
static char log_str[LOG_STR_LEN];

static char log_dump[LOG_DUMP_SIZE];
static unsigned int log_point;
static unsigned int log_wrap;

static char log_dump_plock[LOG_DUMP_SIZE];
static unsigned int log_point_plock;
static unsigned int log_wrap_plock;

static void log_copy(char *buf, int *len, char *log_buf,
		     unsigned int *point, unsigned int *wrap)
{
	unsigned int p = *point;
	unsigned int w = *wrap;
	int tail_len;

	if (!w && !p) {
		*len = 0;
	} else if (*wrap) {
		tail_len = LOG_DUMP_SIZE - p;
		memcpy(buf, log_buf + p, tail_len);
		if (p)
			memcpy(buf+tail_len, log_buf, p);
		*len = LOG_DUMP_SIZE;
	} else {
		memcpy(buf, log_buf, p-1);
		*len = p-1;
	}
}

void copy_log_dump(char *buf, int *len)
{
	log_copy(buf, len, log_dump, &log_point, &log_wrap);
}

void copy_log_dump_plock(char *buf, int *len)
{
	log_copy(buf, len, log_dump_plock, &log_point_plock, &log_wrap_plock);
}

static void log_save_str(int len, char *log_buf, unsigned int *point,
			 unsigned int *wrap)
{
	unsigned int p = *point;
	unsigned int w = *wrap;
	int i;

	if (len < LOG_DUMP_SIZE - p) {
		memcpy(log_buf + p, log_str, len);
		p += len;

		if (p == LOG_DUMP_SIZE) {
			p = 0;
			w = 1;
		}
		goto out;
	}

	for (i = 0; i < len; i++) {
		log_buf[p++] = log_str[i];

		if (p == LOG_DUMP_SIZE) {
			p = 0;
			w = 1;
		}
	}
 out:
	*point = p;
	*wrap = w;
}

void log_level(char *name_in, uint32_t level_in, const char *fmt, ...)
{
	va_list ap;
	char name[NAME_ID_SIZE + 1];
	uint32_t level = level_in & 0x0000FFFF;
	uint32_t extra = level_in & 0xFFFF0000;
	int ret, pos = 0;
	int len = LOG_STR_LEN - 2;
	int plock = extra & LOG_PLOCK;

	memset(name, 0, sizeof(name));

	if (name_in)
		snprintf(name, NAME_ID_SIZE, "%s ", name_in);

	ret = snprintf(log_str + pos, len - pos, "%llu %s",
		       (unsigned long long)monotime(), name);

	pos += ret;

	va_start(ap, fmt);
	ret = vsnprintf(log_str + pos, len - pos, fmt, ap);
	va_end(ap);

	if (ret >= len - pos)
		pos = len - 1;
	else
		pos += ret;

	log_str[pos++] = '\n';
	log_str[pos++] = '\0';

	if (level < LOG_NONE)
		log_save_str(pos - 1, log_dump, &log_point, &log_wrap);
	if (plock)
		log_save_str(pos - 1, log_dump_plock, &log_point_plock, &log_wrap_plock);

	if (level <= syslog_priority)
		syslog(level, "%s", log_str);

	if (level <= logfile_priority && logfile_fp) {
		time_t logtime = time(NULL);
		char tbuf[64];
		strftime(tbuf, sizeof(tbuf), "%b %d %T", localtime(&logtime));
		fprintf(logfile_fp, "%s %s", tbuf, log_str);
		fflush(logfile_fp);
	}

	if (!dlm_options[daemon_debug_ind].use_int)
		return;

	if ((level < LOG_NONE) || (plock && opt(plock_debug_ind)))
		fprintf(stderr, "%s", log_str);
}


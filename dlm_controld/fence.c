/*
 * Copyright 2004-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include "dlm_daemon.h"

static int run_agent(char *agent, char *args, int *pid_out)
{
	int pid, len;
	int pw_fd = -1;  /* parent write file descriptor */
	int cr_fd = -1;  /* child read file descriptor */
	int pfd[2];

	len = strlen(args);

	if (pipe(pfd))
		return -errno;

	cr_fd = pfd[0];
	pw_fd = pfd[1];

	pid = fork();
	if (pid < 0) {
		close(cr_fd);
		close(pw_fd);
		return -errno;
	}

	if (pid) {
		/* parent */
		int ret;

		do {
			ret = write(pw_fd, args, len);
		} while (ret < 0 && errno == EINTR);

		if (ret != len)
			goto fail;

		close(cr_fd);
		close(pw_fd);

		*pid_out = pid;
		return 0;
	} else {
		/* child */
		int c_stdout, c_stderr;

		/* redirect agent stdout/stderr to /dev/null */
		close(1);
		c_stdout = open("/dev/null", O_WRONLY);
		if (c_stdout < 0)
			goto fail;
		close(2);
		c_stderr = open("/dev/null", O_WRONLY);
		if (c_stderr < 0)
			goto fail;

		/* redirect agent stdin from parent */
		close(0);
		if (dup(cr_fd) < 0)
			goto fail;

		close(cr_fd);
		close(pw_fd);

		execlp(agent, agent, NULL);
		exit(EXIT_FAILURE);
	}
 fail:
	close(cr_fd);
	close(pw_fd);
	return -1;
}

int fence_request(int nodeid, uint64_t fail_walltime, uint64_t fail_monotime,
		  struct fence_config *fc, int *pid_out)
{
	struct fence_device *dev;
	char args[FENCE_CONFIG_ARGS_MAX];
	char extra[FENCE_CONFIG_NAME_MAX];
	int rv, pid = -1;

	memset(args, 0, sizeof(args));

	memset(extra, 0, sizeof(extra));
	snprintf(extra, sizeof(extra)-1, "fail_time=%llu\n", (unsigned long long)fail_walltime);

	dev = fc->dev[fc->pos];
	if (!dev)
		return -1;

	rv = fence_config_agent_args(fc, extra, args);
	if (rv < 0) {
		log_error("fence_request %d args error %d", nodeid, rv);
		return rv;
	}

	rv = run_agent(dev->agent, args, &pid);
	if (rv < 0) {
		log_error("fence_request %d pos %d name %s agent %s pid %d run error %d",
			  nodeid, fc->pos, dev->name, dev->agent, pid, rv);
		return rv;
	}

	log_debug("fence_request %d pos %d name %s agent %s pid %d running",
		  nodeid, fc->pos, dev->name, dev->agent, pid);

	*pid_out = pid;
	return 0;
}

/*
 * if pid has exited, return 0
 * result is 0 for success, non-zero for fail
 * success if pid exited with exit status 0
 * fail if pid exited with non-zero exit status, or was terminated by signal
 *
 * if pid is running, return -EAGAIN
 *
 * other error, return -EXXX
 */

int fence_result(int nodeid, int pid, int *result)
{
	int status, rv;

	rv = waitpid(pid, &status, WNOHANG);

	if (rv < 0) {
		/* shouldn't happen */
		log_error("waitpid %d nodeid %d error rv %d errno %d",
			  pid, nodeid, rv, errno);
		return rv;
	}

	if (!rv) {
		/* pid still running, has not changed state */
		return -EAGAIN;
	}

	if (rv == pid) {
		/* pid state has changed */

		if (WIFEXITED(status)) {
			/* pid exited with an exit code */
			*result = WEXITSTATUS(status);
			log_error("waitpid %d nodeid %d exit status %d",
				  pid, nodeid, *result);
			return 0;
		}
		if (WIFSIGNALED(status)) {
			/* pid exited due to a signal */
			*result = -1;
			log_error("waitpid %d nodeid %d term signal %d",
				  pid, nodeid, WTERMSIG(status));
			return 0;
		}

		/* pid state changed but still running */
		return -EAGAIN;
	}

	/* shouldn't happen */
	log_error("waitpid %d nodeid %d error rv %d", pid, nodeid, rv);
	return -1;
}


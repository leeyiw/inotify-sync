/*
 * inotify-sync - a simple file synchronizer and file system watcher
 * Copyright (C) 2010-2013, inotify-sync developers and inotify-sync contributors
 * Copyright (C) 2010-2013, Cohesion Network Security Studio
 *
 * inotify-sync is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * inotify-sync is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with inotify-sync; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <defines.h>

#include <getopt.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>

#include "event_watcher.h"
#include "config.h"

#define PID_FILE "/var/run/inotify-sync.pid"

void help();
void daemonize();
void start(int is_daemon);
void stop();
void log_pid();

int main(int argc, char *argv[])
{

	int ch;
	int is_start = 0, is_stop = 0, is_run = 0;
	//设置长选项
	struct option longopts[] = 
	{
		{"start", no_argument, NULL, 's'},
		{"stop", no_argument, NULL, 'x'},
		{"run", no_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'}
	};

	//如果无任何参数则打印帮助信息
	if(argc == 1)
	{
		help();
		return 0;
	}

	//循环使用getopt_long判断参数
	while((ch = getopt_long(argc, argv, "sxrh", longopts, NULL))!=-1)
	{
		switch(ch)
		{
		case 's':
			is_start = 1;
			break;
		case 'r':
			is_run = 1;
			break;
		case 'x':
			is_stop = 1;
			break;
		case 'h':
		case '?':
			// 如果有错误的参数，会打印错误信息
			help();
			return 0;
		}
	}
	// 处理选项冲突
	if((is_stop && is_start)
	|| (is_stop && is_run)
	|| (is_start && is_run))
	{
		help();
		return 0;
	}

	// 获取当前有效用户id
	uid_t euid = geteuid();

	if(is_run)
	{
		start(0);
	}
	if(is_start)
	{
		if(euid != 0)
		{
			printf("please run '-s' as root user!\n");
			exit(0);
		}
		start(1);
	}
	if(is_stop)
	{
		if(euid != 0)
		{
			printf("please run '-x' as root user!\n");
			exit(0);
		}
		stop();
	}

	return 0;
}

void help()
{
	printf("Usage: inotify-sync [OPTION...]\n");
	printf("a simple file synchronizer and file system watcher.\n");
	printf("\n");
	printf("Options:\n");
	printf("  -s, --start        Run this program on background.\n");
	printf("  -x, --stop         Stop this program on background.\n");
	printf("  -r, --run          this program on foreground.\n");
	printf("  -h, --help         Print this message and exit.\n");
}

void daemonize()
{
	int i;
	umask(0);

	struct rlimit rl;
	if(getrlimit(RLIMIT_NOFILE, &rl)<0)
		perror("getrlimit()");

	pid_t pid;
	if((pid = fork()) < 0)
	{
		perror("fork()");
		exit(errno);
	}
	else if(pid != 0)
	{
		// 父进程退出
		exit(0);
	}

	// 子进程继续运行
	log_pid();

	// 关闭所有文件描述符
	if(rl.rlim_max == RLIM_INFINITY)
		rl.rlim_max = 1024;
	for(i = 0;i < rl.rlim_max; i++)
	{
		close(i);
	}

	int fd0, fd1, fd2;
	// 取消标准输入
	fd0 = open("/dev/null", O_RDWR);
	// 重定向标准输出至配置的log文件
	fd1 = open(log_path, O_WRONLY|O_APPEND|O_CREAT,
			S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	fd2 = open(log_path, O_WRONLY|O_APPEND|O_CREAT,
			S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

	dup2(fd0, STDIN_FILENO);
	dup2(fd1, STDOUT_FILENO);
	dup2(fd2, STDERR_FILENO);

	setsid();
	if(chdir("/") == -1)
	{
		perror("chdir()");
		exit(errno);
	}
}

void start(int is_daemon)
{
	config_init();

	if(is_daemon)
	{
		daemonize();
	}

	event_handler_init();
	event_watcher_init();

	event_watcher_start();
	event_handler_start();

	event_watcher_wait();
	event_handler_wait();
}

void stop()
{
	FILE *fp;
	char buf[10] = {'\0'};

	if((fp = fopen(PID_FILE, "r")) == NULL)
	{
		perror("fopen()");
		exit(errno);
	}
	while(fgets(buf, sizeof(buf), fp) != NULL)
	{
		pid_t pid = atoi(buf);
		if(kill(pid, SIGKILL) == -1)
		{
			perror("kill()");
			exit(errno);
		}
	}
	fclose(fp);
	// 删除PID_FILE文件
	if(unlink(PID_FILE) == -1)
	{
		perror("unlink()");
		exit(errno);
	}
}

void log_pid()
{
	int pid_fd;
	FILE *fp;
	pid_t pid;
	char *pid_s = (char *)malloc(12);
	int nbytes;

	// 权限rw-r--r--
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	if((pid_fd = open(PID_FILE, O_WRONLY|O_CREAT, mode)) == -1)
	{
		perror("open()");
		exit(errno);
	}
	if((fp = fdopen(pid_fd, "w")) == NULL)
	{
		perror("fdopen()");
		exit(errno);
	}

	// 获取当前进程pid
	pid = getpid();
	sprintf(pid_s, "%d", pid);
	if((nbytes = fputs(pid_s, fp)) == EOF)
	{
		perror("fputs()");
		exit(errno);
	}
	fclose(fp);
	close(pid_fd);
}

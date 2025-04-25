#ifndef PING_H
#define PING_H

#define PING_USEC 1000000
#define TIMEOUT_SEC 1
#define PACKET_SIZE 64
#define _POSIX_C_SOURCE 200122L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <arpa/inet.h>

typedef enum Icmp_error
{
	ICMP_TIME_EXCEEDED_ERROR,
	ICMP_ERROR,
	ICMP_NORMAL,
} Icmp_error;

typedef struct s_rtt_stat
{
	double min;
	double avg;
	double max;
	double sum;
	int count;
	double s;
} t_rtt_stat;

#endif
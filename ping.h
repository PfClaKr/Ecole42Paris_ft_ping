#ifndef PING_H
#define PING_H

#define _POSIX_C_SOURCE 200122L
#define _DEFAULT_SOURCE

#define PING_USEC 1000000
#define PACKET_SIZE 64

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

#include <getopt.h> // getopt_long
#include <stdlib.h> // strtol

typedef enum Icmp_error
{
	ICMP_TIME_EXCEEDED_ERROR,
	ICMP_ERROR,
	ICMP_NORMAL,
	ICMP_DUPLICATE_ERROR,
} Icmp_error;

#define OPT_VERBOSE 0
#define OPT_TTL 64
#define OPT_COUNT 0
#define OPT_TIMEOUT 0
#define OPT_LINGER 10
#define OPT_QUIET 0

#define OPT_TTL_MIN 0
#define OPT_TTL_MAX MAXTTL
#define OPT_COUNT_MIN 1
#define OPT_COUNT_MAX INT64_MAX
#define OPT_TIMEOUT_MIN 0
#define OPT_TIMEOUT_MAX INT32_MAX
#define OPT_LINGER_MIN 0
#define OPT_LINGER_MAX INT32_MAX

typedef struct s_opts
{
	// mandat
	int verbose;	// v

	// bonus
	int ttl;		// ttl
	int timeout;	// w
	int linger;		// W
	int count;		// c
	int quiet;		// q
} t_opts;

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

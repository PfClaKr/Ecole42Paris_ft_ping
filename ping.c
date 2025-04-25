#include "ping.h"

int g_flag_ping = 1;

void sig_handler(int signum)
{
	if (signum == SIGINT)
		g_flag_ping = 0;
}

double get_time_diff(struct timeval *start, struct timeval *end)
{
	return ((end->tv_sec - start->tv_sec) * 1000.0 + (end->tv_usec - start->tv_usec) / 1000.0);
}

unsigned short checksum(void *b, int len) // RFC 1071
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int dns_lookup(char *host, struct addrinfo **res)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	return getaddrinfo(host, NULL, &hints, res);
}

int init_icmp_packet(char *packet, int sequence)
{
	struct icmphdr *hdr = (struct icmphdr *)packet;

	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->un.echo.id = getpid() & 0xFFFF;
	hdr->un.echo.sequence = sequence;
	memset(packet + sizeof(struct icmphdr), 0xAA, sizeof(packet) - sizeof(struct icmphdr));
	hdr->checksum = checksum(packet, sizeof(packet));
	sizeof(struct icmphdr);
}

Icmp_error parse_recv_packet(char *packet, int recv_len)
{
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + (ip_hdr->ihl * 4));

	if (!packet)
		return ICMP_ERROR;
	if (recv_len < sizeof(struct iphdr) + sizeof(struct icmphdr))
		return ICMP_ERROR;
	if (recv_len < ip_hdr->ihl * 4 + sizeof(struct icmphdr))
		return ICMP_ERROR;
	if (icmp_hdr->type == ICMP_TIME_EXCEEDED)
		return ICMP_TIME_EXCEEDED_ERROR;
	if (icmp_hdr->type != ICMP_ECHOREPLY)
		return ICMP_ERROR;
	if (icmp_hdr->un.echo.id != (getpid() & 0xFFFF))
		return ICMP_ERROR;
	return ICMP_NORMAL;
}

void update_rtt(t_rtt_stat *rtt, double time_diff)
{
	if (rtt->count == 0)
	{
		rtt->min = rtt->max = time_diff;
		rtt->avg = time_diff;
		rtt->s = 0;
		rtt->count = 1;
		return;
	}

	if (time_diff < rtt->min)
		rtt->min = time_diff;
	if (time_diff > rtt->max)
		rtt->max = time_diff;

	rtt->count++;

	// Welford algorithm
	double delta = time_diff - rtt->avg;
	rtt->avg += delta / rtt->count;
	rtt->s += delta * (time_diff - rtt->avg);
}

void get_ip_addr(char *packet, char *ip_addr)
{
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr.s_addr = ip_hdr->saddr;
	inet_ntop(AF_INET, &addr.sin_addr, ip_addr, INET_ADDRSTRLEN);
}

void print_result(char *host, int sequence, int recv_count, t_rtt_stat rtt)
{
	printf("--- %s ping statistics ---\n", host);
	printf("%d packets transmitted, %d received, %d%% packet loss\n", sequence + 1, recv_count, (sequence + 1 - recv_count) * 100 / (sequence + 1));
	double stddev = 0;
	if (rtt.count > 0)
		stddev = sqrt(rtt.s / rtt.count);
	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", rtt.min, rtt.avg, rtt.max, stddev);
}

void dump_packet(const uint8_t *packet)
{
	const struct iphdr *ip = (const struct iphdr *)packet;
	const struct icmphdr *icmp = (const struct icmphdr *)(packet + ip->ihl * 4);

	printf("IP Hdr Dump:\n ");
	for (int i = 0; i < ip->ihl * 4; i++)
	{
		printf("%02x", packet[i]);
		if ((i + 1) % 2 == 0)
			printf(" ");
	}
	printf("\n");

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");
	printf(" %d  %d  %02x %04x %04x  %d %04x  %02x  %02x %04x ",
		   ip->version,
		   ip->ihl,
		   ip->tos,
		   ntohs(ip->tot_len),
		   ntohs(ip->id),
		   ntohs(ip->frag_off) >> 13,
		   ntohs(ip->frag_off) & 0x1FFF,
		   ip->ttl,
		   ip->protocol,
		   ntohs(ip->check));

	char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->saddr, src_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->daddr, dst_buf, INET_ADDRSTRLEN);
	printf("%s  %s\n", src_buf, dst_buf);
	
	// ICMP header original header
	struct iphdr *orig_ip = (struct iphdr *)(icmp + 1);
    struct icmphdr *orig_icmp = (struct icmphdr *)((uint8_t *)orig_ip + orig_ip->ihl * 4);
    printf("ICMP: type %d, code %d, size %lu, id 0x%04x, seq 0x%x\n",
           orig_icmp->type, orig_icmp->code,
		   sizeof(struct icmphdr) * 8,
           ntohs(orig_icmp->un.echo.id),
		   ntohs(orig_icmp->un.echo.sequence)); // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ <<<<
	// printf("ICMP: type %d, code %d, size %lu, id 0x%04x, seq 0x%04x\n",
	// 	   icmp->type, icmp->code,
	// 	   sizeof(struct icmphdr),
	// 	   ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
}

void send_ping(char *host, int sockfd, struct addrinfo *send_res, int verbose)
{
	int sequence = -1;
	int recv_count = 0;
	struct timeval send_time, recv_time;
	char send_packet[PACKET_SIZE];
	char recv_packet[1024];
	struct sockaddr_in recv_res;
	t_rtt_stat rtt;

	memset(&rtt, 0, sizeof(t_rtt_stat));
	while (g_flag_ping)
	{
		memset(send_packet, 0, sizeof(send_packet));
		memset(recv_packet, 0, sizeof(recv_packet));
		++sequence;
		init_icmp_packet(send_packet, sequence);

		gettimeofday(&send_time, NULL);
		if (sendto(sockfd, send_packet, sizeof(send_packet), 0, send_res->ai_addr, sizeof(struct sockaddr_in)) < 0)
		{
			usleep(PING_USEC);
			printf("sento function fail\n");
			continue;
		}
		socklen_t recv_res_len = sizeof(recv_res);
		int recv_len = recvfrom(sockfd, recv_packet, sizeof(recv_packet), 0, (struct sockaddr *)&recv_res, &recv_res_len);
		if (recv_len < 0)
		{
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				fprintf(stderr, "Request timeout for icmp_seq %d\n", sequence);
				usleep(PING_USEC);
				continue;
			}
		}
		gettimeofday(&recv_time, NULL);
		double time_diff = get_time_diff(&send_time, &recv_time);
		Icmp_error e;
		e = parse_recv_packet(recv_packet, recv_len);
		if (e == ICMP_ERROR)
		{
			printf("ICMP error\n");
			usleep(PING_USEC);
			continue;
		}
		update_rtt(&rtt, time_diff);
		char ip_addr[16];
		get_ip_addr(recv_packet, ip_addr);
		int payload_len = recv_len - sizeof(struct iphdr);
		if (e == ICMP_TIME_EXCEEDED_ERROR)
		{
			fprintf(stderr, "%d bytes from %s: Time to live exceeded\n", payload_len, ip_addr);
			if (verbose == 1)
				dump_packet(recv_packet);
		}
		else
		{
			printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", payload_len, ip_addr, sequence, ((struct iphdr *)recv_packet)->ttl, time_diff);
		}
		++recv_count;
		usleep(PING_USEC);
	}
	print_result(host, sequence, recv_count, rtt);
	close(sockfd);
}

// 92 bytes from 192.168.0.1: Time to live exceeded
// IP Hdr Dump:
//  4500 0054 930f 4000 0101 8566 c0a8 0011 df82 c0f7
// Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data
//  4  5  00 0054 930f   2 0000  01  01 8566 192.168.0.17  223.130.192.247
// ICMP: type 8, code 0, size 64, id 0x3737, seq 0x0000

int main(int ac, char **av)
{
	int opt, verbose = 0;
	opterr = 0;
	while ((opt = getopt(ac, av, ":?v")) != -1)
	{
		switch (opt)
		{
		case 'v':
			verbose = 1;
			break;
		case '?':
			if (optopt != 0)
			{
				printf("ping: invalid option -- '%c'\n", optopt);
				printf("Try 'ping --help' or 'ping --usage' for more information.\n");
				return 64;
			}
			else
			{
				printf("usage: ping [-v] <hostname>\n");
				return 0;
			}
		default:
			printf("ping: invalid option -- '%c'\n", opt);
			printf("Try 'ping --help' or 'ping --usage' for more information.\n");
			return 64;
		}
	}
	if (!av[optind])
	{
		printf("ping: missing host operand\n");
		printf("Try 'ping --help' or 'ping --usage' for more information.\n");
		return 64;
	}

	struct addrinfo *res;
	if (dns_lookup(av[optind], &res) != 0)
	{
		printf("ping: unknown host\n");
		return 1;
	}

	int sockfd;
	char ip_addr[INET_ADDRSTRLEN];

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	struct timeval timeout;
	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = TIMEOUT_SEC;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	// if (ttl_flags != 0)
	// 	ttl_falgs
	// else
	// 	64
	int ttl = 3; // bonus
	setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

	struct sockaddr_in *addr;
	addr = (struct sockaddr_in *)res->ai_addr;
	inet_ntop(res->ai_family, &addr->sin_addr, ip_addr, sizeof(ip_addr));
	signal(SIGINT, sig_handler);
	printf("PING %s (%s): %d data bytes", av[optind], ip_addr, PACKET_SIZE - (int)sizeof(struct icmphdr));
	if (verbose)
		printf(", id 0x%x = %d", htons(getpid() & 0xFFFF), getpid() & 0xFFFF);
	printf("\n");

	send_ping(av[optind], sockfd, res, verbose);
	freeaddrinfo(res);
	return 0;
}

// w - timeout
// W - wait for response
// q - supress
// n - numeric
// c - count
// p - pattern
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

int dns_lookup(char *host, struct addrinfo *res)
{
	struct addrinfo hints;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;
	return getaddrinfo(host, NULL, &hints, &res);
}

void init_icmp_packet(char *packet, int sequence)
{
	struct icmphdr *hdr = (struct icmphdr *)packet;

	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->un.echo.id = getpid() & 0xFFFF;
	hdr->un.echo.sequence = sequence;
	memset(packet + sizeof(struct icmphdr), 0xAA, sizeof(packet) - sizeof(struct icmphdr));
	hdr->checksum = checksum(packet, sizeof(packet));
}

Icmp_error parse_recv_packet(char *packet)
{
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + (ip_hdr->ihl * 4));

	if (!packet)
		return ICMP_ERROR;
	if (strlen(packet) < sizeof(struct iphdr) + sizeof(struct icmphdr))
		return ICMP_ERROR;
	if (strlen(packet) < ip_hdr->ihl * 4 + sizeof(struct icmphdr))
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
		rtt->min = rtt->max = rtt->sum = rtt->avg = time_diff;
	}
	else
	{
		if (rtt->min > time_diff)
			rtt->min = time_diff;
		if (rtt->max < time_diff)
			rtt->max = time_diff;
		rtt->sum += time_diff;
	}
	rtt->avg = rtt->sum / ++(rtt->count);
}

void get_ip_addr(char *packet, char *ip_addr)
{
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_addr.s_addr = ip_hdr->saddr;
	inet_ntop(AF_INET, &addr.sin_addr, ip_addr, INET_ADDRSTRLEN);
}

void print_result(char *host, int sequence, int recv_count, t_rtt_stat rtt)
{
	printf("--- %s ping statistics ---\n", host);
	printf("%d packets transmitted, %d received, %d%% packet loss\n", sequence + 1, recv_count, (sequence + 1 - recv_count) * 100 / (sequence + 1));
	if (recv_count > 0)
	{
		double stddev = sqrt((rtt.sum / rtt.count) - (rtt.avg * rtt.avg));
		printf("round-trip min/avg/max/stddev = %.2f/%.2f/%.2f/%.2f ms\n", rtt.min, rtt.avg, rtt.max, stddev);
	}
}

void send_ping(char *host, int sockfd, struct addrinfo *send_res)
{
	int sequence = -1;
	int recv_count = 0;
	struct timeval send_time, recv_time;
	char send_packet[64];
	char recv_packet[1024];
	struct sockaddr *recv_res;
	t_rtt_stat rtt;

	while (g_flag_ping)
	{
		bzero(send_packet, sizeof(send_packet));
		bzero(recv_packet, sizeof(send_packet));
		bzero(recv_res, sizeof(recv_res));
		++sequence;
		init_icmp_packet(send_packet, sequence);

		gettimeofday(&send_time, NULL);
		if (sendto(sockfd, send_packet, sizeof(send_packet), 0, send_res->ai_addr, send_res->ai_addrlen) < 0)
		{
			usleep(PING_USEC);
			continue;
		}

		if (recvfrom(sockfd, recv_packet, sizeof(recv_packet), 0, recv_res, (socklen_t *)sizeof(recv_res)) < 0)
		{
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
		e = parse_recv_packet(recv_packet); // have to do
		if (e == ICMP_ERROR)
		{
			usleep(PING_USEC);
			continue;
		}
		update_rtt(&rtt, time_diff);
		char ip_addr[16];
		get_ip_addr(recv_packet, ip_addr);
		int payload_len = strlen(recv_packet) - sizeof(struct iphdr);
		if (e == ICMP_TIME_EXCEEDED_ERROR)
			fprintf(stderr, "From %s: icmp_seq=%d Time to live exceeded\n", ip_addr, sequence);
		else
			printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n", payload_len, ip_addr, sequence, ((struct iphdr *)recv_packet)->ttl, time_diff);
		++recv_count;
		usleep(PING_USEC);
	}
	print_result(host, sequence, recv_count, rtt);
	close(sockfd);
}

int main(int ac, char **av)
{
	struct addrinfo res;
	char ip_addr[INET_ADDRSTRLEN];

	if (dns_lookup(av[1], &res))
	{
		printf("ping: unknown host\n");
		return 1;
	}

	int sockfd;
	struct timeval timeout;

	bzero(&timeout, sizeof(timeout));
	timeout.tv_sec = TIMEOUT_SEC;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	inet_ntop(res.ai_family, &res.ai_addr, ip_addr, sizeof(ip_addr));
	signal(SIGINT, sig_handler);
	printf("PING %s (%s) %d bytes of data\n", av[1], ip_addr, (int)sizeof(struct icmphdr));
	send_ping(av[1], sockfd, &res);
	return 0;
}
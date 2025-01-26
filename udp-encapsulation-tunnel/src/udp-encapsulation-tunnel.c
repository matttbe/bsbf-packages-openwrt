#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <getopt.h>

// Compatibility layer for musl/glibc differences
#ifdef __GLIBC__
	// Using glibc
	#define udp_source source
	#define udp_dest dest
	#define udp_len len
	#define udp_check check
	#define tcp_check check
#else
	// Using musl
	#define udp_source uh_sport
	#define udp_dest uh_dport
	#define udp_len uh_ulen
	#define udp_check uh_sum
	#define tcp_check th_sum
#endif

#define BUFFER_SIZE 2048
#define IP_HEADER_LEN 20
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20

struct tunnel_config {
	char device[IFNAMSIZ];
	uint16_t listen_port;
	char bind_device[IFNAMSIZ];
	uint16_t endpoint_port;
};

// Function prototypes
int create_tun(char *dev);
int get_interface_ip(char *interface, struct in_addr *addr);
void process_tun_packet(int tun_fd, int udp_fd, struct tunnel_config *config);
void process_udp_packet(int tun_fd, int udp_fd, struct tunnel_config *config);
uint16_t ip_checksum(void *vdata, size_t length);
uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int len);
uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, void *payload, int payload_len);

int main(int argc, char *argv[]) {
	struct tunnel_config config;
	int option;
	
	// Parse command line arguments
	static struct option long_options[] = {
		{"device", required_argument, 0, 'd'},
		{"listen-port", required_argument, 0, 'l'},
		{"bind-to-device", required_argument, 0, 'b'},
		{"endpoint-port", required_argument, 0, 'e'},
		{0, 0, 0, 0}
	};

	while ((option = getopt_long(argc, argv, "d:l:b:e:", long_options, NULL)) != -1) {
		switch (option) {
			case 'd':
				strncpy(config.device, optarg, IFNAMSIZ-1);
				break;
			case 'l':
				config.listen_port = atoi(optarg);
				break;
			case 'b':
				strncpy(config.bind_device, optarg, IFNAMSIZ-1);
				break;
			case 'e':
				config.endpoint_port = atoi(optarg);
				break;
			default:
				fprintf(stderr, "Usage: %s --device tun0 --listen-port port --bind-to-device dev --endpoint-port port\n", argv[0]);
				exit(1);
		}
	}

	// Create and configure TUN interface
	int tun_fd = create_tun(config.device);
	if (tun_fd < 0) {
		fprintf(stderr, "Failed to create TUN interface\n");
		exit(1);
	}

	// Create UDP socket
	int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_fd < 0) {
		perror("socket");
		exit(1);
	}

	// Bind UDP socket to specific interface
	if (setsockopt(udp_fd, SOL_SOCKET, SO_BINDTODEVICE, config.bind_device, strlen(config.bind_device)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	// Bind UDP socket to listen port
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(config.listen_port);

	if (bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(1);
	}

	// Main loop
	fd_set readfds;
	while (1) {
		FD_ZERO(&readfds);
		FD_SET(tun_fd, &readfds);
		FD_SET(udp_fd, &readfds);
		int maxfd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

		if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(1);
		}

		if (FD_ISSET(tun_fd, &readfds)) {
			process_tun_packet(tun_fd, udp_fd, &config);
		}

		if (FD_ISSET(udp_fd, &readfds)) {
			process_udp_packet(tun_fd, udp_fd, &config);
		}
	}

	return 0;
}

int create_tun(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}

	return fd;
}

int get_interface_ip(char *interface, struct in_addr *addr) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	return 0;
}

uint16_t ip_checksum(void *vdata, size_t length) {
	// Cast the data to 16 bit chunks
	uint16_t *data = vdata;
	uint32_t sum = 0;
	
	while (length > 1) {
		sum += *data++;
		length -= 2;
	}
	
	// Add left-over byte, if any
	if (length > 0)
		sum += *(unsigned char *)data;
	
	// Fold 32-bit sum to 16 bits
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	
	return ~sum;
}

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int len) {
	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t tcp_length;
	} psh;
	
	// Fill pseudo header
	psh.source_address = ip->saddr;
	psh.dest_address = ip->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(len);
	
	// Allocate memory for the calculation
	int total_len = sizeof(struct pseudo_header) + len;
	char *pseudogram = malloc(total_len);
	
	// Copy pseudo header
	memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
	
	// Copy TCP header + data
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp, len);
	
	// Calculate checksum
	uint16_t checksum = ip_checksum(pseudogram, total_len);
	
	free(pseudogram);
	return checksum;
}

uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp, void *payload, int payload_len) {
	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t udp_length;
	} psh;

	psh.source_address = ip->saddr;
	psh.dest_address = ip->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = udp->udp_len;

	int total_len = sizeof(struct pseudo_header) + ntohs(udp->udp_len);
	char *pseudogram = malloc(total_len);

	memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udp, sizeof(struct udphdr));
	memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct udphdr), payload, payload_len);

	uint16_t checksum = ip_checksum(pseudogram, total_len);

	free(pseudogram);
	return checksum;
}

void process_tun_packet(int tun_fd, int udp_fd, struct tunnel_config *config) {
	unsigned char buffer[BUFFER_SIZE];
	unsigned char encap_buffer[BUFFER_SIZE];
	int len;

	len = read(tun_fd, buffer, BUFFER_SIZE);
	if (len < 0) {
		perror("read");
		return;
	}

	struct iphdr *ip = (struct iphdr *)buffer;
	if (ip->protocol != IPPROTO_TCP) {
		return; // Only process TCP packets
	}

	// Create new IP + UDP header
	struct iphdr *new_ip = (struct iphdr *)encap_buffer;
	struct udphdr *udp = (struct udphdr *)(encap_buffer + IP_HEADER_LEN);

	// Get source IP from bound interface
	struct in_addr src_addr;
	if (get_interface_ip(config->bind_device, &src_addr) < 0) {
		fprintf(stderr, "Failed to get interface IP\n");
		return;
	}

	// Setup new IP header
	memset(new_ip, 0, IP_HEADER_LEN);
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->tos = ip->tos;
	new_ip->tot_len = htons(len + UDP_HEADER_LEN);
	new_ip->id = htons(rand());
	new_ip->ttl = 64;
	new_ip->protocol = IPPROTO_UDP;
	new_ip->saddr = src_addr.s_addr;
	new_ip->daddr = ip->daddr;

	// Calculate IP header checksum
	new_ip->check = 0;
	new_ip->check = ip_checksum(new_ip, IP_HEADER_LEN);

	// Setup UDP header
	udp->udp_source = htons(config->listen_port);
	udp->udp_dest = htons(config->endpoint_port);
	udp->udp_len = htons(len - IP_HEADER_LEN + UDP_HEADER_LEN);
	
	// Copy original TCP payload
	memcpy(encap_buffer + IP_HEADER_LEN + UDP_HEADER_LEN, 
		   buffer + IP_HEADER_LEN, 
		   len - IP_HEADER_LEN);

	// Calculate UDP checksum
	udp->udp_check = 0;
	udp->udp_check = udp_checksum(new_ip, udp, buffer + IP_HEADER_LEN, len - IP_HEADER_LEN);

	// Send encapsulated packet
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = ip->daddr;
	dest.sin_port = htons(config->endpoint_port);

	sendto(udp_fd, encap_buffer, len + UDP_HEADER_LEN, 0,
		   (struct sockaddr*)&dest, sizeof(dest));
}

void process_udp_packet(int tun_fd, int udp_fd, struct tunnel_config *config) {
	unsigned char buffer[BUFFER_SIZE];
	unsigned char decap_buffer[BUFFER_SIZE];
	struct sockaddr_in src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	int len;

	len = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0,
				   (struct sockaddr*)&src_addr, &src_addr_len);
	if (len < 0) {
		perror("recvfrom");
		return;
	}

	struct iphdr *ip = (struct iphdr *)buffer;
	struct udphdr *udp = (struct udphdr *)(buffer + IP_HEADER_LEN);

	// Verify this is a UDP packet for our listen port
	if (ip->protocol != IPPROTO_UDP || 
		ntohs(udp->udp_dest) != config->listen_port) {
		return;
	}

	// Get tunnel interface IP address
	struct in_addr tun_addr;
	if (get_interface_ip(config->device, &tun_addr) < 0) {
		fprintf(stderr, "Failed to get tunnel interface IP\n");
		return;
	}

	// Create decapsulated packet
	struct iphdr *new_ip = (struct iphdr *)decap_buffer;
	
	// Setup new IP header
	memset(new_ip, 0, IP_HEADER_LEN);
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->tos = ip->tos;
	new_ip->tot_len = htons(len - UDP_HEADER_LEN);
	new_ip->id = htons(rand());
	new_ip->ttl = 64;
	new_ip->protocol = IPPROTO_TCP;
	new_ip->saddr = src_addr.sin_addr.s_addr;
	new_ip->daddr = tun_addr.s_addr;

	// Calculate IP header checksum
	new_ip->check = 0;
	new_ip->check = ip_checksum(new_ip, IP_HEADER_LEN);

	// Copy TCP payload
	memcpy(decap_buffer + IP_HEADER_LEN,
		   buffer + IP_HEADER_LEN + UDP_HEADER_LEN,
		   len - IP_HEADER_LEN - UDP_HEADER_LEN);

	// Calculate TCP checksum
	struct tcphdr *tcp = (struct tcphdr *)(decap_buffer + IP_HEADER_LEN);
	tcp->tcp_check = 0;
	tcp->tcp_check = tcp_checksum(new_ip, tcp, len - IP_HEADER_LEN - UDP_HEADER_LEN);

	// Write to TUN interface
	write(tun_fd, decap_buffer, len - UDP_HEADER_LEN);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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
	#define tcp_check check
	#define tcp_source source
	#define tcp_dest dest
#else
	// Using musl
	#define tcp_check th_sum
	#define tcp_source th_sport
	#define tcp_dest th_dport
#endif

#define BUFFER_SIZE 2048
#define IP_HEADER_LEN 20  // TODO: can be more if there are options, check IHL
                          // TODO: what about IPv6? IPv6 would be easier, no NAT...
#define UDP_HEADER_LEN 8
#define TCP_HEADER_LEN 20 // TODO: can be more if there are options, check len

// Connection store entry structure - stores (IPv4 saddr, UDP sport, TCP sport)
struct connection_store {           // TODO: "source" in the comment + name + functions below is confusing, it depends on which direction you look. Client IP + port instead?
	struct in_addr ip_saddr;    // Source IP address
	uint16_t udp_sport;         // Source UDP port
	uint16_t tcp_sport;         // Source TCP port
	struct connection_store *next; // TODO: avoid using a list (O(n)), use a HashMap (O(1))
	// TODO: store a timestamp: to be able to remove old entries, and handle conflicts: same IP + TCP port, but different UDP port
};

struct tunnel_config {
	char device[IFNAMSIZ]; // TODO: typically called "interface" or "iface"?
	uint16_t listen_port;
	char bind_device[IFNAMSIZ];
	uint16_t endpoint_port; // TODO: typically called "destination_port" or "dport"?
	struct connection_store *store; // TODO: avoid using a list (O(n)), use a HashMap (O(1))
};

// TODO: for the hashmap, we could have optimisations on the structure, because the number of clients (IP addr + UDP port) should be limited, while the number of TCP connections can be important.
// We could then store a hashmap of IP address, and each one would have a hashmap of TCP ports. (A list of UDP ports could be used per IP address: if there is only one item, no need to find the corresponding TCP connection. But still needed to store them in case another client is added later)

// Store connection information (IPv4 saddr, UDP sport, TCP sport)
static void store_connection(struct tunnel_config *config, struct in_addr saddr, uint16_t udp_sport, uint16_t tcp_sport) {
	struct connection_store *current = config->store;

	// Check if entry already exists
	while (current != NULL) {
		if (current->ip_saddr.s_addr == saddr.s_addr &&
			current->udp_sport == udp_sport && // TODO: if ADDR + TCP port match, but not UDP port, we have a conflict: check timestamp and either block the connection (e.g. different client behind the same IP), or replace (e.g. tunnel has been restarted) → we cannot predict that which one, seems safer to block
			current->tcp_sport == tcp_sport) {
			// TODO: Update timestamps here
			return; // Entry already exists
		}
		current = current->next;
	}

	// Create new entry
	struct connection_store *entry = malloc(sizeof(struct connection_store));
	entry->ip_saddr = saddr;
	entry->udp_sport = udp_sport;
	entry->tcp_sport = tcp_sport;
	entry->next = config->store;
	config->store = entry;
	// TODO: we need a way to remove old entries based on a timestamp because an entry will be create for each TCP connection, so very likely thousands per minute / second on a busy server.
}

// Get stored UDP port for given IPv4 address and TCP port
static uint16_t get_stored_port(struct tunnel_config *config, struct in_addr daddr, uint16_t tcp_dport) {
	struct connection_store *current = config->store;
	while (current != NULL) {
		if (current->ip_saddr.s_addr == daddr.s_addr &&
			current->tcp_sport == tcp_dport) {
			return current->udp_sport;
		}
		current = current->next;
	}
	return 0; // No matching entry found
}

static int create_tun(char *dev) {
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

static int get_interface_ip(char *interface, struct in_addr *addr) {
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

static uint16_t ip_checksum(void *vdata, size_t length) {
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

static uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int len) {
	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t tcp_length;
	};

	struct {
		struct pseudo_header hdr;
		unsigned char tcp[BUFFER_SIZE];
	} buffer;

	// Fill pseudo header
	buffer.hdr.source_address = ip->saddr;
	buffer.hdr.dest_address = ip->daddr;
	buffer.hdr.placeholder = 0;
	buffer.hdr.protocol = IPPROTO_TCP;
	buffer.hdr.tcp_length = htons(len);

	// Allocate memory for the calculation
	int total_len = sizeof(struct pseudo_header) + len;

	// Copy pseudo header and TCP header + data
	memcpy(&buffer.tcp, tcp, len);

	// Calculate checksum
	uint16_t checksum = ip_checksum(&buffer, total_len);

	return checksum;
}

// encapsulate: read from TUN and write TCP header + payload to UDP socket
static void process_tun_packet(int tun_fd, int udp_fd, struct tunnel_config *config) {
	unsigned char buffer[BUFFER_SIZE];
	int len;

	len = read(tun_fd, buffer, BUFFER_SIZE);
	if (len < 0) {
		perror("read");
		return;
	}

	struct iphdr *ip = (struct iphdr *)buffer;
	if (len < IP_HEADER_LEN || ip->protocol != IPPROTO_TCP) {
		return; // Only process TCP packets
	}

	// TODO: use len from ip->ihl and the size in byte should be >= IP_HEADER_LEN
	// TODO: len should then be >= len(ip_hdr) + len(tcp_hdr), min 20 + 20
	struct tcphdr *tcp = (struct tcphdr *)(buffer + IP_HEADER_LEN);
	struct in_addr daddr;
	daddr.s_addr = ip->daddr;
	uint16_t dport;

	// Determine destination UDP port based on endpoint_port or stored connection
	if (config->endpoint_port == 0) {
		// On the server side, no known dport: it cannot be predicted in
		// case of CGNAT (multiple clients behind the same IPv4 -- would
		// be simpler in IPv6 without NAT!), it needs to find it back
		// from previous connections
		dport = get_stored_port(config, daddr, ntohs(tcp->tcp_dest));
		if (dport == 0) {
			return; // No stored port and no endpoint port configured
		}
	} else {
		// On the client side, the dport is known
		dport = config->endpoint_port;
	}

	// Send encapsulated packet
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = ip->daddr;
	dest.sin_port = htons(dport);

	sendto(udp_fd, tcp, len - IP_HEADER_LEN - UDP_HEADER_LEN, 0,
		   (struct sockaddr*)&dest, sizeof(dest));
}

// decapsulate: read from UDP socket, write to TUN
static void process_udp_packet(int tun_fd, int udp_fd, struct tunnel_config *config) {
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

	struct tcphdr *tcp = (struct tcphdr *)buffer;
	if (len < TCP_HEADER_LEN)
		return;

	// TODO: add some sanity checks, e.g. checking to see if the data in the buffer looks OK? e.g. checking if there are MPTCP options? Maybe something else?

	if (config->endpoint_port == 0) {
		// Store the connection information (IPv4 saddr, UDP sport, TCP sport)
		struct in_addr src_addr_ip;
		src_addr_ip.s_addr = src_addr.sin_addr.s_addr;
		store_connection(config, src_addr_ip,
						ntohs(src_addr.sin_port),
						ntohs(tcp->tcp_source));
	}

	// Get tunnel interface IP address
	// TODO: unlikely to change, do it only once in main()?
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
	new_ip->tos = 0;
	new_ip->tot_len = htons(len + IP_HEADER_LEN);
	new_ip->id = htons(rand());
	new_ip->ttl = 1; // It should not go further than one hop
	new_ip->protocol = IPPROTO_TCP;
	new_ip->saddr = src_addr.sin_addr.s_addr;
	new_ip->daddr = tun_addr.s_addr;

	// Calculate IP header checksum
	new_ip->check = 0;
	new_ip->check = ip_checksum(new_ip, IP_HEADER_LEN);

	// Copy TCP payload
	memcpy(decap_buffer + IP_HEADER_LEN, buffer, len);

	// Calculate TCP checksum
	// TODO: it should not be needed on the server side if the TUN address is the same as the public one.
	//       (on the client side, we might not have the public IP)
	struct tcphdr *new_tcp = (struct tcphdr *)(decap_buffer + IP_HEADER_LEN);
	new_tcp->tcp_check = 0;
	new_tcp->tcp_check = tcp_checksum(new_ip, new_tcp, len);

	// Write decapsulated packet to TUN interface
	write(tun_fd, decap_buffer, len - UDP_HEADER_LEN);
}

int main(int argc, char *argv[]) {
	struct tunnel_config config = {0};  // Initialize all fields to 0
	config.store = NULL;  // Initialize connection store
	int option;

	// Parse command line arguments
	static struct option long_options[] = {
		{"device", required_argument, 0, 'd'}, // TODO: typically called "interface" | 'i'?
		{"listen-port", required_argument, 0, 'l'},
		{"bind-to-device", required_argument, 0, 'b'},
		{"endpoint-port", required_argument, 0, 'e'}, // TODO: typically called "destination-port" | 'd'?
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

	// Validate mandatory options
	if (config.device[0] == '\0' || config.listen_port == 0 || config.bind_device[0] == '\0') {
		fprintf(stderr, "Error: device, listen-port, and bind-to-device are mandatory options\n");
		exit(1);
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
	// TODO: bind() should only be needed on the server side:
	//       the client will initiate the connections
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(config.listen_port);

	if (bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(1);
	}

	printf("Tunnel started:\n");
	printf("  TUN device: %s\n", config.device);
	printf("  Bound to device: %s\n", config.bind_device);
	printf("  Listening on port: %d\n", config.listen_port);
	if (config.endpoint_port) {
		printf("  Endpoint port: %d\n", config.endpoint_port);
	}

	// Main loop
	// TODO: use multiple workers to be able to scale on a server with more than one core
	fd_set readfds;
	while (1) {
		FD_ZERO(&readfds);
		FD_SET(tun_fd, &readfds);
		FD_SET(udp_fd, &readfds);
		int maxfd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

		// TODO: use io_uring if possible? (or at least epoll)
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

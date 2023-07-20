#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

typedef struct {
	
	// ethernet
	uint8_t ether_dest[ETHER_ADDR_LEN]; // dest mac addr
	uint8_t ether_src[ETHER_ADDR_LEN]; // source mac addr
	
	uint8_t ether_type[2]; // ether type, 2byte
	
	// IP
	uint8_t ip_v_hl; // ip Version and Header Length
	uint8_t ip_tos; // ip type of service
	uint8_t ip_total_length[2]; // ip total length, 2byte
	uint8_t ip_id[2]; // ip Identification, 2byte
	uint8_t ip_flag_frag[2]; // ip flags, fragment offset
	uint8_t ip_ttl; // ip TTL
	
	uint8_t ip_proto_type; // ip protocol type
	
	uint8_t ip_h_ck[2]; // ip header checksum
	
	uint8_t ip_src[4]; // source ip address
	uint8_t ip_dst[4]; // destination ip address
	
	// TCP
	uint16_t tcp_src_port;
	uint16_t tcp_dst_port;
	
	uint32_t tcp_seq; // tcp sequence number, 4byte
	uint32_t tcp_ack; // tcp ACK number, 4byte
	
	uint16_t tcp_hl_re_flags; // tcp header length, reserved, uaprsf
	
	uint16_t tcp_win_size; // tcp window size
	uint16_t tcp_cksum; // tcp checksum
	uint16_t tcp_urg_point; // tcp urgent point
	
	uint8_t payload[10]; // after tcp payload (least 10 bytes)
	
}pktHeader;

void printMac(uint8_t *h) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", h[0], h[1], h[2], h[3], h[4], h[5]);
}

void printIP(uint8_t *addr) {
	printf("%d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
}

void printPort(uint16_t port) {
	printf("%d\n", port);
}

void printPayload(uint8_t *data) {

	for(int i=0; i<10; i++)
		printf("%02x ", data[i]);
		
	putchar('\n');

}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		pktHeader *h = (pktHeader *) packet;
		
		// filtering non-IPv4 packet
		//uint16_t eType = ntohs(h->ether_type);
		//printf("%04x\n", eType);
		//if(eType != 0x0800)
		//	continue;
		
		uint8_t *eType = h->ether_type;
		printf("ether type: %02x %02x\n", eType[0], eType[1]);
		if(eType[0] != 0x08 || eType[1] !=0x00)
			continue;
		
		
		// filtering non-TCP packet
		if(h->ip_proto_type != 0x06)
			continue;
		
		
		puts("Ethernet");
		printf("source mac: ");
		printMac(h->ether_dest);
		
		printf("destination mac: ");
		printMac(h->ether_src);
		
		printf("ether type: %02x %02x\n", eType[0], eType[1]);
		
		puts("\nIP");
		printf("source IP: ");
		printIP(h->ip_src);
		
		printf("destination IP: ");
		printIP(h->ip_dst);
		
		// printf("ip protocol type: ");
		// printf("%0x02x\n", h->ip_proto_type);
		
		puts("\nTCP");
		printf("source Port: ");
		printPort(h->tcp_src_port);
		
		printf("destination Port: ");
		printPort(h->tcp_dst_port);
		
		
		puts("\nPayload");
		printPayload(h->payload);
		
		puts("\n\n");
		
	}

	pcap_close(pcap);
}

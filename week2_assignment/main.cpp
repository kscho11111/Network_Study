#include <arpa/inet.h>
#include <pcap.h>
#include "pcap_struct.h"
#include <stdio.h>
#include <stdint.h>

void usage(){
	puts("syntax: ./pcap_test interface");
	puts("sample: ./pcap_test wlan0");
}

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char* argv[]){
	if(argc != 2){
		usage();
		return 1;
	}
	char* interface = argv[1];
	pcap_t *pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if (interface == NULL){
		fprintf(stderr, "Can not find default device: %s\n", errbuf);
		return 1;
	}
	if (pcap == NULL){
		fprintf(stderr, "Can not open device: %s\n", errbuf);
		return 1;
	}


	while(true){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;

		printf("Packet Length: %u\n", header->caplen);

		const struct eth_hdr* pk_eth = (const struct eth_hdr*)packet;
		printf("Ethernet Header\n");
		printf("SRC MAC: ");
		for(int i=0; i < ETH_ALEN; ++i){
			printf("%s%02X", (i ? ":" : " "), pk_eth->src[i]);
		}

		printf("\n");
		printf("DST MAC: ");

		for(int i = 0; i < ETH_ALEN; ++i){
			printf("%s%02X", (i  ? ":" : " "), pk_eth->dst[i]);
		}

		printf("\n");

		int eth_type = ntohs(pk_eth->type);
		if(eth_type != 0x0800){
			printf("Ethertype : not IPv4\n");
			continue;
		}

		printf("Ethertype : IPv4\n\n");

		const struct ipv4_hdr *pk_ipv4 = (const struct ipv4_hdr *)pk_eth->data;
		printf("IP Header\n");
		printf("SRC IP: ");

		for (int i = 0; i < IPV4_ALEN; ++i){
			printf("%s%d", (i ? "." : ""), pk_ipv4->src[i]);
		}
		printf("\n");
		printf("DST IP: ");

		for(int i = 0; i< IPV4_ALEN; ++i){
			printf("%s%d", (i ? "." : ""), pk_ipv4->dst[i]);
		}

		printf("\n");

		uint8_t ihl = IPV4_HL(pk_ipv4);
		if(ihl < IPV4_HL_MIN){
			printf("Invalid IPv4 packet\n\n\n");
			return 2;
		}

		if(pk_ipv4->protocol != 0x06){
			printf("IPv4 protocol: not TCP\n\n\n");
			continue;
		}

		printf("IPv4 protocol: TCP\n\n");

		const struct tcp_hdr* pk_tcp = (const struct tcp_hdr*)&pk_ipv4->data[ihl - IPV4_HL_MIN];

		uint16_t length = ntohs(pk_ipv4->length) - ihl;
		printf("TCP Header\n");
		printf("SRC PORT: %d\n", ntohs(pk_tcp->src));
		printf("DST PORT: %d\n", ntohs(pk_tcp->dst));

		printf("\n");

		uint8_t thl = TCP_HL(pk_tcp);
		if (thl < 20 || thl > 60){
			printf("Invaild TCP packet\n\n\n");
			return 2;
		}

		uint32_t tl = length - thl;

		printf("PayLoad: ");

		if(tl > TCP_PAYLOAD_MAXLEN){
			tl = TCP_PAYLOAD_MAXLEN;
		}

		for(uint32_t i=0; i < tl; ++i){
			printf("%s%02X", (i ? " " : ""), pk_tcp->payload[thl - 20 + i]);
		}
		printf("\n\n\n");
	}
	pcap_close(pcap);

	return 0;
}

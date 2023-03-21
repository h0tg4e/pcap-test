#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

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

typedef struct Ethernet_Header
{
	u_char dst_mac[6];
	u_char src_mac[6];
	short type;
}Et_h;

typedef struct IP_Header
{
	u_char size;
	u_char d;
	u_char total_size[2];
	u_char dummy[5];
	u_char protocol;
	u_char dum[2];
	u_char src_ip[4];
	u_char dst_ip[4];
}IP_h;


typedef struct TCP_Header
{
	u_char src_port[2];
	u_char dst_port[2];
	u_char dum[8];
	u_char size;
}TCP_h;



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

	Et_h* et;
	IP_h* ip;
	TCP_h* tc;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		et = (Et_h*)packet;
		ip = (IP_h*)(packet + 14);
		int ip_size = ((int)(ip->size) % 16) * 4;
		tc = (TCP_h*)(packet + ip_size + 14);
		int tcp_size = ((int)(tc->size) / 16) * 4;
		int data_size = (int)(ip->total_size[0]) * 16 * 16 + (int)(ip->total_size[1]) - ip_size - tcp_size;

		if (et->type != 8) {
			printf("This is not IPv4.\n");
			break;
		}

		if (ip->protocol != 6) {
			printf("This is not TCP protocol.\n");
			break;
		}

		printf("------------------------------------\n\n\n");
		printf("-----------Ethernet Header----------\n");
		printf("src mac: ");
		for (int i = 0; i < 6; i++) {
			if (i < 5)
				printf("%02x ", et->src_mac[i]);
			else
				printf("%02x\n", et->src_mac[i]);
		}
		printf("dst mac: ");
		for (int i = 0; i < 6; i++) {
			if (i < 5)
				printf("%02x ", et->dst_mac[i]);
			else
				printf("%02x\n", et->dst_mac[i]);
		}
		printf("--------------IP Header-------------\n");
		printf("src ip: ");
		for (int i = 0; i < 4; i++) {
			if (i < 3)
				printf("%02x ", ip->src_ip[i]);
			else
				printf("%02x\n", ip->src_ip[i]);
		}
		printf("dst ip: ");
		for (int i = 0; i < 4; i++) {
			if (i < 3)
				printf("%02x ", ip->dst_ip[i]);
			else
				printf("%02x\n", ip->dst_ip[i]);
		}
		printf("--------------TCP Header-------------\n");
		printf("src port: %02x ", tc->src_port[0]);
		printf("%02x\n", tc->src_port[1]);
		printf("dst port: %02x ", tc->dst_port[0]);
		printf("%02x\n", tc->dst_port[1]);
		printf("-----------------Data----------------\n");
		packet += (u_char)(14 + ip_size + tcp_size);
		if (data_size == 0) {
			for (int i = 0; i < 10; i++) {
				printf("00 ");
			}
		}
		else if (data_size < 10) {
			for (int i = 0; i < data_size; i++) {
				printf("%02x ", packet[i]);
			}
			for (int i = 0; i < 10 - data_size; i++) {
				printf("00 ");
			}
		}
		else {
			for (int i = 0; i < 10; i++) {
				printf("%02x ", packet[i]);
			}
		}
		printf("\n");
	}
	pcap_close(pcap);
}

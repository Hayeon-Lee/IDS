#ifndef DETECTPACKET_H
#define DETECTPACKET_H

#include <netinet/if_ether.h>
#include <pcap.h>
#include <netinet/in.h>

int startDetectThread(void *detectstruct);
void makePacketNode(const u_char *packet, struct pcap_pkthdr *header);
unsigned short readEthernet(const u_char *packet, Packet *packet_node);
int readIPV4(const u_char *packet, Packet *packet_node);
int readUDP (const u_char *packet, int ipsize, Packet *packet_node);

#endif

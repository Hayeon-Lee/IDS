#ifndef DETECTPACKET_H
#define DETECTPACKET_H

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <netinet/in.h>
#include <stdint.h>

typedef struct {
  int length;

  unsigned char dstmac[6];
  unsigned char srcmac[6];
  unsigned short ethertype;

  long long srcip; //host to network 변환됨
  long long dstip; //host to network 변환됨
  int protocol;

  int srcport; //host to network 변환됨
  int dstport; //host to network 변환됨

  short flag_payload;
  int size_payload;
  char payload[1461];

  int type; //icmp type
} PacketNode;

void initPacketNode(PacketNode *node);
void *startDetectThread(void * detectstruct);
PacketNode makePacketNode(u_char *packet, int caplen);
unsigned short readEthernet(u_char *packet, PacketNode *node);
int readIPV4(u_char *packet, PacketNode *node);
int readUDP (u_char *packet, PacketNode *node);
int readTCP(u_char *packet, PacketNode *node);
int readICMP(u_char *packet, PacketNode *node);
int isICMP(u_char *packet);
int read_ether_icmp(u_char *packet, PacketNode *node);

int checkNode(PacketNode node, Rule rule);
int match_pattern(char *payload, char *pattern, int size_payload);
DangerPacket * makeDangerPacket(PacketNode node, char * rulename, char *rulecontent); 
#endif

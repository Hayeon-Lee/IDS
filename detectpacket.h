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

void *start_detectthread(void * detectstruct);
void init_packet_node(PacketNode *node);
PacketNode parse_packet_node(u_char *packet, int caplen);
unsigned short decode_ethernet_header(u_char *packet, PacketNode *node);
int decode_ipv4_header(u_char *packet, PacketNode *node);
int decode_udp_header(u_char *packet, PacketNode *node);
int decode_tcp_header(u_char *packet, PacketNode *node);
int decode_icmp_header(u_char *packet, PacketNode *node);
int is_icmp(u_char *packet);
int decode_ether_icmp_header(u_char *packet, PacketNode *node);

int match_node_with_rule(PacketNode node, Rule rule);
int match_node_with_rule_pattern(char *payload, char *pattern, int size_payload);
DangerPacket *make_danger_packet(PacketNode node, char * rulename, char *rulecontent); 
#endif

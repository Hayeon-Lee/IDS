#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "queue.h"
#include "detectpacket.h"


int startDetectThread(void * detectstruct) { 
  PacketQueue *pkt_queue = ((DetectStruct *)detectstruct)->packetqueue;
  Rule rulestruct = ((DetectStruct *)detectstruct)->rulestruct;

  while(1){
    sleep(1);

    Packet *item = dequeuePacket(pkt_queue);

    if (item) {
      PacketNode node;
      node = makePacketNode(item->packet, item->caplen);
      printf("%d\n", node.protocol);
    }
  }
}

void initPacketNode(PacketNode *node){
  node->length = -1;
  
  node->ethertype = -1;

  node->srcip = -1;
  node->dstip = -1;
  node->protocol = -1;

  node->srcport = -1;
  node->dstport = -1;

  //payload 유무, payload 사이즈
  node->flag_payload = 0;
  node->size_payload = 0;
}

PacketNode makePacketNode (u_char *packet, int caplen) { 
  PacketNode node;
  initPacketNode(&node);
  
  //이더넷 헤더일 경우
  if (caplen >= 14) {
    //node 길이 초기화
    node.length = caplen;
    unsigned short type = readEthernet(packet, &node);

    //IPV4
    if (type == ETHERTYPE_IP && caplen >= 34) {
      int protocol = readIPV4(packet, &node);

      //TCP
      if (protocol == 6 && caplen >= 54) {
        readTCP(packet, &node);
        printf("tcp입니다\n");
      }
      //UDP
      if (protocol == 17 && caplen >= 42) {
        readUDP(packet, &node);
        printf("udp입니다\n");  
      }
      //ICMP
      if (protocol == 1 && caplen >= 42) {
        printf("icmp입니다.\n");
      }
    }
  }

  return node;
}

unsigned short readEthernet(u_char *packet, PacketNode *node ) {

  struct ether_header *eth_header;
  eth_header = (struct ether_header*)packet;

  node->ethertype = ntohs(eth_header->ether_type);
  memcpy(node->dstmac, eth_header->ether_dhost, ETH_ALEN);
  memcpy(node->srcmac, eth_header->ether_shost, ETH_ALEN);

  return ntohs(eth_header->ether_type);
}

int readIPV4(u_char *packet, PacketNode *node) {
  struct ip *ip_header = (struct ip*)(packet+sizeof(struct ether_header));
  node->srcip = htonl(ip_header->ip_src.s_addr);
  node->dstip = htonl(ip_header->ip_dst.s_addr);
  node->protocol = ip_header->ip_p;
  return ip_header->ip_p;
}

int readUDP(u_char *packet, PacketNode *node) {
  int ether_size = sizeof(struct ether_header);
  int add_size = ether_size + 20;

  struct udphdr *udp_header = (struct udphdr*)(packet + add_size); 
  node->srcport = udp_header->uh_sport;
  node->dstport = udp_header->uh_dport;

  if (node->length > 42) {
    node->flag_payload = 1;
    int payload_size = (node->length) - 42; 
    node->size_payload = payload_size;
    memcpy(node->payload, (packet+41), payload_size); 
  }

  return 0;
}

int readTCP(u_char *packet, PacketNode *node) {
  int ether_size = sizeof(struct ether_header);
  int add_size = ether_size + 20;

  struct tcphdr *tcp_header = (struct tcphdr*)(packet+add_size);

  node->srcport = htons(tcp_header->th_sport);
  node->dstport = htons(tcp_header->th_dport);
  
  if (tcp_header->th_flags & TH_PUSH) {
    node->flag_payload = 1;
    int payload_size = (node->length) - 54;
    node->size_payload = payload_size;
    memcpy(node->payload, (packet+53), payload_size);
  }    

  return 0;
}

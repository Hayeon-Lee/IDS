#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "queue.h"
#include "detectpacket.h"

int startDetectThread(void *detectstruct);
unsigned short readEthernet(const u_char *packet, Packet *packet_node);
int readIPV4(const u_char *packet, Packet *packet_node);
int readUDP (const u_char *packet, int ipsize, Packet *packet_node);

int startDetectThread(void * detectstruct) {
  DetectStruct *tmpstruct = (DetectStruct *)detectstruct;
  PacketQueue *tmpqueue = tmpstruct->packetqueue;
  
  while(1){
    sleep(1);
    dequeuePacket(tmpqueue);
    printf("dequeue: %d\n", tmpqueue->count);
  }
}

void makePacketNode (const u_char *packet, struct pcap_pkthdr *header) { 
  Packet packet_node;

  if (header->caplen >= 14) {
    //이더넷 헤더
    unsigned short type = readEthernet(packet, &packet_node);
    
    //IPV4
    if (type == ETHERTYPE_IP && header->caplen >= 34) {
     // int protocol = readIPV4(packet, &packet_node);
      
      int protocol =0; 
      //TCP
      if (protocol == 6 && header->caplen >= 54) {
        printf("tcp입니다\n");
      }
      //UDP
      if (protocol == 17 && header->caplen >= 42) {
     //   readUDP(packet, 20, &packet_node);
        //printf("%u\n", packet_node.dstport);
        printf("udp입니다\n");
      }
      //ICMP
      if (protocol == 1 && header->caplen >= 42) {
        printf("icmp입니다.\n");
      }
    }
  }
}

unsigned short readEthernet(const u_char *packet, Packet *packet_node) {

    struct ether_header *eth_header;
    eth_header = (struct ether_header*)packet;

    //packet_node->ethernet_header = eth_header;

    //return ntohs(packet_node->ethernet_header->ether_type);
}

int readIPV4(const u_char *packet, Packet * packet_node) {

    struct ip *ip_header = (struct ip*)(packet+sizeof(struct ether_header));
 //   packet_node->srcip = ip_header->ip_src;
  //  packet_node->dstip = ip_header->ip_dst;
  //  packet_node->protocol = ip_header->ip_p;

 //   return packet_node->protocol;
}

int readUDP(const u_char *packet, int ipsize, Packet *packet_node) {
    int ether_size = sizeof(struct ether_header);
    int add_size = ether_size + ipsize;

    struct udphdr *udp_header = (struct udphdr*)(packet + add_size); 
  
 //   packet_node->srcport = udp_header->uh_sport;
  //  packet_node->dstport = udp_header->uh_dport;
    return 0;
}

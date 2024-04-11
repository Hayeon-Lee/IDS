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
  Rule rule = ((DetectStruct *)detectstruct)->rulestruct;

  while(1){
    sleep(1);

    Packet *item = dequeuePacket(pkt_queue);

    if (item) {
      PacketNode node;
      node = makePacketNode(item->packet, item->caplen);
      int rulenum = checkNode(node, rule);

      if (rulenum != -1) {
          
      } 
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
      }
      //UDP
      if (protocol == 17 && caplen >= 42) {
        readUDP(packet, &node);
      }
      //ICMP
      if (protocol == 1 && caplen >= 42) {
        printf("ICMP\n");
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
    
    for (int i=0; i<payload_size; i++) {
      node->payload[i] = packet[53+i];
    }
  }    

  return 0;
}

int checkNode(PacketNode node, Rule rule){

  //정책에는 pattern이 반드시 있으므로 payload가 0이면 검사하지 않음
  if (node.flag_payload == 0) {
    return -1;
  }

  int i=0;
  
  short flag=0;
  short result=0;
  
   
  //flag 는 첫 번째로 정책을 어겼는지 확인 (result = 1 로 초기화)
  //정책과 노드의 값이 모두 있는데 다르면 더 이상 확인할 필요 없음 
  for(i=0; i<rule.cnt; i++) {
    
     //패턴 검사
    if (match_pattern(node.payload, rule.rules[i].pattern, node.size_payload)==1) {
      if (flag == 0) {
        flag = 1;
        result = 1;
      }
      else result &= 1;
    }
    else continue;   
  
    if (rule.rules[i].srcip != -1 && node.srcip != -1){
      if (rule.rules[i].srcip == node.srcip) {
        if (flag == 0) {
            flag = 1;
            result = 1;
        }
        else result &= 1;
      }
      else continue;  
    }
    if (rule.rules[i].dstip != -1 && node.dstip != -1){
      if (rule.rules[i].dstip == node.dstip){
        if (flag == 0) {
            flag = 1;
            result = 1;
        }
        else result &= 1;
      }
      else continue;
    }
    if (rule.rules[i].srcport != -1 && node.srcport != -1) {
      if (rule.rules[i].srcport == node.srcport) {
        if (flag == 0) {
            flag = 1;
            result = 1;
        }
        else result &= 1;
      }
      else continue;
    }
    if (rule.rules[i].dstport != -1 && node.dstport != -1){
      if (rule.rules[i].dstport == node.dstport) {
        if (flag == 0) {
            flag = 1;
            result = 1;
        }
        else result &= 1;
      }
      else continue;  
    }   
    if (result == 1) {
      printf("위험해요~\n");
      return i;
    }
    else {
      flag = 0;
      result = 0;
    }
  } 
      
   
  return -1;
}

int match_pattern(char *payload, char *pattern, int size_payload){
  if (strlen(pattern)>size_payload) {
    return -1;
  }
  
  for(int i=0; i<size_payload; i++) {
    int j = 0;
    int flag = 0;

    if (payload[i] == pattern[j]) {
      for(j=0; j<strlen(pattern); j++) {
        if (payload[i+j] != pattern[j]) {
            flag = 1;
            break;
        }
        else continue;
      }
      if (flag == 0) {
        return 1;
      }
    }
  }
 
  return -1;
}

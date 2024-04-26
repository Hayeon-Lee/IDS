#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>

#include "queue.h"
#include "detectpacket.h"
#include "hashtable.h"

#define DANGER -1
#define FLOOD -1
#define SUCCESS 1
#define FAIL 0

#define ICMP 1
#define TCP 6
#define UDP 17
#define ECHO_REQUEST 8
#define NOT_SUPPORTED_PROTOCOL -1

void *start_detectthread(void * detectstruct) { 
  PacketQueue *pkt_queue = ((DetectStruct *)detectstruct)->packetqueue;
  Rule rule = ((DetectStruct *)detectstruct)->rulestruct;
  DangerPacketQueue *danger_pkt_queue = ((DetectStruct *)detectstruct)->dangerpacketqueue;
  HashTable *hashtable = ((DetectStruct *)detectstruct)->hashtable;
  int *end_flag = ((DetectStruct *)detectstruct)->end_flag;
  long long *thread_dequeue_cnt = &((DetectStruct *)detectstruct)->thread_dequeue_cnt;
  int8_t *flood_attack_flag = ((DetectStruct *)detectstruct)->flood_attack_flag;

  int count = 0; 

  while(1){
    if (*end_flag == 1) break;

    Packet *item = dequeuePacket(pkt_queue);

    if (!item) { 
      count++;
      if (count >= 10) {
        usleep(10);
        count = 0;
      }
      continue;
    }

    *thread_dequeue_cnt += 1;
    PacketNode node;
    node = parse_packet_node(item->packet, item->caplen);
    free(item->packet);
    free(item);

    //지원되지 않는 프로토콜
    if (node.protocol == NOT_SUPPORTED_PROTOCOL) {
      DangerPacket * dangernode = make_danger_packet(node, "not support", "not support");
      enqueueDangerPacket(danger_pkt_queue, dangernode);
      continue;
    }

    if (node.protocol == ICMP) {
      if (node.dstip == UINT_MAX && node.type == ECHO_REQUEST) {
        DangerPacket * dangernode = make_danger_packet(node, "SMURF", "SMURF");
        enqueueDangerPacket(danger_pkt_queue, dangernode);
        continue;
      }
    }

    if (*flood_attack_flag == 1 && node.protocol == ICMP && node.type == ECHO_REQUEST) {
      int isAttack = check_table(hashtable, node.srcip);    
      if (isAttack == FAIL) {
        printf("[ERR] HASHTABLE이 정상작동하지 않습니다. FLOOD 감지를 중지합니다. 정책 탐지는 정상적으로 이루어집니다.\n");
        *flood_attack_flag = 0;
      }

      if (isAttack == FLOOD) {
        char flood_msg[50];

        if (node.protocol == 1) snprintf(flood_msg, 50, "%s FLOOD", "ICMP");

        DangerPacket *dangernode = make_danger_packet(node, flood_msg, flood_msg);
        enqueueDangerPacket(danger_pkt_queue, dangernode);
        continue;
      }
    }

    int rulenum = match_node_with_rule(node, rule);
    if (rulenum != DANGER) { //정책 위반
      DangerPacket *dangernode = make_danger_packet(node, (char *)(rule.rules[rulenum].name), (char *)(rule.rules[rulenum].content) ); 
      enqueueDangerPacket(danger_pkt_queue, dangernode);
    }
  }
  return NULL;
}

void init_packet_node(PacketNode *node){
  node->length = -1;
  
  node->dstmac[0] = '\0';
  node->srcmac[0] = '\0';
  node->ethertype = -1;

  node->srcip = -1;
  node->dstip = -1;
  node->protocol = -1;

  node->srcport = -1;
  node->dstport = -1;

  //payload 유무, payload 사이즈
  node->flag_payload = 0;
  node->size_payload = 0;

  node->type = -1;
}

PacketNode parse_packet_node (u_char *packet, int caplen) { 
  PacketNode node;
  init_packet_node(&node);
  
  if (caplen >= 28 && is_icmp(packet)) {
    node.protocol = 1;
    decode_icmp_header(packet, &node);
    return node;
  }

  if (caplen >= 14) {
    node.length = caplen;
    unsigned short type = decode_ethernet_header(packet, &node);

    if (type == ETHERTYPE_IP && caplen >= 28) {
      int protocol = decode_ipv4_header(packet, &node);
      
      if (protocol == TCP && caplen >= 54) {
        node.protocol = TCP;
        decode_tcp_header(packet, &node);
      }
      if (protocol == UDP && caplen >= 42) {
        node.protocol = UDP;
        decode_udp_header(packet, &node);
      }
      //ICMP (ethernet 헤더가 있는 특수한 케이스 icmp)
      if (protocol == 1 && caplen >= 42) {
        node.protocol = 1;
        node.srcport = 0;
        node.dstport = 0;
        decode_ether_icmp_header(packet, &node);
      }
    }
  }
  return node;
}

unsigned short decode_ethernet_header(u_char *packet, PacketNode *node ) {

  struct ether_header *eth_header;
  eth_header = (struct ether_header*)packet;

  node->ethertype = ntohs(eth_header->ether_type);

  memcpy(node->dstmac, eth_header->ether_dhost, ETH_ALEN);
  memcpy(node->srcmac, eth_header->ether_shost, ETH_ALEN);

  return ntohs(eth_header->ether_type);
}

int decode_ipv4_header(u_char *packet, PacketNode *node) {
  struct ip *ip_header = (struct ip*)(packet+sizeof(struct ether_header));
  node->srcip = htonl(ip_header->ip_src.s_addr);
  node->dstip = htonl(ip_header->ip_dst.s_addr);
  node->protocol = ip_header->ip_p;
  return ip_header->ip_p;
}

int decode_udp_header(u_char *packet, PacketNode *node) {
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

int decode_tcp_header(u_char *packet, PacketNode *node) {
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

int is_icmp(u_char *packet){
  struct ip *ip_header = (struct ip*)packet;
  return (ip_header->ip_p==1) ? 1 : 0; 
}

int decode_icmp_header (u_char *packet, PacketNode *node) {
  struct ip *ip_header = (struct ip*)packet;
  node->srcip = htonl(ip_header->ip_src.s_addr);
  node->dstip = htonl(ip_header->ip_dst.s_addr);
  node->protocol = ip_header->ip_p;
  node->srcport = 0;
  node->dstport = 0;

  struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ip));
  node->type = icmp_header->type; 
  return 0;
}

int decode_ether_icmp_header(u_char *packet, PacketNode *node){
  int ether_size = sizeof(struct ether_header);
  int add_size = ether_size + 20;

  struct icmphdr *icmp_header = (struct icmphdr *)(packet + add_size);
  node->type = icmp_header->type;
  node->srcport = 0;
  node->dstport = 0;
  return 0;
}

int match_node_with_rule(PacketNode node, Rule rule){

  if (node.flag_payload == 0) {
    return -1;
  }

  int i=0;
  
  short flag=0;
  short result=0;
  
   
  for(i=0; i<rule.cnt; i++) {
    
     //패턴 검사
    if (match_node_with_rule_pattern(node.payload, rule.rules[i].pattern, node.size_payload)==1) {
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
      return i;
    }
    else {
      flag = 0;
      result = 0;
    }
  } 
      
   
  return -1;
}

int match_node_with_rule_pattern(char *payload, char *pattern, int size_payload){
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

DangerPacket *make_danger_packet(PacketNode node, char * rulename, char * rulecontent) {
  DangerPacket * dangernode = (DangerPacket *)malloc(sizeof(DangerPacket));
  if (dangernode == NULL) {
    printf("위험한 패킷이 존재하지만 저장에 실패하였습니다. 프로그램을 종료합니다.\n");
    exit(0);
  }

  char detecttime[30];
  time_t current_time;
  time(&current_time);

  struct tm *local_time = localtime(&current_time);
  strftime(detecttime, sizeof(detecttime), "%y-%m-%d %H:%M:%S", local_time);
  snprintf((char *)(dangernode->detecttime), 30, "%s", detecttime);

  //지원되지 않는 패킷  
  if (node.protocol == -1) {
      snprintf((char *)(dangernode->rulename), 16, "%s", rulename);
      snprintf((char *)(dangernode->rulecontent), 225, "%s", rulecontent);
      snprintf((char *)(dangernode->protocol), 15, "%s", "not support");
    return dangernode;
  }
    
    snprintf((char *)(dangernode->rulename), 16, "%s", rulename);
    snprintf((char *)(dangernode->rulecontent), 225, "%s", rulecontent);

  if (node.srcmac[0] != '\0') {
    snprintf((char *)(dangernode->srcmac), 6, (const char *)(node.srcmac));
  }
  if (node.dstmac[0] != '\0') {
    snprintf((char *)(dangernode->dstmac), 6, (const char *)(node.dstmac));
  }

  if (node.srcip!=-1) {
    char tmpsrcip[16];
    struct in_addr addr;

    addr.s_addr = htonl(node.srcip);
    inet_ntop(AF_INET, &addr, tmpsrcip, INET_ADDRSTRLEN);

    snprintf((char*)(dangernode->srcip), 16,"%s", tmpsrcip);
  }

  if (node.dstip!=-1){

    char tmpdstip[16];
    struct in_addr addr;

    addr.s_addr = htonl(node.dstip);
    inet_ntop(AF_INET, &addr, tmpdstip, INET_ADDRSTRLEN);
    snprintf((char *)(dangernode->dstip), 16, "%s", tmpdstip);
  }

  if (node.protocol!=-1){
    if (node.protocol == 6) {
      snprintf((char *)(dangernode->protocol), 15, "%s", "tcp");
    }
    if (node.protocol == 17) {
      snprintf((char *)(dangernode->protocol), 15, "%s", "udp");
    }
    if (node.protocol == 1){
      snprintf((char *)(dangernode->protocol), 15, "%s", "icmp");
    }
  }

  if (node.srcport != -1) {
    dangernode->srcport = node.srcport;
  }

  if (node.dstport != -1) {
    dangernode->dstport = node.dstport;
  }

  return dangernode;
}

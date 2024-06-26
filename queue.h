#ifndef QUEUE_H
#define QUEUE_H

#define PROTOCOL_NAME_LEN 15
#define MAC_ADDR_LEN 18 
#define IP_ADDR_LEN 16
#define PAYLOAD_LEN 1461

#define RULE_NAME_LEN 16
#define RULE_CONTENT_LEN 255

#define MAX_CONFIG_LEN 255

#include <netinet/if_ether.h>
#include <pthread.h>
#include <pcap.h>
#include <stdint.h>
#include "hashtable.h"

typedef struct {
  unsigned char name[RULE_NAME_LEN];
  unsigned char content[RULE_CONTENT_LEN];
  
  unsigned short dstmac[ETH_ALEN];
  unsigned short srcmac[ETH_ALEN];
  
  long long srcip; //host to network 변환됨
  long long dstip; //host to network 변환됨
  int  protocol;

  int srcport; //host to network 변환됨
  int dstport; //host to network 변환됨

  char pattern[1461];
} RuleDetail;

typedef struct {
  unsigned short cnt;
  int MAX_RULE_COUNT;
  RuleDetail *rules;
} Rule;

//PacketItem 
typedef struct {
  int caplen;
  u_char * packet;
} Packet;

//PacketQueue
typedef struct {
  int front, rear;
  int count;
  pthread_mutex_t mutex;
  Packet **packet;
  int MAX_QUEUE_SIZE;

  long long total_enqueue_cnt;
  long long total_dequeue_cnt;
  long long total_drop_cnt;
} PacketQueue;

//DangerPacketItem
typedef struct {
  unsigned char srcmac[7];
  unsigned char dstmac[7];
  unsigned short srcport;
  unsigned short dstport;
  unsigned char protocol[PROTOCOL_NAME_LEN];
  unsigned char srcip[IP_ADDR_LEN];
  unsigned char dstip[IP_ADDR_LEN];
  unsigned char rulename[RULE_NAME_LEN];
  unsigned char rulecontent[RULE_CONTENT_LEN];
  unsigned char detecttime[30];
} DangerPacket; 

//DangerPacketQueue
typedef struct {
  int front, rear;
  int count;
  pthread_mutex_t mutex;
  DangerPacket **items;
  int MAX_QUEUE_SIZE;

  long long total_enqueue_cnt;
  long long total_dequeue_cnt;
  long long total_drop_cnt;
} DangerPacketQueue;

typedef struct {
  PacketQueue **packetqueue;
  DangerPacketQueue *dangerpacketqueue;
  int *end_flag;
  int threadcnt;
} ReadStruct;

typedef struct {
  Rule rulestruct; //정책
  PacketQueue *packetqueue; //패킷큐
  DangerPacketQueue *dangerpacketqueue; //위험패킷큐
  HashTable *hashtable; //해시테이블

  int *end_flag;

  long long thread_dequeue_cnt;
  int8_t *flood_attack_flag;
} DetectStruct;

typedef struct {
  DangerPacketQueue *dangerpacketqueue;
  int *end_flag;
} LogStruct;

void initPacketQueue(PacketQueue *queue, int queuesize);
int enqueuePacket(PacketQueue *queue, Packet *value, int size);
Packet *dequeuePacket(PacketQueue *queue);

void initDangerPacketQueue(DangerPacketQueue *queue, int queuesize);
void enqueueDangerPacket(DangerPacketQueue *queue, DangerPacket *value);
DangerPacket* dequeueDangerPacket(DangerPacketQueue *queue);

#endif

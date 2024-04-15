#ifndef QUEUE_H
#define QUEUE_H

#define MAX_QUEUE_SIZE 1028 //임시값
#define MAX_DANGER_QUEUE_SIZE 1028 //임시값

#define PROTOCOL_NAME_LEN 5
#define MAC_ADDR_LEN 18 
#define IP_ADDR_LEN 16
#define PAYLOAD_LEN 1461

#define RULE_NAME_LEN 16

#define RULE_NAME_LEN 16
#define RULE_CONTENT_LEN 255
#define MAX_RULE_CNT 15 //임시값

#include <netinet/if_ether.h>
#include <pthread.h>
#include <pcap.h>

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
  // TODO 전체 정책 개수만큼으로 동적 할당
  RuleDetail rules[MAX_RULE_CNT];
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
  Packet *packet[MAX_QUEUE_SIZE]; 
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
  DangerPacket *items[MAX_DANGER_QUEUE_SIZE];
} DangerPacketQueue;

typedef struct {
  PacketQueue *packetqueue;
  DangerPacketQueue *dangerpacketqueue;
} ReadStruct;

typedef struct {
  Rule rulestruct; //정책
  PacketQueue *packetqueue; //패킷큐
  DangerPacketQueue *dangerpacketqueue; //위험패킷큐
} DetectStruct;

typedef struct {
  DangerPacketQueue *dangerpacketqueue;
  int *end_flag;
} LogStruct;

void initPacketQueue(PacketQueue *queue);
int enqueuePacket(PacketQueue *queue, Packet *value, int size);
Packet *dequeuePacket(PacketQueue *queue);

void initDangerPacketQueue(DangerPacketQueue *queue);
void enqueueDangerPacket(DangerPacketQueue *queue, DangerPacket *value);
DangerPacket* dequeueDangerPacket(DangerPacketQueue *queue);

#endif

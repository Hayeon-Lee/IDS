#ifndef QUEUE_H
#define QUEUE_H

#define MAX_QUEUE_SIZE 128 //임시값

#define PROTOCOL_NAME_LEN 5
#define MAC_ADDR_LEN 18 
#define IP_ADDR_LEN 16
#define PAYLOAD_LEN 1461
#include <pcap.h>

//Circular Queue Structure
typedef struct {
  int front, rear;
  int count;
  int data[MAX_QUEUE_SIZE]; 
} CircularQueue;

//PacketQueue
typedef struct {
  int front, rear;
  int count;
  const u_char *packet[MAX_QUEUE_SIZE]; 
} PacketQueue;

/*
//DangerPacketQueue에 들어갈 아이템(얘가 큐가 아님)
//DangerPacketQueue Item Structure
typedef struct {
  unsigned long long detectiontime;
  unsigned short srcport;
  unsigned short dstport;
  unsigned char protocol[PROTOCOL_NAME_LEN];
  unsigned char srcip[IP_ADDR_LEN];
  unsigned char dstip[IP_ADDR_LEN];
  unsigned char rulename[RULE_NAME_LEN];
} DangerPacket; 
*/
void initQueue(CircularQueue *queue);
void enqueue(CircularQueue *queue, int value);
void dequeue(CircularQueue *queue);

void initPacketQueue(PacketQueue *queue);
void enqueuePacket(PacketQueue *queue, const u_char *value, int size);
void dequeuePacket(PacketQueue *queue);

#endif

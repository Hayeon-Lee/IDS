#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#define MAX_QUEUE_SIZE 128 //임시값
#define PROTOCOL_NAME_LEN 5
#define MAC_ADDR_LEN 18 
#define IP_ADDR_LEN 16
#define PAYLOAD_LEN 1461
#define RULE_NAME_LEN 16
#define RULE_CONTENT_LEN 255
#define MAX_RULE_CNT 10 //임시값

//Circular Queue Structure
typedef struct {
  int front, rear;
  int count;
  int data[MAX_QUEUE_SIZE]; 
} CircularQueue;

//PacketQueue Item Structure
typedef struct {
  unsigned short srcport;
  unsigned short dstport;
  unsigned char protocol[PROTOCOL_NAME_LEN];
  unsigned char srcip[IP_ADDR_LEN];
  unsigned char dstip[IP_ADDR_LEN];
  unsigned char srcmac[MAC_ADDR_LEN];
  unsigned char dstmac[MAC_ADDR_LEN];
  unsigned char payload[PAYLOAD_LEN];
} Packet;

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

typedef struct {
  unsigned char name[RULE_NAME_LEN];
  unsigned char content[RULE_CONTENT_LEN];
} RuleDetail;

typedef struct {
  unsigned short cnt;
  RuleDetail rules[MAX_RULE_CNT];
} Rule;

//Function Prototype
void handleSignal(int signal);
void initQueue(CircularQueue *queue);
void enqueue(CircularQueue *queue, int value);
void dequeue(CircularQueue *queue);

//Function Prototype used by Main Thread
//void readSettingFile(); //추후설정파일에 대해 알아보고 구현
void readRuleFile(Rule* IDSRule);
void registerRule(Rule* IDSRule);

int main() {
    
    //Initialize Queue
    CircularQueue PacketQueue, DangerPacketQueue;
    initQueue(&PacketQueue);
    initQueue(&DangerPacketQueue);

    //Initialize Rule Structure
    Rule IDSRule; 
    IDSRule.cnt = 0;

    //정책 파일을 읽고 저장한다.
    readRuleFile(&IDSRule);
    //정책을 저장한다
    registerRule(&IDSRule);

    signal(SIGINT, handleSignal);      
    for(;;) {
      printf("Program Processing...");
      fflush(stdout);
      sleep(1);
    }
}

void handleSignal(int signal) {
  if (signal==SIGINT) {
    printf("프로그램을 종료합니다.\n");  
    exit(0);
  }
}

void initQueue(CircularQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
}

void readRuleFile(Rule* IDSRule) {
  FILE * rulefile = fopen("./conf/rule.txt", "r");
  
  if (rulefile == NULL) {
    printf("정책 파일 열기 실패.\n");
    handleSignal(2);
  }
  
  char line[RULE_CONTENT_LEN];
  char *pline;

  while (!feof(rulefile)){
    pline = fgets(line, RULE_CONTENT_LEN, rulefile);
    
    if (pline && IDSRule->cnt < MAX_RULE_CNT) {
      strcpy(IDSRule->
      IDSRule->cnt += 1;
    }
  }
  fclose(rulefile);
}

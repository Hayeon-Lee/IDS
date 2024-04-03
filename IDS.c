#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>

#include "queue.h"

#define PROTOCOL_NAME_LEN 5
#define MAC_ADDR_LEN 18 
#define IP_ADDR_LEN 16
#define PAYLOAD_LEN 1461
#define RULE_NAME_LEN 16
#define RULE_CONTENT_LEN 255
#define MAX_RULE_CNT 10 //임시값

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

//Function Prototype used by Main Thread
//void readSettingFile(); //추후설정파일에 대해 알아보고 구현
void makeRule(Rule* IDSRule);
void *afterThread(void* a);
int main() {
    
    //Initialize Queue
    CircularQueue PacketQueue, DangerPacketQueue;
    initQueue(&PacketQueue);
    initQueue(&DangerPacketQueue);

    //Initialize Rule Structure
    Rule IDSRule; 
    IDSRule.cnt = 0;

    //정책 파일을 읽고 저장한다.
    makeRule(&IDSRule);
      
    pthread_t ReadThread;
    int thr_id = pthread_create(&ReadThread, NULL, afterThread,(void *)0);

    signal(SIGINT, handleSignal);      
    for(;;) {
 //     printf("Program Processing...");
      fflush(stdout);
      sleep(1);
    }
}

void *afterThread(void * a) { 
 // printf("스레드 생성 완료.");
   
  pcap_t *handle ;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_offline("./packets/dns1.pcap", errbuf);

  if (handle) {
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res = pcap_next_ex(handle, &header,&packet);



    for (int i=0; i<header->caplen; i++) {
      printf("0x%02X\t", packet[i]);
    }
    // printf("%c", handle->buffer);
  }
  return (void *)0;
}

void handleSignal(int signal) {
  if (signal==SIGINT) {
    printf("프로그램을 종료합니다.\n");  
    exit(0);
  }
}

void makeRule(Rule* IDSRule) {
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
      
      char *content;
      char *name = strtok_r(pline, "|", &content);

      strcpy(IDSRule->rules[IDSRule->cnt].name, name);
      strcpy(IDSRule->rules[IDSRule->cnt].content, content);

      IDSRule->rules[IDSRule->cnt].content[strlen(content)-1] = '\0';

      printf("%s %s\n", IDSRule->rules[IDSRule->cnt].name, IDSRule->rules[IDSRule->cnt].content);
      IDSRule->cnt += 1;
    }
  }
  fclose(rulefile);
}

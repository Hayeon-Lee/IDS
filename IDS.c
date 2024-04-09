#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "queue.h"
#include "readpacket.h"
#include "detectpacket.h"

void handleSignal(int signal);

//void readSettingFile(); //추후설정파일에 대해 알아보고 구현
void makeRule(Rule* IDSRule);
void *makeReadThread(void* packetqueue);
void *makeDetectThread(void *detectstruct);

int check_rule_valid();
int return_rule_type(char *prop);

int main() { 
  //Initialize Rule Structure
  Rule IDSRule; 
  IDSRule.cnt = 0;

  //정책 파일을 읽고 저장한다.
  makeRule(&IDSRule);

  //Packet Queue 선언 및 초기화
  PacketQueue packetqueue;
  initPacketQueue(&packetqueue);

  //Danger Packet Queue 선언 및 초기화
  DangerPacketQueue dangerpacketqueue;
  initDangerPacketQueue(&dangerpacketqueue);

  //Detect Thread에게 넘겨줄 구조체 선언 및 초기화
  DetectStruct detectstruct;
  detectstruct.rulestruct = IDSRule;
  detectstruct.packetqueue = &packetqueue;
  detectstruct.dangerpacketqueue = dangerpacketqueue;

  pthread_t ReadThread;
  int read_thr_id = pthread_create(&ReadThread, NULL, makeReadThread,(void *)&packetqueue);

  pthread_t DetectThread1;
  pthread_t DetectThread2;

  int detect_thr_id1 = pthread_create(&DetectThread1, NULL, makeDetectThread, (void *)&detectstruct);
  int detect_thr_id2 = pthread_create(&DetectThread2, NULL, makeDetectThread, (void *)&detectstruct);

  //pthread_join(read_thr_id, NULL); //에러남
  //pthread_join(detect_thr_id, NULL);

   signal(SIGINT, handleSignal);      
   for(;;) {
    fflush(stdout);
    sleep(1);
   }
}

void *makeReadThread(void *packetqueue) { 
  //printf("스레드 생성 완료.");
  start_readthread(packetqueue);    
  return (void *)0;
}

void *makeDetectThread(void *detectstruct) {
  startDetectThread(detectstruct);
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
      
      if(name == NULL){
        printf("pipeline이 없습니다. 무시합니다.\n");
        continue;
      }
      else {
        int result = check_rule_valid(content);
 
        if (result == 1){
          printf("%s %s", IDSRule->rules[IDSRule->cnt].name, IDSRule->rules[IDSRule->cnt].pattern);
          IDSRule->cnt += 1;
        }
      }
    }
  }
  fclose(rulefile);
}

int check_rule_valid(char *content, Rule *IDSRule){

  char *behind;
  char *front = strtok_r(content, ";", &behind);

  //; 기준으로 나누기 (요소 기준으로 나누기)
  if (front) {
    while(front){
      //= 기준으로 나누기 (요소 내부 값과 키 나누기)
      char *value;
      char *prop = strtok_r(front, "=", &value);
      int type = -1;

      if(prop) {
        type = return_rule_type(prop);
        
        switch (type) {
          case 1: //srcmac 
           // memcpy(IDSRule->rules[IDSRule->cnt].srcmac, value);
            break;
          case 2: //dstmac
           // memcpy(IDSRule->rules[IDSRule->cnt].dstmac, value);
            break;
          case 3: //srcip
            IDSRule->rules[IDSRule->cnt].srcip = inet_addr(value);
            break;
          case 4: //dstip
            IDSRule->rules[IDSRule->cnt].dstip = inet_addr(value);
            break;
          case 5: //srcport
            IDSRule->rules[IDSRule->cnt].srcport = atoi(value);
            break;
          case 6: //dstport
            IDSRule->rules[IDSRule->cnt].dstport = atoi(value);
            break;
          case 7: //pattern
            strcpy(IDSRule->rules[IDSRule->cnt].pattern, value);
            break;
          case -1:
            return -1;
        }
      }
      front = strtok_r(behind, ";", &behind);
    }
  }
  
  //조건이 한 개일 때(=pattern이 반드시 있어야 함)
  else{ 
    if (strlen(content)>0) {
     char *value;
     char *prop = strtok_r(content, "pattern=", &value);
     strcpy(IDSRule->rules[IDSRule->cnt].pattern, value);
     return 1;
    }
  }
  return -1; //처리 불가능한 패킷
}

int return_rule_type(char *prop){
  if(strcmp(prop, "srcmac")==0) return 1;
  if(strcmp(prop, "dstmac")==0) return 2;
  if(strcmp(prop, "srcip")==0) return 3;
  if(strcmp(prop, "dstip")==0) return 4;
  if(strcmp(prop, "srcport")==0) return 5;
  if(strcmp(prop, "dstport")==0) return 6;
  if(strcmp(prop, "pattern")==0) return 7;
  
  return -1;
}

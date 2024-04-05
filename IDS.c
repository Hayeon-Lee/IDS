#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "queue.h"
#include "readpacket.h"
#include "detectpacket.h"

void handleSignal(int signal);

//void readSettingFile(); //추후설정파일에 대해 알아보고 구현
void makeRule(Rule* IDSRule);
void *makeReadThread(void* packetqueue);
void *makeDetectThread(void *detectstruct);
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
    detectstruct.packetqueue = packetqueue;
    detectstruct.dangerpacketqueue = dangerpacketqueue;
  
    pthread_t ReadThread;
    int read_thr_id = pthread_create(&ReadThread, NULL, makeReadThread,(void *)&packetqueue);
    
    pthread_t DetectThread;
    int detect_thr_id = pthread_create(&DetectThread, NULL, makeDetectThread, (void *)&detectstruct);

    signal(SIGINT, handleSignal);      
    for(;;) {
 //     printf("Program Processing...");

      fflush(stdout);
      sleep(1);
    }
}

void *makeReadThread(void *packetqueue) { 
  printf("스레드 생성 완료.");
  start_readthread(packetqueue);    
  return (void *)0;
}

void *makeDetectThread(void *detectstruct) {
  printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~탐지스레드 ~~~~~~~~~~~~~~~~~~~~~~~~~\n");
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

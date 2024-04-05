#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "queue.h"
#include "readpacket.h"

#define RULE_NAME_LEN 16
#define RULE_CONTENT_LEN 255
#define MAX_RULE_CNT 10 //임시값

typedef struct {
  unsigned char name[RULE_NAME_LEN];
  unsigned char content[RULE_CONTENT_LEN];
} RuleDetail;

typedef struct {
  unsigned short cnt;
  RuleDetail rules[MAX_RULE_CNT];
} Rule;

void handleSignal(int signal);

//void readSettingFile(); //추후설정파일에 대해 알아보고 구현
void makeRule(Rule* IDSRule);
void *makeReadThread(void* packetqueue);
int main() {
    
    //Packet Queue 선언 및 초기화
    PacketQueue packetqueue;
    initPacketQueue(&packetqueue);

    //Initialize Rule Structure
    Rule IDSRule; 
    IDSRule.cnt = 0;

    //정책 파일을 읽고 저장한다.
    makeRule(&IDSRule);
      
    pthread_t ReadThread;
    int read_thr_id = pthread_create(&ReadThread, NULL, makeReadThread,(void *)&packetqueue);

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

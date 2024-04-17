#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "queue.h"
#include "readpacket.h"
#include "detectpacket.h"
#include "logpacket.h"

#define DEFAULT_QUEUESIZE 1028
#define DEFAULT_THREADCNT 4
#define DEFAULT_RULECNT 100 

int end_flag = 0;

void handle_signal(int signal){
  if (signal == SIGINT) {
    printf("프로그램을 종료합니다\n");
    end_flag = 1;
    exit(0);
  }
}

int return_rule_type(char *prop){
  // TODO return code define.
  if(strcmp(prop, "srcmac")==0) return 1;
  if(strcmp(prop, "dstmac")==0) return 2;
  if(strcmp(prop, "srcip")==0) return 3;
  if(strcmp(prop, "dstip")==0) return 4;
  if(strcmp(prop, "srcport")==0) return 5;
  if(strcmp(prop, "dstport")==0) return 6;
  if(strcmp(prop, "pattern")==0) return 7;
  
  return -1;
}

int check_rule_valid(char *content, Rule *IDSRule){

  char *behind;
  char *front = strtok_r(content, ";", &behind);

  //initialize
  IDSRule->rules[IDSRule->cnt].pattern[0] = '\0';
  IDSRule->rules[IDSRule->cnt].srcip = -1;
  IDSRule->rules[IDSRule->cnt].dstip = -1;
  IDSRule->rules[IDSRule->cnt].protocol = -1;
  IDSRule->rules[IDSRule->cnt].srcport = -1;
  IDSRule->rules[IDSRule->cnt].dstport = -1;

  //; 기준으로 나누기 (요소 기준으로 나누기)
  if (front) {
    while(front){
      //= 기준으로 나누기 (요소 내부 값과 키 나누기)
      char *value;
      char *prop = strtok_r(front, "=", &value);
      int type = -1;
      
      struct in_addr ip;
      char tmp[1461];
      strcpy(tmp, value);
      
      int length = strlen(tmp);
      for (int i=0; i<length; i++) {
        if (tmp[i] == 0x0a) {
          tmp[i] = 0x00;
        }
      }

      if(prop) {
        type = return_rule_type(prop);
        
        switch (type) {
          case 3: //srcip
            ip.s_addr = inet_addr(value);
            ip.s_addr = ntohl(ip.s_addr);
            
            // TODO MAXINT 뭐시기
            if (ip.s_addr < 0 || ip.s_addr > 4294967295) {
              return -1;
            }

            IDSRule->rules[IDSRule->cnt].srcip = ip.s_addr;
            break;
          case 4: //dstip
            ip.s_addr = inet_addr(value);
            ip.s_addr = ntohl(ip.s_addr);
            
            if (ip.s_addr < 0 || ip.s_addr > 4294967295) {
              return -1;
            }

            IDSRule->rules[IDSRule->cnt].dstip = ip.s_addr;
            break;
          case 5: //srcport
            if (atoi(tmp)<0 || atoi(tmp) > 65535){
              return -1;
            } 
            IDSRule->rules[IDSRule->cnt].srcport = atoi(tmp);
            break;
          case 6: //dstport
            
            if (atoi(tmp)<0 || atoi(tmp) > 65535){
              return -1;
            } 
            IDSRule->rules[IDSRule->cnt].dstport = atoi(tmp);
            break;
          case 7: //pattern
            strcpy(IDSRule->rules[IDSRule->cnt].pattern, tmp);
            break;
          case -1:
            return -1;
        }
      }
      front = strtok_r(behind, ";", &behind);
    }
    return 1;
  }
  return -1; //처리 불가능한 패킷
}

void makeRule(Rule* IDSRule, int rulecnt) {
  FILE * rulefile = fopen("./conf/rule.txt", "r");

  if (rulefile == NULL) {
    printf("정책 파일을 열지 못했습니다. 프로그램 종료합니다.\n");
    exit(0);
  }

  char line[RULE_CONTENT_LEN];
  char *pline;
  int written_rules = 0;

  while (!feof(rulefile)){
    pline = fgets(line, RULE_CONTENT_LEN, rulefile);
    
    if (pline && IDSRule->cnt < rulecnt) {
      written_rules += 1;
      char *content;
      char *name = strtok_r(pline, "|", &content);      

      strcpy(IDSRule->rules[IDSRule->cnt].content, content);      
      for (int i=0; i<strlen(IDSRule->rules[IDSRule->cnt].content);i++){
        if (IDSRule->rules[IDSRule->cnt].content[i] == 0x0a){
          IDSRule->rules[IDSRule->cnt].content[i] = 0x00;
        }
      }

      if(name == NULL){
        printf("pipeline이 없습니다. 무시합니다.\n");
        continue;
      }
      else {
        // TODO 이름 고민
        int result = check_rule_valid(content, IDSRule);
 
        if (result == 1 && IDSRule->rules[IDSRule->cnt].pattern[0] != '\0'){
          strcpy(IDSRule->rules[IDSRule->cnt].name, name);
          IDSRule->cnt += 1;
        }
      }
    }
  }
  fclose(rulefile);
  printf("============================정책 파일 확인합니다.=======================\n\n");
  printf("작성하신 전체 정책은 %d개이며, 이 중 %d개가 등록되었습니다.\n\n", written_rules, IDSRule->cnt);

  if (IDSRule->cnt == 0) {
    printf("등록된 정책이 없습니다. 정책 파일 재작성 후 프로그램을 재시작해주세요.\n");
    exit(0);
  }

  printf("==============================등록 정책 목록===========================\n");
  for(int i=0; i<IDSRule->cnt; i++){
    printf("%s|%s\n", IDSRule->rules[i].name, IDSRule->rules[i].content);
  }
  printf("=======================================================================\n");

  printf("작성하신 내용이 맞다면 y를, 아니라면 아무 문자나 입력해주세요.: ");
  char order;
  getchar();
  scanf("%c", &order);
  if (order!='y') {
    printf("정책파일 재작성 후 프로그램 재시작해주세요.\n");
    exit(0);
  }
  else {
    printf("============================정책파일 확인을 마쳤습니다. 프로그램을 시작합니다. ==========================\n");
    system("clear");
  }
}

void parse_config_file (int *queuesize, int *threadcnt, int *rulecnt)  {
  int isFile = 1;

  FILE *configfile = fopen("./conf/config", "r");
  if (configfile == NULL) isFile = 0;
  else{
    char line[MAX_CONFIG_LEN];
    char *pline;

    int props_flag[3] = {0,};

    while(!feof(configfile)){
      pline = fgets(line, MAX_CONFIG_LEN, configfile);

      if(pline) {
        char *content;
        char *name = strtok_r(pline, "=", &content);

        if (strcmp(name, "queuesize")==0) {
          *queuesize = atoi(content);
        } else if (strcmp(name, "thread")==0){
          *threadcnt = atoi(content);
        } else *rulecnt = atoi(content);
      }
    }
  }
  
  system("clear");
  if (!isFile) printf("설정파일을 열지 못해 기본값으로 진행합니다.\n");
  printf("==========================설정파일 확인을 진행합니다.======================\n");
  printf("[큐 사이즈: %d]\n[스레드 개수: %d]\n[정책 개수: %d]\n", *queuesize, *threadcnt, *rulecnt);
  printf("작성하신 내용이 맞다면 y를, 아니라면 아무 문자나 입력해주세요.: ");
  char order;
  scanf("%c", &order);
  if (order!='y') {
    printf("설정파일 재작성 후 프로그램 재시작해주세요.\n");
    exit(0);
  }
  else {
    printf("============================설정파일 확인을 마쳤습니다.==========================\n");
    system("clear");
  }
}

int main() { 
  
  //conf 파일로부터 동적할당 
  //init_config();
  //구조체로 묶어서 한 번에 초기화 ( 확장성을 위해서 ) 
  int queuesize = DEFAULT_QUEUESIZE, threadcnt = DEFAULT_THREADCNT, rulecnt = DEFAULT_RULECNT;
  parse_config_file(&queuesize, &threadcnt, &rulecnt);
  
  //Initialize Rule Structure
  Rule IDSRule;
  IDSRule.rules = (RuleDetail *)malloc(sizeof(RuleDetail)*rulecnt);
  IDSRule.cnt = 0;
  
  //정책 파일을 읽고 저장한다.
  makeRule(&IDSRule, rulecnt);

 // Packet Queue 선언 및 초기화
  PacketQueue packetqueue;
  initPacketQueue(&packetqueue, queuesize);
  /*
  PacketQueue* *packetqueue_array = (PacketQueue *)malloc(sizeof(PacketQueue*)*threadcnt);
  for(int i=0; i<threadcnt; i++) {
    PacketQueue packetqueue;
    packetqueue_array[i] = &packetqueue;
    initPacketQueue(packetqueue_array[i], queuesize);
  }
  */

  //Danger Packet Queue 선언 및 초기화
  DangerPacketQueue dangerpacketqueue;
  initDangerPacketQueue(&dangerpacketqueue, queuesize);

  //Read Thread에게 넘겨줄 구조체 선언 및 초기화
  ReadStruct readstruct;
  readstruct.packetqueue = &packetqueue;
  readstruct.dangerpacketqueue = &dangerpacketqueue;
  readstruct.end_flag = &end_flag;

  //Detect Thread에게 넘겨줄 구조체 선언 및 초기화
  DetectStruct detectstruct;
  detectstruct.rulestruct = IDSRule;
  detectstruct.packetqueue = &packetqueue;
  detectstruct.dangerpacketqueue = &dangerpacketqueue;
  detectstruct.end_flag = &end_flag;  

  LogStruct logstruct;
  logstruct.dangerpacketqueue = &dangerpacketqueue;
  logstruct.end_flag = &end_flag;

  pthread_t ReadThread;
  int read_thr_id = pthread_create(&ReadThread, NULL, start_readthread,(void *)&readstruct);

  pthread_t *detect_thread_array = (pthread_t *)malloc(sizeof(pthread_t)*threadcnt);
  if (detect_thread_array == NULL) {
    printf("스레드 생성 실패하였습니다. 프로그램을 종료합니다.\n");
    exit(0);
  }

  for (int i=0; i<threadcnt; i++){
    if (pthread_create(&detect_thread_array[i], NULL, startDetectThread, (void *)&detectstruct) != 0){
      printf("스레드 실행 실패하였습니다. 프로그램을 종료합니다.\n");
      exit(0);
    }
  }

  pthread_t LogThread;
  int log_thr_id = pthread_create(&LogThread, NULL, start_logthread, (void *)&logstruct);

  printf("======== 프로그램을 종료하려면 ctrl+c를 입력하세요.=========\n");
  
  signal(SIGINT, handle_signal);

  if(pthread_join(LogThread, NULL)!=0) printf("로그 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");

  for(int i=0; i<threadcnt; i++) {
    if(pthread_join(detect_thread_array[i], NULL) != 0) {
      printf("탐지 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");
      exit(0);
    }
  }

  if (pthread_join(ReadThread, NULL)!=0) printf("읽기 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");
}

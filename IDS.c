#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdint.h>

#include "queue.h"
#include "readpacket.h"
#include "detectpacket.h"
#include "logpacket.h"

#define DEFAULT_QUEUESIZE 1028
#define DEFAULT_THREADCNT 4
#define DEFAULT_RULECNT 100 
#define DEFAULT_PROP_CNT 3

#define SRCMAC 1
#define DSTMAC 2
#define SRCIP 3
#define DSTIP 4
#define SRCPORT 5
#define DSTPORT 6
#define PATTERN 7

#define OK 1
#define BAD -1
#define INITIALIZE -1

typedef struct {
  int32_t queuesize;
  int32_t threadcnt;
  int32_t rulecnt;
  int32_t propcnt;
} Config;

typedef struct {
  PacketQueue **packetqueue_array;
  DetectStruct **detectstruct_array; 
  int32_t *end_flag;
  int32_t threadcnt;
} PrintStruct;

int end_flag = 0;

void handle_signal(int signal){
  if (signal == SIGINT) {
    printf("프로그램을 종료합니다\n");
    end_flag = 1;
  }
}

int return_rule_type(char *prop){
  if(strcmp(prop, "srcmac")==0) return SRCMAC;
  if(strcmp(prop, "dstmac")==0) return DSTMAC;
  if(strcmp(prop, "srcip")==0) return SRCIP;
  if(strcmp(prop, "dstip")==0) return DSTIP;
  if(strcmp(prop, "srcport")==0) return SRCPORT;
  if(strcmp(prop, "dstport")==0) return DSTPORT;
  if(strcmp(prop, "pattern")==0) return PATTERN;
  
  return BAD;
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
          case SRCIP: //srcip
            ip.s_addr = inet_addr(value);
            ip.s_addr = ntohl(ip.s_addr);
            
            if (ip.s_addr < 0 || ip.s_addr > UINT_MAX) return BAD;            
            IDSRule->rules[IDSRule->cnt].srcip = ip.s_addr;
            break;

          case DSTIP: //dstip
            ip.s_addr = inet_addr(value);
            ip.s_addr = ntohl(ip.s_addr);
            
            if (ip.s_addr < 0 || ip.s_addr > UINT_MAX) return BAD;
            IDSRule->rules[IDSRule->cnt].dstip = ip.s_addr;
            break;

          case SRCPORT: //srcport
            if (atoi(tmp)<0 || atoi(tmp) > USHRT_MAX) return BAD; 
            IDSRule->rules[IDSRule->cnt].srcport = atoi(tmp);
            break;

          case DSTPORT: //dstport
            if (atoi(tmp)<0 || atoi(tmp) > USHRT_MAX) return BAD;
            IDSRule->rules[IDSRule->cnt].dstport = atoi(tmp);
            break;

          case PATTERN: //pattern
            strcpy(IDSRule->rules[IDSRule->cnt].pattern, tmp);
            break;
          
          case BAD:
            return BAD;
        }
      }
      front = strtok_r(behind, ";", &behind);
    }
    return OK;
  }
  return BAD; //처리 불가능한 패킷
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

      strcpy((char *)(IDSRule->rules[IDSRule->cnt].content), content);      
      for (int i=0; i<strlen((const char *)(IDSRule->rules[IDSRule->cnt].content));i++){
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
 
        if (result == OK && IDSRule->rules[IDSRule->cnt].pattern[0] != '\0'){
          strcpy((char *)(IDSRule->rules[IDSRule->cnt].name),(const char *)name);
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

void parse_config_file (Config* config)  {
  int isFile = 1;

  FILE *configfile = fopen("./conf/config", "r");
  if (configfile == NULL) isFile = 0;
  else{
    char line[MAX_CONFIG_LEN];
    char *pline;

    while(!feof(configfile)){
      pline = fgets(line, MAX_CONFIG_LEN, configfile);

      if(pline) {
        char *content;
        char *name = strtok_r(pline, "=", &content);

        if (strcmp(name, "queuesize")==0) {
          config->queuesize = atoi(content);
        } else if (strcmp(name, "thread")==0){
          config->threadcnt = atoi(content);
        } else {
         config->rulecnt = atoi(content);
        }
      }
    }
  }
  
  system("clear");
  if (!isFile) printf("설정파일을 열지 못해 기본값으로 진행합니다.\n");
  printf("==========================설정파일 확인을 진행합니다.======================\n");
  printf("[큐 사이즈: %d]\n[스레드 개수: %d]\n[정책 개수: %d]\n", config->queuesize, config->threadcnt, config->rulecnt);
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

void * start_printthread(void * printstruct) {
  PrintStruct *print_struct = (PrintStruct *)printstruct;
  PacketQueue **packetqueue_array = print_struct -> packetqueue_array;
  DetectStruct **detectstruct_array = print_struct -> detectstruct_array;
  int threadcnt = print_struct->threadcnt;
  int *end_flag = print_struct->end_flag;


  printf("[안내: 스레드는 자신의 번호와 같은 큐로부터 dequeue합니다.]\n\n");

  while(1){
    sleep(1);

    if (*end_flag == 1) break;

    int total_enqueue = 0;
    int total_drop = 0;

    for(int i=0; i<threadcnt; i++) {
      printf("===========[QUEUE(THREAD) %d]==========\n", i+1);
      printf("[ENQUEUE]: %lld ", packetqueue_array[i]->total_enqueue_cnt);
      printf("[DEQUEUE]: %lld ", detectstruct_array[i]->thread_dequeue_cnt);
      printf("[DROP]: %lld [%.2lf]\n", packetqueue_array[i]->total_drop_cnt,
                                     packetqueue_array[i]->total_drop_cnt/(float)packetqueue_array[i]->total_enqueue_cnt*100.0);
      
      total_enqueue += packetqueue_array[i]->total_enqueue_cnt;
      total_drop += packetqueue_array[i] -> total_drop_cnt;
    }
    printf("\n");
    printf("[평균 drop]: %.2lf\n", total_drop/(float)total_enqueue * 100.0);
    printf("======================================\n");
  }

  return NULL;
}

int main() { 
 
  Config config;
  config.queuesize = DEFAULT_QUEUESIZE;
  config.threadcnt = DEFAULT_THREADCNT;
  config.rulecnt = DEFAULT_RULECNT;
  config.propcnt = DEFAULT_PROP_CNT;

  parse_config_file(&config);
  
  //Initialize Rule Structure
  Rule IDSRule;
  IDSRule.rules = (RuleDetail *)malloc(sizeof(RuleDetail)*config.rulecnt);
  IDSRule.cnt = 0;
  
  //정책 파일을 읽고 저장한다.
  makeRule(&IDSRule, config.rulecnt);
 
  // PacketQueue의 주소를 저장하는 일차원 배열
  PacketQueue **packetqueue_array = (PacketQueue **)malloc(sizeof(PacketQueue*)*config.threadcnt);
  for(int i=0; i<config.threadcnt; i++) {
    PacketQueue *packetqueue = (PacketQueue *)malloc(sizeof(PacketQueue));
    packetqueue_array[i] = packetqueue;
    initPacketQueue(packetqueue_array[i], config.queuesize);
  }

  //Danger Packet Queue 선언 및 초기화
  DangerPacketQueue dangerpacketqueue;
  initDangerPacketQueue(&dangerpacketqueue, config.queuesize);

  //Read Thread에게 넘겨줄 구조체 선언 및 초기화
  ReadStruct readstruct;
  readstruct.packetqueue = packetqueue_array;
  readstruct.dangerpacketqueue = &dangerpacketqueue;
  readstruct.end_flag = &end_flag;
  readstruct.threadcnt = config.threadcnt;

  DetectStruct **detectstruct_array = (DetectStruct **)malloc(sizeof(DetectStruct*)*config.threadcnt);
  for(int i=0; i<config.threadcnt; i++){
    DetectStruct *detectstruct = (DetectStruct *)malloc(sizeof(DetectStruct));
    detectstruct->rulestruct = IDSRule;
    detectstruct->packetqueue = packetqueue_array[i];
    detectstruct->dangerpacketqueue = &dangerpacketqueue;
    detectstruct->end_flag = &end_flag;
    detectstruct->thread_dequeue_cnt = 0;
    detectstruct_array[i] = detectstruct;
  }

  LogStruct logstruct;
  logstruct.dangerpacketqueue = &dangerpacketqueue;
  logstruct.end_flag = &end_flag;

  pthread_t ReadThread;
  int read_thr_id = pthread_create(&ReadThread, NULL, start_readthread,(void *)&readstruct);
  if (read_thr_id != 0) {
    printf("[READ THREAD] 생성 실패. 프로그램을 종료합니다.\n");
    exit(0);
  }

  pthread_t *detect_thread_array = (pthread_t *)malloc(sizeof(pthread_t)*config.threadcnt);
  if (detect_thread_array == NULL) {
    printf("[DETECT THREAD] 스레드 공간 생성 실패하였습니다. 프로그램을 종료합니다.\n");
    exit(0);
  }

  for (int i=0; i<config.threadcnt; i++){
    if (pthread_create(&detect_thread_array[i], NULL, startDetectThread, (void *)(detectstruct_array[i])) != 0){
      printf("[DETECT THREAD] 생성 실패. 프로그램을 종료합니다.\n");
      exit(0);
    }
  }

  pthread_t LogThread;
  int log_thr_id = pthread_create(&LogThread, NULL, start_logthread, (void *)&logstruct);
  if (log_thr_id != 0) {
    printf("[LOG THREAD] 생성 실패. 프로그램을 종료합니다.\n");
    exit(0);
  }

  PrintStruct printstruct;
  printstruct.packetqueue_array = packetqueue_array;
  printstruct.detectstruct_array = detectstruct_array;
  printstruct.end_flag = &end_flag;
  printstruct.threadcnt = config.threadcnt;

  pthread_t PrintThread;
  int print_thr_id = pthread_create(&PrintThread, NULL, start_printthread, (void *)&printstruct);
  if (print_thr_id != 0){
    printf("[PRINT THREAD] 생성 실패. 실시간 통계는 출력되지 않지만 IDS는 정상실행됩니다.\n");
  }

  printf("======== 프로그램을 종료하려면 ctrl+c를 입력하세요.=========\n");
  
  signal(SIGINT, handle_signal); 

  if(pthread_join(LogThread, NULL)!=0) printf("로그 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");

  for(int i=0; i<config.threadcnt; i++) {
    if(pthread_join(detect_thread_array[i], NULL) != 0) {
      printf("탐지 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");
      exit(0);
    }
  }

  if (pthread_join(ReadThread, NULL)!=0) printf("읽기 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");

  if (pthread_join(PrintThread, NULL)!=0) printf("통계 출력 스레드 종료를 탐지하지 못했지만, 지금까지 진행한 작업은 저장되었습니다.\n");
}

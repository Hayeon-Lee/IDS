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
#include "hashtable.h"

#define DEFAULT_QUEUESIZE 512
#define DEFAULT_THREADCNT 6
#define DEFAULT_RULECNT 100 
#define DEFAULT_FLOODFLAG 1
#define DEFAULT_PROP_CNT 4

#define DEFAULT_TABLESIZE 1000000
#define DEFAULT_TIMELIMIT 10
#define DEFAULT_COUNT 1000

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
  int8_t floodflag;
  int32_t propcnt;
} Config;

typedef struct {
  PacketQueue **packetqueue_array;
  DetectStruct **detectstruct_array; 
  DangerPacketQueue *dangerpacketqueue;
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
  IDSRule->rules[IDSRule->cnt].srcip = INITIALIZE;
  IDSRule->rules[IDSRule->cnt].dstip = INITIALIZE;
  IDSRule->rules[IDSRule->cnt].protocol = INITIALIZE;
  IDSRule->rules[IDSRule->cnt].srcport = INITIALIZE;
  IDSRule->rules[IDSRule->cnt].dstport = INITIALIZE;

  //; 기준으로 나누기 (요소 기준으로 나누기)
  if (front) {
    while(front){
      //= 기준으로 나누기 (요소 내부 값과 키 나누기)
      char *value;
      char *prop = strtok_r(front, "=", &value);
      int type = INITIALIZE;
      
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

void parse_rule_file(Rule* IDSRule, int rulecnt) {
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

      if(name != NULL){
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
    printf("==========================설정파일 확인을 진행합니다.======================\n");
    char line[MAX_CONFIG_LEN];
    char *pline;

    while(!feof(configfile)){
      pline = fgets(line, MAX_CONFIG_LEN, configfile);

      if(pline) {
        char *content;
        char *name = strtok_r(pline, "=", &content);

        if (strcmp(name, "queuesize")==0) {
          config->queuesize = atoi(content);
          if(config->queuesize < 512 || config->queuesize > 4096) {
            printf("[ERR: QUEUESIZE] 큐 사이즈(%d)가 범위를 벗어났습니다. 범위는 512 이상, 4096 이하입니다. 기본값인 512로 설정합니다.\n", config->queuesize);
            config->queuesize = 512;
          }
        } else if (strcmp(name, "thread")==0){
          config->threadcnt = atoi(content);
          if(config->threadcnt < 6 || config->threadcnt > 12) {
            printf("[ERR: THREAD] 스레드(%d)가 범위를 벗어났습니다. 범위는 6 이상, 12 이하입니다. 기본값인 6로 설정합니다.\n", config->threadcnt);
            config->threadcnt = 6;
          }
        } else if (strcmp(name, "rule")==0){
         config->rulecnt = atoi(content);
         if (config->rulecnt <= 0 || config->rulecnt>250){
            printf("[ERR: RULECNT] 정책 개수(%d)가 범위를 벗어났습니다. 범위는 1 이상 250 이하입니다. 기본값인 100을 설정합니다.\n", config->rulecnt);
            config->rulecnt = 100;
         } else if (strcmp(name, "ICMP_FLOOD_DETECT")==0){
            config->floodflag = atoi(content);
            if (config->floodflag != 1 && config->floodflag != 0) {
              printf("[ERR: FLOODDETECT] FLOOD 공격 감지 여부(%d)가 올바른 값이 아닙니다. 1 또는 0을 입력해야 합니다. 기본값인 1을 설정합니다.\n", config->floodflag);
              config->floodflag = 1;
            }
         }  
        }
      }
    }
  }
  
  if (!isFile) printf("설정파일을 열지 못해 기본값으로 진행합니다.\n");
  printf("==========================설정파일 할당값을 확인합니다.======================\n");
  printf("[큐 사이즈: %d]\n[스레드 개수: %d]\n[정책 개수: %d]\n[FLOOD 탐지 여부: %d]\n", config->queuesize, config->threadcnt, config->rulecnt, config->floodflag);
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

void parse_flood_conf_file (FloodConfig *flood_config) {

  FILE *flood_conf_file = fopen("./conf/flood_conf", "r");
  if (flood_conf_file != NULL) {
    printf("==========================FLOOD ATTACK 설정파일 확인을 진행합니다.======================\n");
    char line[MAX_CONFIG_LEN];
    char *pline;

    while(!feof(flood_conf_file)){
      pline = fgets(line, MAX_CONFIG_LEN, flood_conf_file);
      if (pline){
        char *content;
        char *name = strtok_r(pline, "=", &content);
        if (strcmp(name, "tablesize")==0){
          flood_config->tablesize = atoi(content);
          if(flood_config->tablesize < 1000000 || flood_config->tablesize > 10000000) {
            printf("[ERR: TABLESIZE] 테이블 사이즈(%d)가 범위를 벗어났습니다. 범위는 1000000(백만) 이상, 10000000(천만) 이하입니다. 기본값인 백만으로 설정합니다.\n", flood_config->tablesize);
            flood_config->tablesize = 1000000;
          } 
        } else if (strcmp(name, "timelimit")==0) {
          flood_config->timelimit = atoi(content);
          if(flood_config->timelimit < 10) {
            printf("[ERR: TIMELIMIT] 기준 시간(%d)가 범위를 벗어났습니다. 범위는 10 이상입니다. 기본값인 10으로 설정합니다.\n", flood_config->timelimit);
            flood_config->timelimit = 10;
          } 
        } else if (strcmp(name, "count")==0){
          flood_config->count = atoi(content);
          if (flood_config->count < 1000 || flood_config->count > 100000) {
            printf("[ERR: COUNT] 기준 탐지 개수(%d)가 범위를 벗어났습니다. 범위는 1000 이상 100000(십만) 이하입니다. 기본값인 1000으로 설정합니다.\n", flood_config->count);
            flood_config->count = 1000;
          }
        }
      }
    }
  }
  else printf("FLOOD 설정 파일을 열지 못해 기본값으로 진행합니다.\n");
  printf("==========================FLOOD 설정파일 할당값을 확인합니다.======================\n");
  printf("[테이블 사이즈: %d]\n[기준 시간: %d]\n[기준 개수: %d]\n", flood_config->tablesize, flood_config->timelimit, flood_config->count);
  printf("작성하신 내용이 맞다면 y를, 아니라면 아무 문자나 입력해주세요.: ");
  
  char order;
  getchar();
  scanf("%c", &order);
  if (order!='y') {
    printf("flood 설정 파일 재작성 후 프로그램 재시작해주세요.\n");
    exit(0);
  }
  
  printf("==========================FLOOD 설정파일 확인을 마쳤습니다.======================\n");
  system("clear");
}

void *start_printthread(void * printstruct) {
  PrintStruct *print_struct = (PrintStruct *)printstruct;
  PacketQueue **packetqueue_array = print_struct -> packetqueue_array;
  DetectStruct **detectstruct_array = print_struct -> detectstruct_array;
  DangerPacketQueue *dangerpacketqueue = print_struct -> dangerpacketqueue;
  int threadcnt = print_struct->threadcnt;
  int *end_flag = print_struct->end_flag;

  long long *backup_packetqueue_thread_enqueue = (long long *)calloc(threadcnt, sizeof(long long));
  long long *backup_packetqueue_thread_dequeue = (long long *)calloc(threadcnt, sizeof(long long));

  int backup_dangerpacketqueue_total_enqueue_cnt = 0;
  int backup_dangerpacketqueue_total_dequeue_cnt = 0;

  printf("[안내: 스레드는 자신의 번호와 같은 큐로부터 dequeue합니다.]\n\n");

  while(1){
    sleep(1);

    if (*end_flag == 1) {
      free(backup_packetqueue_thread_enqueue);
      free(backup_packetqueue_thread_dequeue);
      break;
    }

    int total_enqueue = 0;
    int total_drop = 0;

    for(int i=0; i<threadcnt; i++) {
      printf("===================[PACKET QUEUE(THREAD) %d]===============\n", i+1);
      printf("[ENQUEUE]: %lld (%lld/sec)\n", packetqueue_array[i]->total_enqueue_cnt, packetqueue_array[i]->total_enqueue_cnt - backup_packetqueue_thread_enqueue[i]);
      printf("[DEQUEUE]: %lld (%lld/sec)\n", detectstruct_array[i]->thread_dequeue_cnt, detectstruct_array[i]->thread_dequeue_cnt - backup_packetqueue_thread_dequeue[i]);
      printf("[DROP]: %lld [%.2lf]\n", packetqueue_array[i]->total_drop_cnt,
                                     packetqueue_array[i]->total_drop_cnt/(float)packetqueue_array[i]->total_enqueue_cnt*100.0);
      
      backup_packetqueue_thread_enqueue[i] = packetqueue_array[i]->total_enqueue_cnt;
      backup_packetqueue_thread_dequeue[i] = detectstruct_array[i]->thread_dequeue_cnt;

      total_enqueue += packetqueue_array[i]->total_enqueue_cnt;
      total_drop += packetqueue_array[i] -> total_drop_cnt;
    }
    printf("\n");
    printf("[PACKET QUEUE 평균 drop]: %.2lf\n\n", total_drop/(float)total_enqueue * 100.0);

    printf("=====================[DANGER PACKET QUEUE]======================\n");
    printf("[ENQUEUE]: %lld (%lld/sec)\n", dangerpacketqueue->total_enqueue_cnt, dangerpacketqueue->total_enqueue_cnt - backup_dangerpacketqueue_total_enqueue_cnt);
    printf("[DEQUEUE]: %lld (%lld/sec)\n", dangerpacketqueue->total_dequeue_cnt, dangerpacketqueue->total_dequeue_cnt - backup_dangerpacketqueue_total_dequeue_cnt);
    printf("[DROP]: %lld [%.2lf]\n", dangerpacketqueue->total_drop_cnt, dangerpacketqueue->total_drop_cnt/(float)dangerpacketqueue->total_enqueue_cnt*100.0);

    backup_dangerpacketqueue_total_enqueue_cnt = dangerpacketqueue->total_enqueue_cnt;
    backup_dangerpacketqueue_total_dequeue_cnt = dangerpacketqueue->total_dequeue_cnt;
    printf("\n\n");

    printf("#################################################################\n");
  }

  return NULL;
}

int main() { 
  Config config;
  config.queuesize = DEFAULT_QUEUESIZE;
  config.threadcnt = DEFAULT_THREADCNT;
  config.rulecnt = DEFAULT_RULECNT;
  config.floodflag = DEFAULT_FLOODFLAG;
  config.propcnt = DEFAULT_PROP_CNT;
  parse_config_file(&config);

  FloodConfig flood_config;
  flood_config.tablesize = DEFAULT_TABLESIZE;
  flood_config.timelimit = DEFAULT_TIMELIMIT;
  flood_config.count = DEFAULT_COUNT;
  
  HashTable hashtable;

  Rule IDSRule;
  IDSRule.rules = (RuleDetail *)malloc(sizeof(RuleDetail)*config.rulecnt);
  IDSRule.cnt = 0;
 
  PacketQueue **packetqueue_array = (PacketQueue **)malloc(sizeof(PacketQueue*)*config.threadcnt);
  DangerPacketQueue dangerpacketqueue;

  ReadStruct readstruct;
  readstruct.packetqueue = packetqueue_array;
  readstruct.dangerpacketqueue = &dangerpacketqueue;
  readstruct.end_flag = &end_flag;
  readstruct.threadcnt = config.threadcnt;

  DetectStruct **detectstruct_array = (DetectStruct **)malloc(sizeof(DetectStruct*)*config.threadcnt);
  
  LogStruct logstruct;
  logstruct.dangerpacketqueue = &dangerpacketqueue;
  logstruct.end_flag = &end_flag;
  
  PrintStruct printstruct;
  printstruct.packetqueue_array = packetqueue_array;
  printstruct.detectstruct_array = detectstruct_array;
  printstruct.dangerpacketqueue = &dangerpacketqueue;
  printstruct.end_flag = &end_flag;
  printstruct.threadcnt = config.threadcnt;
  
  //init hashtable
  if (config.floodflag == 1) {
    parse_flood_conf_file(&flood_config);
    init_hash_table(&hashtable, &flood_config);
  } 
 
  //make Rule Structure
  parse_rule_file(&IDSRule, config.rulecnt);

  //packet queue 
  for(int i=0; i<config.threadcnt; i++) {
    PacketQueue *packetqueue = (PacketQueue *)malloc(sizeof(PacketQueue));
    packetqueue_array[i] = packetqueue;
    initPacketQueue(packetqueue_array[i], config.queuesize);
  }

  //danger pacekt queue
  initDangerPacketQueue(&dangerpacketqueue, config.queuesize);

  //detect struct array
  for(int i=0; i<config.threadcnt; i++){
    DetectStruct *detectstruct = (DetectStruct *)malloc(sizeof(DetectStruct));
    detectstruct->rulestruct = IDSRule;
    detectstruct->packetqueue = packetqueue_array[i];
    detectstruct->dangerpacketqueue = &dangerpacketqueue;
    detectstruct->hashtable = &hashtable;
    detectstruct->end_flag = &end_flag;
    detectstruct->thread_dequeue_cnt = 0;
    detectstruct->flood_attack_flag = &(config.floodflag);
    detectstruct_array[i] = detectstruct;
  }

  pthread_t ReadThread;
  pthread_t *detect_thread_array = (pthread_t *)malloc(sizeof(pthread_t)*config.threadcnt);
  pthread_t LogThread;
  pthread_t PrintThread;

  //make read thread
  int read_thr_id = pthread_create(&ReadThread, NULL, start_readthread,(void *)&readstruct);
  if (read_thr_id != 0) {
    printf("[READ THREAD] 생성 실패. 프로그램을 종료합니다.\n");
    exit(0);
  }

  //make detect thread array
  if (detect_thread_array == NULL) {
    printf("[DETECT THREAD] 스레드 공간 생성 실패하였습니다. 프로그램을 종료합니다.\n");
    exit(0);
  }

  //make detect thread array items
  for (int i=0; i<config.threadcnt; i++){
    if (pthread_create(&detect_thread_array[i], NULL, start_detectthread, (void *)(detectstruct_array[i])) != 0){
      printf("[DETECT THREAD] 생성 실패. 프로그램을 종료합니다.\n");
      exit(0);
    }
  }

  //make log thread
  int log_thr_id = pthread_create(&LogThread, NULL, start_logthread, (void *)&logstruct);
  if (log_thr_id != 0) {
    printf("[LOG THREAD] 생성 실패. 프로그램을 종료합니다.\n");
    exit(0);
  }

  //make print thread
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

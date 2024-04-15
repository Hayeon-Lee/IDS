#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "queue.h"
#include "logpacket.h"

void *start_logthread(void *logstruct) {
  LogQueue logqueue;
  initLogQueue(&logqueue);
  DangerPacketQueue *danger_pkt_queue = ((LogStruct*)logstruct)->dangerpacketqueue;
  int *end_flag = ((LogStruct*)logstruct)->end_flag;

  const char *dir_name = "logs";
  //log directory 존재 안 할 시 생성해줌
  struct stat st;
  if (stat(dir_name, &st) == -1) {
    mkdir(dir_name, 0700);
    printf("directory create");
  }
  
  time_t start_time;
  time(&start_time);

  //int tmp = 0;
  while(1) {
  #if 0
    if (*end_flag == 1) {
      printf("end_flag is changed\n");
    }
    #endif

    time_t current_time;
    time(&current_time);
    //double elapsed_time = difftime(current_time, start_time)/60.0;
    double elapsed_time = current_time - start_time; //Sec    

    DangerPacket * dangerpacket = dequeueDangerPacket(danger_pkt_queue);
    if (dangerpacket != NULL) {
      enqueueLog(&logqueue, dangerpacket);
    }

    if ((logqueue.count > (MAX_LOG_QUEUE_SIZE*0.8))){
      printf("QUEUE사이즈: %d\n", logqueue.count);
      start_time = current_time;
      makeLogFile(&logqueue);
    }
    else if (logqueue.count > 0 && elapsed_time >= 10) {
      printf("개수와 시간: %d %d\n", logqueue.count, (int)elapsed_time);
      start_time = current_time;
      makeLogFile(&logqueue);
    }
  }
}

void makeLogFile(LogQueue *queue){
  time_t current_time;
  time(&current_time);

  struct tm *local_time = localtime(&current_time);

  char file_name[300];
  file_name[0]='\0';

  strcat(file_name, "./logs/");
  char file_time[30];
  strftime(file_time, sizeof(file_time), "%y%m%d_%H%M%S", local_time);
  strcat(file_name, file_time);

  FILE *logfile = fopen(file_name, "w");
  if (logfile == NULL) {
    printf("failed to open\n");
    return;
  } 
  else {
    writeLog(queue, logfile);
    fclose(logfile);
    save_log_in_sqlite3();
  }
}

void initLogQueue(LogQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
}

void enqueueLog(LogQueue *queue, DangerPacket *value) {
  if (queue->count >= MAX_LOG_QUEUE_SIZE) {
    return;
  }
  queue->rear = ((queue->rear)+1)%MAX_LOG_QUEUE_SIZE;
  queue->packet[queue->rear] = value;
  queue->count += 1;
}

DangerPacket * dequeueLog(LogQueue *queue) {
  if (queue->count <= 0) {
    return NULL;
  }
  DangerPacket *item;

  item = queue->packet[queue->front];
  queue->front = ((queue->front+1))%MAX_LOG_QUEUE_SIZE;
  queue->count -= 1;
  return item;
}

void writeLog(LogQueue *queue, FILE *logfile){
  while (queue->count) {
    DangerPacket * packet = dequeueLog(queue);
    if (packet != NULL) {
      char * logstring = returnLogString(packet);
      free(packet);
      fputs(logstring, logfile);
      free(logstring); 
    }
  }
}

char * returnLogString(DangerPacket * packet){
  return_query_string(packet);

  char *logstring = malloc(300 * sizeof(char));
  char partial[40] = "          |          ";
  char notsp[15] = "not support";
  char overflow[15] = "overflow";
  char arrow[5] = "->";
  char portpartial[2] = ":";

  char srcport[20];
  char dstport[20];

  sprintf(srcport, "%u", packet->srcport);
  sprintf(dstport, "%u", packet->dstport);

  logstring[0] = '\0';

  //탐지 시간
  strcat(logstring, packet->detecttime);
  strcat(logstring, partial);

  //not support
  if (strcmp(packet->protocol, notsp)==0) {
    strcat(logstring, notsp);
    strcat(logstring, "\n");
    return logstring;
  }

  //overflow
  if (strcmp(packet->protocol, overflow)==0){
    strcat(logstring, overflow);
    strcat(logstring, "\n");
    return logstring;
  }

  strcat(logstring, packet->srcip);
  strcat(logstring, portpartial);
  strcat(logstring, srcport);
  strcat(logstring, arrow);
  strcat(logstring, packet->dstip);
  strcat(logstring, portpartial);
  strcat(logstring, dstport);

  strcat(logstring, partial);
  strcat(logstring, packet->rulename);
  strcat(logstring, ": ");
  strcat(logstring, packet->rulecontent);

  return logstring;
}

int save_log_in_sqlite3(){
  sqlite3 *db;

  char *errMsg = 0;
  int result;

  const char *dbName = "logs.db";
  result = sqlite3_open(dbName, &db);

  if (result != SQLITE_OK){
    printf("데이터베이스 열기 실패\n");
    return 1;
  }

  else{
    
    sqlite3_close(db);
    return 0;
  }
}

char * return_query_string(DangerPacket *packet) {
  char *querystring = malloc(300 * sizeof(char));
  
  if (strmp(packet->protocol, notsp)==0) {
    snprintf(querystring, 300, "
  }

}

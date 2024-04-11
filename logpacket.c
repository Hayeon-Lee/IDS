#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "logpacket.h"

int start_logthread(void *dangerpacketqueue) {
  LogQueue logqueue;
  initLogQueue(&logqueue);
  DangerPacketQueue *danger_pkt_queue = (DangerPacketQueue*)dangerpacketqueue;
  
  const char *dir_name = "logs";
  //log directory 존재 안 할 시 생성해줌
  struct stat st;
  if (stat(dir_name, &st) == -1) {
    mkdir(dir_name, 0700);
    printf("directory create");
  }
  
  /*
  dangerpacketqueue가 절반 이상 찼을 때(혹은 1분에 한 개씩)
  파일을 새로 만들고, queue에서 뽑아 저장한다.
  */

  
  time_t start_time;
  time(&start_time);

  while(1) {
    sleep(30);
    time_t current_time;
    time(&current_time);
    double elapsed_time = difftime(current_time, start_time)/60.0;
    
    printf("흐른시간: %d\n", (int)elapsed_time);

    DangerPacket * dangerpacket = dequeueDangerPacket(danger_pkt_queue);
    if (dangerpacket != NULL) {
      enqueueLog(&logqueue, dangerpacket);
    }

    if ((logqueue.count > (MAX_QUEUE_SIZE/2))){
      makeLogFile(&logqueue);
    }
    else if ((int)elapsed_time >= 1 && (int)elapsed_time%1== 0) { 
      printf("%d %d\n", logqueue.count, (int)elapsed_time);
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
    printf("%s\n", file_name);

  FILE *logfile = fopen(file_name, "w");
  if (logfile == NULL) {
    printf("failed to open\n");
    return;
  } 
  else {
    writeLog(queue, logfile);
    fclose(logfile);
  }
}

void initLogQueue(LogQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
}

void enqueueLog(LogQueue *queue, DangerPacket *value) {
  if (queue->count >= MAX_QUEUE_SIZE) {
    printf("LogQueue가 꽉 차 드롭합니다.\n");
    return;
  }
  queue->rear = ((queue->rear)+1)%MAX_QUEUE_SIZE;
  queue->packet[queue->rear] = value;
  queue->count += 1;
}

DangerPacket * dequeueLog(LogQueue *queue) {
  if (queue->count <= 0) {
    printf("LogQueue가 비어있습니다.\n");
    return NULL;
  }
  DangerPacket *item;

  item = queue->packet[queue->front];
  queue->front = ((queue->front+1))%MAX_QUEUE_SIZE;
  queue->count -= 1;
  return item;
}

void writeLog(LogQueue *queue, FILE *logfile){
  for (int i=0; i<queue->count; i++){
    DangerPacket * packet = dequeueLog(queue);
    if (packet != NULL) {
      char logstring[300]; 
      strcpy(logstring, returnLogString(packet));
      fputs(logstring, logfile);
    }
  }
}

char * returnLogString(DangerPacket * packet){
  char *logstring = malloc(300 * sizeof(char));
  char partial[40] = "          |          ";
  char notsp[15] = "not support";
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

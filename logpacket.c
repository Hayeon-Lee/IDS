#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "queue.h"
#include "logpacket.h"

void *start_logthread(void *logstruct) {
  LogQueue logqueue;
  initLogQueue(&logqueue);
  DangerPacketQueue *danger_pkt_queue = ((LogStruct*)logstruct)->dangerpacketqueue;
  int *end_flag = ((LogStruct*)logstruct)->end_flag;

  time_t start_time;
  time(&start_time);

  sqlite3 *db;
  char db_name[100];
  char db_make_time[30];

  struct tm *start_time_tm = localtime(&start_time);
  strftime(db_make_time, 30, "%y%m%d", start_time_tm);
  snprintf(db_name, 100, "logs_%s.db", db_make_time);

  char *errMsg = 0;
  int db_result = sqlite3_open(db_name, &db);
  if (db_result != SQLITE_OK) {
    db = NULL;
    printf("[DB 생성 실패] 프로그램을 종료합니다.\n");
    exit(0);
  } else {
    int table_result = create_table_in_sqlite3(db);
    if (table_result == 0) {
      printf("[TABLE 생성 실패] 프로그램을 종료합니다.\n");
      exit(0);
    }
  }

  int usleep_count = 0;

  while(1) {
  
    if (*end_flag == 1) {
      printf("[log thread] 프로그램 종료를 감지했습니다. 남은 로그를 적습니다.\n");
      writeLog(&logqueue, db);

      if (db!=NULL) sqlite3_close(db);
      break;
    }
    
    time_t current_time;
    time(&current_time);
    double elapsed_time = current_time - start_time; //Sec    

    DangerPacket * dangerpacket = dequeueDangerPacket(danger_pkt_queue);
    if (dangerpacket != NULL) {
      enqueueLog(&logqueue, dangerpacket);
    } else {
      usleep_count ++;
      if(usleep_count == 10) {
        usleep(1);
        usleep_count = 0; 
      }
    }

    if ((logqueue.count > (MAX_LOG_QUEUE_SIZE*0.8))){
      start_time = current_time;
      writeLog(&logqueue, db);
    }
    else if (logqueue.count > 0 && elapsed_time >= 10) {
      start_time = current_time;
      writeLog(&logqueue, db);
    }
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

void writeLog(LogQueue *queue, sqlite3 *db){
  while (queue->count) {
    DangerPacket * packet = dequeueLog(queue);
    if (packet != NULL) {
      int result = insert_data_in_db(db, packet);
      if (result == 0) {
        printf("sqlite 저장실패.\n");
        exit(0);
      }
      free(packet);
    }
  }
}

int create_table_in_sqlite3(sqlite3 *db) {
  char *errMsg = 0;
  int result = 0;

  char *createTableQuery =  
          "CREATE TABLE IF NOT EXISTS LOGS ("
          "ORDERNUM INTEGER PRIMARY KEY AUTOINCREMENT,"
          "DETECTTIME TEXT,"
          "SRCIP TEXT,"
          "SRCPORT INTEGER,"
          "DSTIP TEXT,"
          "DSTPORT INTEGER,"
          "RULENAME TEXT,"
          "RULECONTENT TEXT);";

  result = sqlite3_exec(db, createTableQuery, 0, 0, &errMsg);
  if (result != SQLITE_OK) return 0;
  else return 1; 
}

int insert_data_in_db(sqlite3 *db, DangerPacket *packet){
  char insertDataQuery[300];
  int result = 0;
  char *errMsg = 0;

  char notsp[15] = "not support";
  char overflow[15] = "overflow";

  if (strcmp(packet->protocol, notsp)==0) {
    snprintf(insertDataQuery, 300,
            "INSERT INTO LOGS (DETECTTIME, RULENAME) VALUES (\"%s\", \"%s\");",
            packet->detecttime, notsp);
  } else if (strcmp(packet->protocol, overflow)==0){
    snprintf(insertDataQuery, 300,
            "INSERT INTO LOGS (DETECTTIME, RULENAME) VALUES (\"%s\", \"%s\");",
            packet->detecttime, overflow);
  } else {
    snprintf(insertDataQuery, 300,
            "INSERT INTO LOGS (DETECTTIME, SRCIP, SRCPORT, DSTIP, DSTPORT, RULENAME, RULECONTENT)"
            " VALUES (\"%s\", \"%s\", %u, \"%s\", %u, \"%s\", \"%s\");",
            packet->detecttime, packet->srcip, packet->srcport, packet->dstip, packet->dstport, 
            packet->rulename, packet->rulecontent);
  }
 // printf("%s\n", insertDataQuery);
  result = sqlite3_exec(db, insertDataQuery, 0, 0, &errMsg);
  if (result != SQLITE_OK){
    return 0;
  }else return 1;
}

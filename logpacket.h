#ifndef LOGPACKET_H
#define LOGPACKET_H

#include <sqlite3.h>

typedef struct {
  int front, rear;
  int count;
  DangerPacket **packet;
  int MAX_QUEUE_SIZE;
} LogQueue;

void *start_logthread(void *logstruct);
void initLogQueue(LogQueue *queue, int queuesize);
void enqueueLog(LogQueue *queue, DangerPacket *value);
DangerPacket * dequeueLog(LogQueue *queue);

void makeLogFile(LogQueue *queue, sqlite3 *db);
void writeLog(LogQueue *queue,sqlite3 *db);
char * returnLogString(DangerPacket *packet);
int create_table_in_sqlite3(sqlite3 *db);
int insert_data_in_db(sqlite3 *db, DangerPacket *packet);
#endif

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
void init_log_queue(LogQueue *queue, int queuesize);
void enqueue_log(LogQueue *queue, DangerPacket *value);
DangerPacket * dequeue_log(LogQueue *queue);

void write_log_in_db(LogQueue *queue,sqlite3 *db);
int create_table_in_sqlite3(sqlite3 *db);
int insert_data_in_db(sqlite3 *db, DangerPacket *packet);
#endif

#ifndef LOGPACKET_H
#define LOGPACKET_H

#define MAX_LOG_QUEUE_SIZE 1028

typedef struct {
  int front, rear;
  int count;
  DangerPacket *packet[MAX_LOG_QUEUE_SIZE];
} LogQueue;

void *start_logthread(void *logstruct);
void initLogQueue(LogQueue *queue);
void enqueueLog(LogQueue *queue, DangerPacket *value);
DangerPacket * dequeueLog(LogQueue *queue);

void makeLogFile(LogQueue *queue);
void writeLog(LogQueue *queue, FILE *logfile);
char * returnLogString(DangerPacket *packet);
int save_log_in_sqlite3();
char *return_query_string(DangerPacket *packet);
#endif

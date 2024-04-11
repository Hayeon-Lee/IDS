#ifndef LOGPACKET_H
#define LOGPACKET_H

#define MAX_QUEUE_SIZE 128

typedef struct {
  int front, rear;
  int count;
  DangerPacket *packet[MAX_QUEUE_SIZE];
} LogQueue;

int start_logthread(void *dangerpacketqueue);
void initLogQueue(LogQueue *queue);
void enqueueLog(LogQueue *queue, DangerPacket *value);
DangerPacket * dequeueLog(LogQueue *queue);

void makeLogFile(LogQueue *queue);
void writeLog(LogQueue *queue, FILE *logfile);
char * returnLogString(DangerPacket *packet);
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "queue.h"
#include "detectpacket.h"

void initPacketQueue(PacketQueue *queue, int queuesize) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
  queue->MAX_QUEUE_SIZE = queuesize;
  queue->packet = (Packet **)malloc(sizeof(Packet*)*queuesize);

  queue->total_enqueue_cnt = 0;
  queue->total_dequeue_cnt = 0;
  queue->total_drop_cnt = 0;

  pthread_mutex_init(&(queue->mutex), NULL);
}

int enqueuePacket(PacketQueue *queue, Packet *value, int size){
  pthread_mutex_lock(&(queue->mutex));
  queue->total_enqueue_cnt++;

  if (queue->count >= queue->MAX_QUEUE_SIZE) {
    queue->total_drop_cnt ++;
    pthread_mutex_unlock(&(queue->mutex));
    return -1;
  }
  queue->rear = ((queue->rear)+1)%(queue->MAX_QUEUE_SIZE);
  queue->packet[queue->rear] = value;
  queue->count += 1;
  pthread_mutex_unlock(&(queue->mutex));
  return 1;
}

Packet * dequeuePacket(PacketQueue *queue){
  
  pthread_mutex_lock(&(queue->mutex));  

  if (queue->count <= 0) {
    pthread_mutex_unlock(&(queue->mutex));
    return NULL;
  }

  Packet *item;
  item = queue->packet[queue->front];
  queue->front = ((queue->front)+1)%(queue->MAX_QUEUE_SIZE);
  queue->count -= 1;
  queue->total_dequeue_cnt ++;
  pthread_mutex_unlock(&(queue->mutex));

  return item;
}

void initDangerPacketQueue(DangerPacketQueue *queue, int queuesize) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
  queue->MAX_QUEUE_SIZE = queuesize;

  queue->items = (DangerPacket **)malloc(sizeof(DangerPacket *)*queuesize);
  
  queue->total_enqueue_cnt = 0;
  queue->total_dequeue_cnt = 0;
  queue->total_drop_cnt = 0;
  
  pthread_mutex_init(&(queue->mutex), NULL);
}

void enqueueDangerPacket(DangerPacketQueue *queue,DangerPacket *value) {
  pthread_mutex_lock(&(queue->mutex));
  queue->total_enqueue_cnt ++;

  if (queue->count >= queue->MAX_QUEUE_SIZE) {
    queue->total_drop_cnt ++;
    pthread_mutex_unlock(&(queue->mutex));
    return;
  } 
  
  queue->rear = ((queue->rear)+1)%(queue->MAX_QUEUE_SIZE);
  queue->items[queue->rear] = value;
  queue->count += 1;
  pthread_mutex_unlock(&(queue->mutex));
}

DangerPacket * dequeueDangerPacket(DangerPacketQueue *queue) {
  pthread_mutex_lock(&(queue->mutex));

  if(queue->count <= 0) {
    pthread_mutex_unlock(&(queue->mutex));
    return NULL;
  }
  DangerPacket *item;
  item = queue->items[queue->front];
  queue->front = ((queue->front+1))%(queue->MAX_QUEUE_SIZE);
  queue->count -= 1;
  queue->total_dequeue_cnt ++;
  pthread_mutex_unlock(&(queue->mutex));

  return item;
}

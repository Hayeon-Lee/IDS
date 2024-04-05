#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "queue.h"

void initQueue(CircularQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
  
  return;
}

void enqueue(CircularQueue *queue, int value) {
  if (queue->count >= MAX_QUEUE_SIZE) {
    printf("Queue가 꽉 차 대기합니다.");
    return;
  }

  queue->rear = ((queue->rear)+1)%MAX_QUEUE_SIZE;
  queue->data[queue->rear] = value;
  queue->count += 1;
}

void dequeue(CircularQueue *queue) {
  if (queue->count <=0) {
    printf("Queue가 비어있습니다.");
    return;
  }

  //int value = queue->data[queue->front];
  queue->front = ((queue->front)+1)%MAX_QUEUE_SIZE;
  queue->count -= 1;
}

void initPacketQueue(PacketQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
}

void enqueuePacket(PacketQueue *queue, const u_char *value, int size){
  if (queue->count >= MAX_QUEUE_SIZE) {
    printf("Queue가 꽉 차 드롭합니다.\n");
    return;
  }

  queue->rear = ((queue->rear)+1)%MAX_QUEUE_SIZE;
  queue->packet[queue->rear] = (const u_char *)malloc(size * sizeof(u_char));
  memcpy((void *)(&queue->packet[queue->rear]), value, size);
  queue->count += 1;
}

void dequeuePacket(PacketQueue *queue){
  if (queue->count <= 0) {
    printf("Queue가 비어있습니다.");
    return;
  }
  
  queue->front = ((queue->front)+1)%MAX_QUEUE_SIZE;
  queue->count -= 1;
}

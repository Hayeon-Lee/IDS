#include "queue.h"

void initQueue(CircularQueue *queue) {
  queue->front = 0;
  queue->rear = -1;
  queue->count = 0;
  
  return;
}

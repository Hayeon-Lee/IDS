#ifndef QUEUE_H
#define QUEUE_H

#define MAX_QUEUE_SIZE 128 //임시값

//Circular Queue Structure
typedef struct {
  int front, rear;
  int count;
  int data[MAX_QUEUE_SIZE]; 
} CircularQueue;

void initQueue(CircularQueue *queue);
//void enqueue(CircularQueue *queue, int value)
//void dequeue(CircularQueue *queue) return

#endif

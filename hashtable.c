#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

#define FLOOD -1
#define SUCCESS 1
#define FAIL 0

#define NOT_EMPTY 2
#define EMPTY 3

void initHashTable(HashTable *hashtable, FloodConfig *flood_config ){
  hashtable->table = (HashTableNode **)malloc(sizeof(HashTableNode*)*flood_config->tablesize);

  for(int i=0; i<flood_config->tablesize; i++) hashtable->table[i] = NULL;

  hashtable->tablesize = flood_config->tablesize;
  hashtable->timelimit = flood_config->timelimit;
  hashtable->count = flood_config->count;

  pthread_mutex_init(&(hashtable->mutex), NULL);
  return;
}

int checkHashTable(HashTable *hashtable, unsigned int srcip) {
  int key = srcip % hashtable->tablesize;
  
  if (hashtable->table[key]) return NOT_EMPTY;
  return EMPTY;
}

HashTableNode* makeTableNode(unsigned int srcip) {
  
  time_t detect_time;
  time(&detect_time);

  HashTableNode *node = (HashTableNode *)malloc(sizeof(HashTableNode));
  if (node == NULL) {
    printf("해시테이블 저장에 문제가 생겼습니다. 프로그램을 종료합니다.\n");
    exit(0);
  }

  node->srcip = srcip;
  node->count = 1;
  node->detecttime = detect_time;

  return node;
}

int insertTableNode(HashTable *hashtable, unsigned int srcip){
  pthread_mutex_lock(&(hashtable->mutex));

  int isEmpty = checkHashTable(hashtable, srcip);
  int key = srcip % (hashtable->tablesize);

  time_t current_time;
  time(&current_time);
  double elapsed_time = current_time - hashtable->table[key]->detecttime;
  
  if (isEmpty == EMPTY) {
    hashtable->table[key] = makeTableNode(srcip);
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  //not empty 코드
  if (elapsed_time > hashtable->timelimit) { //시간보다 지났으면 초기화
    free(hashtable->table[key]);
    hashtable->table[key] = makeTableNode(srcip);
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  if (elapsed_time <= hashtable->timelimit) { //시간보다 지나지 않았다면 비교
    if (hashtable->table[key]->count >= (hashtable->count)-1) { //개수가 넘었다면
        free(hashtable->table[key]);
        hashtable->table[key] = NULL;
        pthread_mutex_unlock(&(hashtable->mutex));
        return FLOOD;     
    }
    hashtable->table[key]->count += 1;
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  return FAIL;
}

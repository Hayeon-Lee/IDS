#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "hashtable.h"

#define FLOOD -1
#define SUCCESS 1
#define FAIL 0
#define EMPTY 1
#define NOT_EMPTY 0

void initHashTable(HashTable *hashtable, FloodConfig *flood_config ){
  hashtable->table = (HashTableNode **)malloc(sizeof(HashTableNode*)*flood_config->tablesize);
  memset(hashtable->table, 0x00, sizeof(HashTableNode *)*flood_config->tablesize);

  hashtable->tablesize = flood_config->tablesize;
  hashtable->timelimit = flood_config->timelimit;
  hashtable->count = flood_config->count;

  pthread_mutex_init(&(hashtable->mutex), NULL);
  return;
}

int isEmptyHashTable(HashTable *hashtable, int key) { 
  return (hashtable->table[key]) ? NOT_EMPTY : EMPTY;
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

int hashSrcIp (unsigned int srcip) {
 
  void *srcip_void_pointer = (void *)&(srcip);
  char *srcip_str= (char *)srcip_void_pointer;
  unsigned char string_srcip_hash[17];
  SHA256((const unsigned char *)srcip_str, 16, string_srcip_hash);

  int *integer_srcip_hash = (int *)string_srcip_hash;
  return *integer_srcip_hash;
}

int insertTableNode(HashTable *hashtable, unsigned int srcip){
  pthread_mutex_lock(&(hashtable->mutex));

  int key = hashSrcIp(srcip) % (hashtable->tablesize);
  int isEmpty = isEmptyHashTable(hashtable, key);

  struct timespec detect_ts, current_ts;
  clock_gettime(CLOCK_REALTIME, &current_ts);

  if (isEmpty) {
    hashtable->table[key] = makeTableNode(srcip);
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  detect_ts.tv_sec = hashtable->table[key]->detecttime;
  detect_ts.tv_nsec = 0;
  long sec_diff = current_ts.tv_sec - detect_ts.tv_sec;
  
  //not empty 코드
  if (sec_diff > hashtable->timelimit) { //시간보다 지났으면 초기화
    free(hashtable->table[key]);
    hashtable->table[key] = makeTableNode(srcip);
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  if (sec_diff <= hashtable->timelimit) { //시간보다 지나지 않았다면 비교
    hashtable->table[key]->count += 1;
    if (hashtable->table[key]->count >= hashtable->count) { //개수가 넘었다면
        free(hashtable->table[key]);
        hashtable->table[key] = NULL;
        pthread_mutex_unlock(&(hashtable->mutex));
        return FLOOD;     
    }
    pthread_mutex_unlock(&(hashtable->mutex));
    return SUCCESS;
  }

  pthread_mutex_unlock(&(hashtable->mutex));
  return FAIL;
}

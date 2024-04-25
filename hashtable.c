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

/*
 *  Ozan Yigit's original sdbm hash.
 *
 * Ugly, but fast.  Break the string up into 8 byte units.  On the first time
 * through the loop get the "leftover bytes" (strlen % 8).  On every other
 * iteration, perform 8 HASHC's so we handle all 8 bytes.  Essentially, this
 * saves us 7 cmp & branch instructions.
 *
*/
uint32_t hash_func4 (const char *key, int len) { //ub8 이 unsigned  8비트 char
  const char *k;
  unsigned int n, loop;

  if (len == 0)
    return (0);

#define  HASHC  n = *k++ + 65599 * n
  n = 0;
  k = key;

  loop = (len + 8 - 1) >> 3;
  switch (len & (8 - 1)) {
  case 0:
    do {
      HASHC;
  case 7:
      HASHC;
  case 6:
      HASHC;
  case 5:
      HASHC;
  case 4:
      HASHC;
  case 3:
      HASHC;
  case 2:
      HASHC;
  case 1:
      HASHC;
    } while (--loop);
  }
  return (n);
}

void initHashTable(HashTable *hashtable, FloodConfig *flood_config ){
  hashtable->node = (HashTableHead*)malloc(sizeof(HashTableHead)*flood_config->tablesize);
  for (int i=0; i<flood_config->tablesize; i++) {
    hashtable->node[i].nodecnt = 0;
    hashtable->node[i].next = NULL;
  }

  hashtable->tablesize = flood_config->tablesize;
  hashtable->timelimit = flood_config->timelimit;
  hashtable->count = flood_config->count;

  pthread_mutex_init(&(hashtable->mutex), NULL);

  return;
}

int isEmptyHashTable(HashTable *hashtable, int key) { 
  return (hashtable->node[key].nodecnt) ? NOT_EMPTY : EMPTY;
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
  node->next = NULL;

  return node;
}

HashTableNode* findTargetLocation(HashTable *hashtable, int key, unsigned srcip){
  HashTableNode *node = hashtable->node[key].next;

  while(node != NULL) {
    if (node->srcip == srcip) return node; //그 아이피를 가진 노드를 반환해준다
    if (node->next == NULL) return node; //다음 위치가 null이면 (끝까지 찾은거니까) 이 아이피는 없는 아이피이므로 반환한다.
  }

  node = NULL;
  return node;
}

int insertNode(HashTable *hashtable, int key, unsigned int srcip, int isEmpty){
  
  if (isEmpty){
    hashtable->node[key].nodecnt = 1; //첫 번째
    hashtable->node[key].next = makeTableNode(srcip);
    hashtable->node[key].next->prev = NULL; //앞 노드는 HEAD이기 때문에 양방향 연결 x 
    return SUCCESS; 
  }


  struct timespec detect_ts, current_ts;
  clock_gettime(CLOCK_REALTIME, &current_ts);

  HashTableNode *target_node = findTargetLocation(hashtable, key, srcip);
  if (!target_node) return FAIL;

  if (target_node->srcip != srcip) { //이 아이피는 리스트에 존재하지 않는다 == 끝에 넣어준다
    hashtable->node[key].nodecnt += 1;
    target_node->next = makeTableNode(srcip);
    target_node->next->prev = target_node; //앞 뒤 연결해줌
    return SUCCESS;
  }
  
  //이 아이피는 리스트에 존재한다
  detect_ts.tv_sec = target_node->detecttime;
  detect_ts.tv_nsec = 0;
  long sec_diff = current_ts.tv_sec - detect_ts.tv_sec;

  if (sec_diff > hashtable->timelimit) { //시간을 체크해봤는데 제한시간이 지났다
    time_t detect_time;
    time(&detect_time);

    target_node->count = 0;
    target_node->detecttime = detect_time;
    return SUCCESS;
  }

  if (sec_diff <= hashtable->timelimit) { //시간을 체크해봤는데 제한시간이 안 지났다
    target_node->count += 1;

    if (target_node->count >= hashtable->count) { //제한 개수가 넘었다면
      hashtable->node[key].nodecnt -= 1;
    
      //내 앞이 헤드이면
      if (target_node->prev == NULL) {
        hashtable->node[key].next = target_node->next;
        if (target_node->next != NULL) 
          target_node->next->prev = NULL;
        free(target_node);
        return FLOOD;
      }
      
      //내 앞에 노드가 있다면
      target_node->prev->next = target_node->next;
      if(target_node->next != NULL) 
        target_node->next->prev = target_node->prev;     
      free(target_node);
      return FLOOD;
    }
    return SUCCESS;
  }
  return FAIL; 
}

uint32_t hashSrcIp (unsigned int srcip) {
  return hash_func4((const char *)&srcip, sizeof(srcip));
}

int checkTable(HashTable *hashtable, unsigned int srcip) {
  pthread_mutex_lock(&(hashtable->mutex));
  
  uint32_t key = hashSrcIp(srcip) % (hashtable->tablesize);
  //fprintf(stderr, "key : [%u]\n", key);
  int isEmpty = isEmptyHashTable(hashtable, key);

  int insertResult = 0;
  insertResult = insertNode(hashtable, key, srcip, isEmpty);  
 
  pthread_mutex_unlock(&(hashtable->mutex));
  return insertResult;
}

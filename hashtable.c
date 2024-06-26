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

void init_hash_table(HashTable *hashtable, FloodConfig *flood_config ){
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

int is_empty_hash_table(HashTable *hashtable, int key) { 
  return (hashtable->node[key].nodecnt) ? NOT_EMPTY : EMPTY;
}

HashTableNode* make_table_node(unsigned int srcip) {
  
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

//함수의 목적이 2개가 되기 때문이다
HashTableNode* find_target_location(HashTable *hashtable, int key, unsigned srcip){
  HashTableNode *node = hashtable->node[key].next;

  while(node != NULL) {
    if (node->srcip == srcip) return node; //그 아이피를 가진 노드를 반환해준다
    if (node->next == NULL) return node; //다음 위치가 null이면 (끝까지 찾은거니까) 이 아이피는 없는 아이피이므로 반환한다.
    //마지막 노드의 위치를 따로 저장을 해둔 다음 그 위치에 붙이는 것이 좋다 (가독성 측면에서) 
    node = node->next;
  }

  return NULL; //오류가 발생할 수 있는 부분이기 때문에 명시적으로 NULL 을 리턴해주는 것이 좋다.
}

int insert_table_node(HashTable *hashtable, int key, unsigned int srcip, int isEmpty){
  
  if (isEmpty){
    hashtable->node[key].nodecnt = 1; //첫 번째
    hashtable->node[key].next = make_table_node(srcip);
    hashtable->node[key].next->prev = NULL; //앞 노드는 HEAD이기 때문에 양방향 연결 x 
    return SUCCESS; 
  }

/*
위치를 저장한 뒤 그 부분에 추가하는 것으로 바꾸는 것이 좋을 것 같습니다
*/

  struct timespec detect_ts, current_ts;
  clock_gettime(CLOCK_REALTIME, &current_ts);

  HashTableNode *target_node = find_target_location(hashtable, key, srcip);
  if (!target_node) return FAIL;

  if (target_node->srcip != srcip) { //이 아이피는 리스트에 존재하지 않는다 == 끝에 넣어준다
    hashtable->node[key].nodecnt += 1;
    target_node->next = make_table_node(srcip);
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

uint32_t hash_src_ip (unsigned int srcip) {
  return hash_func4((const char *)&srcip, sizeof(srcip));
}

int check_table(HashTable *hashtable, unsigned int srcip) {
  pthread_mutex_lock(&(hashtable->mutex));
  
  uint32_t key = hash_src_ip(srcip) % (hashtable->tablesize);
  int isEmpty = is_empty_hash_table(hashtable, key); //함수로 만들지 않아도 되지 않았을까? - inline으로 짜는 게 어땠을까? - 성능적 측면에서 나쁘지 않을까?
 
/* 
* hashtable 자료구조랑 프로그램의 로직이 섞여 불편한 것 같습니다: 코드 재활용이 어려워보입니다 
* 해시테이블 키 별로 들어갈 수 있는 항목의 제한이 있으면 좋을 것 같습니다: 해시테이블이 저장할 수 있는 노드의 개수를 제한하면 좋겠습니다 
* create/destroy/insert/remove/count/get... -> 라이브러리 개발 시 함수의 이름을 정형화시키는 것이 좋을 것 같습니다 (확장성과 범용성을 고려했을 때)
*/

  int insertResult = 0;
  insertResult = insert_table_node(hashtable, key, srcip, isEmpty);  
 
  pthread_mutex_unlock(&(hashtable->mutex));
  return insertResult;
}

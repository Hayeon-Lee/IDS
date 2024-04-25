#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdint.h>
#include <pthread.h>
#include <time.h>

#define FLOOD_IP_ADDR_LEN 16

typedef struct {
  int32_t tablesize;
  int32_t timelimit;
  int32_t count;
} FloodConfig;


typedef struct _HashTableNode {
  unsigned int srcip;
  int count;
  time_t detecttime;

  struct _HashTableNode *prev;
  struct _HashTableNode *next;
} HashTableNode;

typedef struct {
  int nodecnt;
  HashTableNode *next;
} HashTableHead;

typedef struct {
  HashTableHead *node;
  int tablesize;
  int timelimit;
  int count;
  pthread_mutex_t mutex;
} HashTable;

void initHashTable(HashTable *hashtable, FloodConfig *flood_config);
int isEmptyHashTable(HashTable *hashtable, int key);
HashTableNode* makeTableNode(unsigned int srcip);
HashTableNode* findTargetLocation(HashTable *hashtable, int key, unsigned srcip);
int insertNode(HashTable *hashtable, int key, unsigned int srcip, int isEmpty);
int hashSourceTp(HashTable *hashtable, unsigned int srcip);
int hasSrcIp(unsigned int srcip);
int checkTable(HashTable *hashtable, unsigned int srcip);
#endif

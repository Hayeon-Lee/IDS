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

typedef struct {
  int nodecnt;
  struct HashTableNode *next;
} HashTableHead;

typedef struct {
  unsigned int srcip;
  int count;
  time_t detecttime;

  struct HashTableNode *next;
  struct HashTableNode *prev;
} HashTableNode;

typedef struct {
  HashTableHead *node;
  int tablesize;
  int timelimit;
  int count;
  pthread_mutex_t mutex;
} HashTable;

void initHashTable(HashTable *hashtable, FloodConfig *flood_config);
//int hashSourceTp(HashTable *hashtable, unsigned int srcip);
//HashTableNode* makeTableNode(unsigned int srcip);
//int insertTableNode(HashTable *hashtable, unsigned int srcip);
//int isEmptyHashTable(HashTable *hashtable, int key);
//int hashSrcIpKey(unsigned int srcip);
#endif

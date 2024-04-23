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
  unsigned int srcip;
  int count;
  time_t detecttime;
} HashTableNode;

typedef struct {
  HashTableNode **table;
  int tablesize;
  int timelimit;
  int count;
  pthread_mutex_t mutex;
} HashTable;

void initHashTable(HashTable *hashtable, FloodConfig *flood_config);
int hashSourceTp(HashTable *hashtable, unsigned int srcip);
HashTableNode* makeTableNode(unsigned int srcip);
int insertTableNode(HashTable *hashtable, unsigned int srcip);
#endif

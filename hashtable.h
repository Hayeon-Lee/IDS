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

void init_hash_table(HashTable *hashtable, FloodConfig *flood_config);
int is_empty_hash_table(HashTable *hashtable, int key);
HashTableNode* make_table_node(unsigned int srcip);
HashTableNode* find_target_location(HashTable *hashtable, int key, unsigned srcip);
int insert_table_node(HashTable *hashtable, int key, unsigned int srcip, int isEmpty);
int hash_source_ip(HashTable *hashtable, unsigned int srcip);
int check_table(HashTable *hashtable, unsigned int srcip);
#endif

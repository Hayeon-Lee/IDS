#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "queue.h"
#include "readpacket.h"

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

#define QUEUE_OVERFLOW -1

void *start_readthread(void * readstruct) {
  char * path = "./packets";

  ReadStruct * read_struct = (ReadStruct *)readstruct;
  PacketQueue* *packetqueue_array = read_struct -> packetqueue;
  DangerPacketQueue *dangerpacketqueue = read_struct->dangerpacketqueue;
  int *end_flag = read_struct->end_flag;
  int threadcnt = read_struct->threadcnt;

  DIR * directory = opendir(path);
  if (directory == NULL) {
    printf("[accessDirectory()]: 디렉토리에 접근할 수 없습니다.");
    printf("프로그램 종료합니다.\n");
    exit(0);
  }

  const char *processed_packet = "processed_packets";
  struct stat st;
  if(stat(processed_packet, &st) == -1) {
    mkdir(processed_packet, 0700);
    printf("directory_create\n");
  }

  while(1){
    if (*end_flag == 1) {
      closedir(directory);
      break;
    }

    struct dirent *entry;
    if ((entry = readdir(directory)) == NULL) usleep(1);
    else read_packet_files(directory, path, packetqueue_array, dangerpacketqueue, threadcnt, entry);
  }
  return NULL;
}

int check_filename_extension(const char * filename) {
  char *loc;

  if ((loc = strrchr(filename, '.')) == NULL) return 0;

  char *target_str_pcap = ".pcap";
  char *target_str_cap = ".cap";

  if (strcmp(loc, target_str_pcap) == 0 || strcmp(loc, target_str_cap) == 0) return 1;
  return 0;
}

void read_packet_files(DIR * directory,
    char * directory_path,
    PacketQueue* *packetqueue_array,
    DangerPacketQueue *dangerpacketqueue,
    int threadcnt,
    struct dirent *entry) {
  
  int queue_index = 0;

  if (strcmp(entry -> d_name, ".") == 0) return;
  if (strcmp(entry -> d_name, "..") == 0) return;

  if (check_filename_extension(entry->d_name)) {
    char before_process_path[MAX_FILENAME_LEN];
    char after_process_path[MAX_FILENAME_LEN];

    snprintf(before_process_path, MAX_FILENAME_LEN, "%s/%s", directory_path, entry->d_name);
    snprintf(after_process_path, MAX_FILENAME_LEN, "processed_packets/%s", entry->d_name);

    //read .pcap or .cap file
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_offline(before_process_path, errbuff);

    if (handle) {
      int result = 0;
      struct pcap_pkthdr * header;
      const u_char * packet;

      //read by line in .pcap or .cap file 
      while ((result = pcap_next_ex(handle, & header, &packet)) == 1) {
        if ((header -> caplen) > 0) {
          Packet *packet_node = make_packet_node(header, packet);

          int enqueue_result = enqueuePacket((PacketQueue * ) packetqueue_array[queue_index], packet_node, header -> caplen);
          queue_index = (queue_index + 1)%threadcnt;

          if (enqueue_result==QUEUE_OVERFLOW){
            DangerPacket *dangernode = make_danger_packet_node();
            enqueueDangerPacket(dangerpacketqueue, dangernode);
            free(packet_node);
          }
        }
      }
      pcap_close(handle);
      rename(before_process_path, after_process_path);
    }
  } 
}


DangerPacket *make_danger_packet_node(){
  DangerPacket * dangernode = (DangerPacket *)malloc(sizeof(DangerPacket));
  if (dangernode == NULL) {
    printf("큐가 오버플로우 되어 예외 처리 중 동적할당 문제로 인해 진행이 불가합니다.\n");
    exit(0);
  }

  char detecttime[30];
  time_t current_time;
  time(&current_time);

  struct tm *current_time_to_struct = localtime(&current_time);
  strftime(detecttime, sizeof(detecttime), "%y-%m-%d %H:%M:%S", current_time_to_struct);

  snprintf((char *)(dangernode->detecttime),30, "%s", detecttime);
  snprintf((char *)(dangernode->rulename),16, "%s", "overflow");
  snprintf((char *)(dangernode->rulecontent),255, "%s", "overflow");
  snprintf((char *)(dangernode->protocol),10, "%s", "overflow");

  return dangernode; 
}

Packet *make_packet_node(struct pcap_pkthdr *header, const u_char *packet){
  Packet *packet_node = (Packet *)malloc(sizeof(Packet));
  if (packet_node == NULL) {
    printf("패킷을 읽어왔지만 저장할 수 없습니다.\n");
    exit(0);
  }
  unsigned char *p_data = (unsigned char *)malloc(header->caplen);
  if (p_data == NULL) {
    printf("패킷 처리 라이브러리에서 제공한 패킷 데이터 처리 중 오류가 발생했습니다.\n");
    exit(0);
  }
 
  memcpy(p_data, packet, header->caplen);
  packet_node->packet = p_data;
  packet_node->caplen = header->caplen;

  return packet_node;
}

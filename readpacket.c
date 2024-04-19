#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "queue.h"
#include "readpacket.h"

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

void *start_readthread(void * readstruct) {
  char * path = "./packets";

  ReadStruct * read_struct = (ReadStruct *)readstruct;
  PacketQueue* *packetqueue_array = read_struct -> packetqueue;
  DangerPacketQueue *dangerpacketqueue = read_struct->dangerpacketqueue;
  int *end_flag = read_struct->end_flag;
  int threadcnt = read_struct->threadcnt;

  const char *processed_packet = "processed_packets";
  struct stat st;
  if(stat(processed_packet, &st) == -1) {
    mkdir(processed_packet, 0700);
    printf("directory_create\n");
  }

  while(1){
    sleep(1);
//디렉토리 내부에 파일이 없으면 usleep()
    DIR * directory = opendir(path);

    if (directory == NULL) {
      printf("[accessDirectory()]: 디렉토리에 접근할 수 없습니다.");
      printf("프로그램 종료합니다.\n");
      exit(0);
    }else {
      accessPacketFiles(directory, path, packetqueue_array, dangerpacketqueue, threadcnt);   
      closedir(directory);

      if (*end_flag == 1) break;
    }
  }
  return NULL;
}

int check_extension(const char * filename) {
  char *loc;

  if ((loc = strrchr(filename, '.')) != NULL) {
    char * target_str_pcap = ".pcap\0";
    char * target_str_cap = ".cap\0";

    if (strcmp(loc, target_str_pcap) == 0 ||
        strcmp(loc, target_str_cap) == 0) {
      return 1;
    } else {
      return 0;
    }
  } else {
    return 0;
  }
}

void accessPacketFiles(DIR * directory,
    char * directory_path,
    PacketQueue* *packetqueue_array,
    DangerPacketQueue *dangerpacketqueue,
    int threadcnt) {
  struct dirent * entry;
  
  int queue_index = 0; 
  //디렉토리의 파일 읽기
  while ((entry = readdir(directory)) != NULL) {
    //해당 디렉토리와 상위 디렉토리가 아닐 때
    if (strcmp(entry -> d_name, ".") != 0 &&
        strcmp(entry -> d_name, "..") != 0) {

      //확장자가 pcap인 파일만 진행
      if (check_extension(entry -> d_name)) {
        //파일 이름 합치기 
        char full_path[MAX_FILENAME_LEN] = "\0";
        char moving_path[MAX_FILENAME_LEN] ="\0";
        
        snprintf(full_path, MAX_FILENAME_LEN, "%s/%s", directory_path, entry->d_name);
        snprintf(moving_path, MAX_FILENAME_LEN, "./processed_packets/%s", entry->d_name);
        
        //패킷 읽기
        pcap_t * handle;
        char errbuff[PCAP_ERRBUF_SIZE];

        //파일 읽기
        handle = pcap_open_offline(full_path, errbuff);
        if (handle) {
          int result = 0;
          struct pcap_pkthdr * header;
          const u_char * packet;

          //pcap file에서 한 줄 한 줄 읽어오기
          while ((result = pcap_next_ex(handle, & header, &packet)) == 1) {
            if ((header -> caplen) > 0) {
              Packet *value = (Packet *)malloc(sizeof(Packet));
              unsigned char *p_data = (unsigned char *)malloc(header->caplen);
              memcpy(p_data, packet, header->caplen);

              value->packet = p_data;
              value->caplen = header->caplen;
              
              int r = enqueuePacket((PacketQueue * ) packetqueue_array[queue_index], value, header -> caplen);
              queue_index = (queue_index + 1)%threadcnt;
              if (r==-1){
                  DangerPacket * dangernode = (DangerPacket *)malloc(sizeof(DangerPacket));
                  char detecttime[30];
                  time_t current_time;
                  time(&current_time);

                  struct tm *local_time = localtime(&current_time);
                  strftime(detecttime, sizeof(detecttime), "%y-%m-%d %H:%M:%S", local_time);
                  snprintf((char *)(dangernode->detecttime),30, "%s", detecttime);
                  snprintf((char *)(dangernode->rulename),16, "%s", "overflow");
                  snprintf((char *)(dangernode->rulecontent),255, "%s", "overflow");
                  snprintf((char *)(dangernode->protocol),10, "%s", "overflow");

                  enqueueDangerPacket(dangerpacketqueue, dangernode);
                  free(value); //overflow된 패킷은 dangerpacket으로 저장되었으므로 없앤다.
                }
              }
            else {
              printf("패킷의 길이가 0입니다... 다음으로 넘어갑니다...");
            }
          }
          pcap_close(handle);
          rename(full_path, moving_path);
        }
        else {
          printf("[accessPacketFiles()]: 패킷파일 읽기 실패하였습니다... 다음으로 넘어갑니다...\n");
        }

      } 
      else {
        printf("지원되지 않는 확장자입니다... 다음 파일로 넘어갑니다...\n");
        continue;
      }
    }
  }
}

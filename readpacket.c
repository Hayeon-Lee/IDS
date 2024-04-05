#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "queue.h"
#include "readpacket.h"

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

int start_readthread(void * packetqueue) {
  char * path = "./packets";

  DIR * directory = opendir(path);

  if (directory == NULL) {
    printf("[accessDirectory()]: 디렉토리에 접근할 수 없습니다.");
    return -1;
  } else {
    accessPacketFiles(directory, path, packetqueue);
  }
}

int check_extension(const char * filename) {

  char * loc;

  if ((loc = strrchr(filename, '.')) != NULL) {
    char * target_str = ".pcap\0";

    if (( * loc == '.') && strcmp(loc, target_str) == 0) {
      return 1;
    } else {
      return -1;
    }
  } else {
    return -1;
  }
}

void accessPacketFiles(DIR * directory, char * directory_path, void * packetqueue) {
    struct dirent * entry;

    //디렉토리의 파일 읽기
    while ((entry = readdir(directory)) != NULL) {
      //해당 디렉토리와 상위 디렉토리가 아닐 때
      if (strcmp(entry -> d_name, ".") != 0 && strcmp(entry -> d_name, "..") != 0) {

        int ext_result = check_extension(entry -> d_name);
        //확장자가 pcap인 파일만 진행
        if (ext_result == 1) {
          //파일 이름 합치기 
          char full_path[MAX_FILENAME_LEN] = "\0";
          strcat(full_path, directory_path);
          strcat(full_path, "/");
          strcat(full_path, entry -> d_name);

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
                  value->header = header;
                  value->packet = (u_char *)packet;
                  
                  enqueuePacket((PacketQueue * ) packetqueue, value, header -> caplen);
                } 
                else {
                  printf("패킷의 길이가 0입니다... 다음으로 넘어갑니다...");
                }
            }
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
    closedir(directory);
}

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

typedef struct {
  struct ether_header *ethernet_header;
  struct in_addr srcip;
  struct in_addr dstip;
  unsigned short protocol;
} Packet;

int accessDirectory();
int check_extension(const char *filename);
void accessPacketFiles(DIR *directory, char * directory_path);
int readEthernet(pcap_t * handle);

int main() {
  accessDirectory();
}

int accessDirectory() {
  char * path = "./packets";

  DIR *directory = opendir(path);

  if (directory == NULL) {
    printf("[accessDirectory()]: 디렉토리에 접근할 수 없습니다.");
    return -1;
  }
  else {
    accessPacketFiles(directory, path);   
  }
}

int check_extension(const char *filename) {

  char * loc;

  if ((loc = strrchr(filename, '.'))!=NULL) {
    char *target_str = ".pcap\0";

    if((*loc == '.') && strcmp(loc, target_str)==0){
      return 1;
    }
    else {
      return -1;
    }
  }
  else {
    return -1;
  }
}

void accessPacketFiles(DIR *directory, char * directory_path) {
  struct dirent* entry; 

  //디렉토리의 파일 읽기
  while ((entry = readdir(directory))!=NULL){
    //해당 디렉토리와 상위 디렉토리가 아닐 때
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0){

      int ext_result = check_extension(entry->d_name);   
      //확장자가 pcap인 파일만 진행
      if (ext_result == 1) {
        //파일 이름 합치기 
        char full_path[MAX_FILENAME_LEN] = "\0";
        strcat(full_path, directory_path);
        strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        //패킷 읽기
        pcap_t *handle;
        char errbuff[PCAP_ERRBUF_SIZE];
        handle = pcap_open_offline(full_path, errbuff);

        if (handle) {
          readEthernet(handle);
        } 
        else {
          printf("[accessPacketFiles()]: 패킷파일 읽기 실패하였습니다... 다음 파일로 넘어갑니다...\n");
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

int readEthernet(pcap_t * handle) {
  struct pcap_pkthdr *header;
  const u_char *packet;

  int result = pcap_next_ex(handle, &header, &packet);

  struct ether_header *eth_header;
  eth_header = (struct ether_header*)packet;

  Packet packet_node;
  
  packet_node.ethernet_header = eth_header;

  unsigned short type = ntohs(packet_node.ethernet_header->ether_type);

  if (type == ETHERTYPE_IP) {
    printf("IPv4 입니다.");       
    return 1; 
  }

  else if (type == ETHERTYPE_IPV6) {
    printf("IPv6 입니다.");
    return 1;
  }

  else {
    printf("지원하지 않습니다.");
    return 1;
  }

  return 0;
}

int readIPV4() {

}

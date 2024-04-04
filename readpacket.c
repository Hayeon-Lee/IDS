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
#include <netinet/udp.h>

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

typedef struct {
  struct ether_header *ethernet_header;
  struct in_addr srcip;
  struct in_addr dstip;
  unsigned short protocol;
  unsigned short srcport;
  unsigned short dstport;
} Packet;

int accessDirectory();
int check_extension(const char *filename);
void accessPacketFiles(DIR *directory, char * directory_path);
void makePacketNode(const u_char *packet, struct pcap_pkthdr *header);
unsigned short readEthernet(const u_char *packet, Packet *packet_node);
int readIPV4(const u_char *packet, Packet *packet_node);
int readUDP (const u_char *packet, int ipsize, Packet *packet_node);

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
          
          struct pcap_pkthdr *header;
          const u_char *packet;
          int result = pcap_next_ex(handle, &header, &packet);
          
          if (result == 1) {    

            if ((header->caplen)>0) makePacketNode(packet, header);
            else printf("패킷의 길이가 0입니다... 다음 파일로 넘어갑니다...");
          }
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

void makePacketNode (const u_char *packet, struct pcap_pkthdr *header) { 
  Packet packet_node;

  if (header->caplen >= 14) {
    //이더넷 헤더
    unsigned short type = readEthernet(packet, &packet_node);
    
    //IPV4
    if (type == ETHERTYPE_IP && header->caplen >= 34) {
      int protocol = readIPV4(packet, &packet_node);
      
      //TCP
      if (protocol == 6 && header->caplen >= 54) {
        printf("tcp입니다\n");
      }
      //UDP
      if (protocol == 17 && header->caplen >= 42) {
        readUDP(packet, 20, &packet_node);
        printf("%u\n", packet_node.dstport);
        printf("udp입니다\n");
      }
      //ICMP
      if (protocol == 1 && header->caplen >= 42) {
        printf("icmp입니다.\n");
      }
    }
  }
}

unsigned short readEthernet(const u_char *packet, Packet *packet_node) {

    struct ether_header *eth_header;
    eth_header = (struct ether_header*)packet;

    packet_node->ethernet_header = eth_header;

    return ntohs(packet_node->ethernet_header->ether_type);
}

int readIPV4(const u_char *packet, Packet * packet_node) {

    struct ip *ip_header = (struct ip*)(packet+sizeof(struct ether_header));
    packet_node->srcip = ip_header->ip_src;
    packet_node->dstip = ip_header->ip_dst;
    packet_node->protocol = ip_header->ip_p;

    return packet_node->protocol;
}

int readUDP(const u_char *packet, int ipsize, Packet *packet_node) {
    int ether_size = sizeof(struct ether_header);
    int add_size = ether_size + ipsize;

    struct udphdr *udp_header = (struct udphdr*)(packet + add_size); 
  
    packet_node->srcport = udp_header->uh_sport;
    packet_node->dstport = udp_header->uh_dport;
    return 0;
}

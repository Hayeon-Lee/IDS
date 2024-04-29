#ifndef READPACKET_H
#define READPACKET_H

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

#include <pcap.h>
#include <dirent.h>
#include "queue.h"

void *start_readthread(void *readstruct);
int check_filename_extension(const char *filename);
void read_packet_files(DIR *directory, char * directory_path, PacketQueue **packetqueue_array, DangerPacketQueue *dangerpacketqueue, int threadcnt);
DangerPacket *make_danger_packet_node();
Packet *make_packet_node(struct pcap_pkthdr *header, const u_char *packet);
#endif

#ifndef READPACKET_H
#define READPACKET_H

#define MAX_FILENAME_LEN 511 //255+255+1(/)+1('\0')

#include <dirent.h>
#include "queue.h"

void *start_readthread(void *readstruct);
int check_extension(const char *filename);
void accessPacketFiles(DIR *directory, char * directory_path, PacketQueue* *packetqueue_array, DangerPacketQueue *dangerpacketqueue, int threadcnt);

#endif

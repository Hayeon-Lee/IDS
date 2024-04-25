CC = gcc
CFLAGS = -g -O2 -Wall -D_BSD_SOURCE 
LIBS = -lpthread -lpcap -lnsl -lsqlite3 
TARGET = IDS.out

SRCS = IDS.c queue.c readpacket.c detectpacket.c logpacket.c hashtable.c 
OBJS = $(SRCS:.c=.o)

all: preprocess $(TARGET)

$(TARGET): $(OBJS)
        $(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
        $(CC) $(CFLAGS) -c $< -o $@

preprocess:
        ./check_and_move.sh

clean:
        rm -f $(OBJS) $(TARGET)

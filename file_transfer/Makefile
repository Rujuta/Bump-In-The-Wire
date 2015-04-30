CC=gcc

CFLAGS = -I .
DEPS=net_include.h net_include_common.h queue.h

all: ncp rcv 

ncp: ncp_v1.c packet_creation.c
	$(CC) -o ncp ncp_v1.c packet_creation.c -I .

rcv: rcv_v1.c queue.c packet_creation.c
	$(CC) -o rcv rcv_v1.c queue.c packet_creation.c -I .

tcp_server: tcp_server.c 
	$(CC) -o tcp_server tcp_server.c 

tcp_client: tcp_client.c
	$(CC) -o tcp_client tcp_client.c


clean: 
	rm ncp
	rm rcv
	rm tcp_client
	rm tcp_server
%.o:    %.c
	$(CC) $(CFLAGS) $*.c



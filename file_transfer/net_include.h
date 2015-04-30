#include <stdio.h>

#include <stdlib.h>

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h> 
#include <netdb.h>
#include<sys/time.h>
#include <errno.h>
#include <arpa/inet.h>

#define PORT	     10230

#define MAX_MESS_LEN 1400


#include "net_include.h"
#include "net_include_common.h"
//#include "sendto_dbg.h"
#define NAME_LENGTH 80

void print_ip(int);
packet* create_packet(type new_type,int sequence_no, char* data_to_send){

	packet* new_packet;
	new_packet=(packet*)malloc(sizeof(packet));
	new_packet->packet_type=new_type;
	new_packet->sequence_num=sequence_no;
	if (data_to_send == NULL)
		strcpy(new_packet->payload,"\0");
	else
		strcpy(new_packet->payload,data_to_send);

	return new_packet;
}

/*Function to print an IP address*/
void print_ip(int from_ip){
printf( "\nIP : (%d.%d.%d.%d)\n",
			(htonl(from_ip) & 0xff000000)>>24,
			(htonl(from_ip) & 0x00ff0000)>>16,
			(htonl(from_ip) & 0x0000ff00)>>8,
			(htonl(from_ip) & 0x000000ff)
	      );

}

double get_time(struct timeval *tim){

	gettimeofday(tim,NULL);
	double time=tim->tv_sec+(tim->tv_usec/1000000.0);
	return (time);

}

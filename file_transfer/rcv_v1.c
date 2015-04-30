#include "net_include.h"
#include "net_include_common.h"
//#include "sendto_dbg.h"
#include "queue.h"
#define NAME_LENGTH 80

/**RECEIVER**/
void send_ack(int ,int, int , struct sockaddr_in *);
//packet* create_packet(type,int,char*);
void send_command(int, int, struct sockaddr_in *);
queue* get_queue();
int main(int argc, char *argv[]){

	/*File pointer to destination file*/
	FILE *dest_ptr;

	/*Socket structures*/
	struct sockaddr_in name; 
	struct sockaddr_in send_addr;
	struct sockaddr_in from_addr;
	struct sockaddr_in other_addr;

	/*IP of sender*/
	int from_ip;

	/*Socket descriptors*/
	int ss,sr;
	int change=0;

	/*Socket descriptor sets*/
	fd_set read_sd; 
	fd_set write_sd,temp_read_sd;

	/*Timeouts*/
	struct timeval timeout;

	/*Receiver window, array of pointers to packets*/
	packet* recv_buff[WINDOW]={NULL};


	/*No of bytes received*/
	int bytes;
	socklen_t from_len;
	int num;

	int index,i;
	int counter;
	int last_sequence_no=-3;

	/*Current ip is with which client*/
	int current_ip=-1;

	/*Pointer to hold received packet*/	
	packet *mess_buff2;

	/*Send command packet*/
	packet* send_command_packet;
	/*Sequence number of last packet received in order*/
	int max_inorder=-1;

	/*Counter to keep track of packets received after which ACK should be sent*/
	int ack_counter=0;

	/*Biggest sequence number received*/
	int biggest_recv=0;

	/*Progress IP*/
	int conn_set=0;

	/*Statistics*/
	double total_start_time=0;
	double block_start_time=0;
//	double time_taken=0;
	struct timeval time;
	long bytes_count=0;

	/*SENDER TIMER- to reset when server thinks client is dead*/
	int sender_timeout=0;
	/*Initialize Queue to hold Ip addresses*/
	queue *sender_queue;
	sender_queue=(queue*)get_queue();

	if(argc<2){
		printf("\nUsage: <./rcv> <loss%>\n");
	}
	sr=socket(AF_INET, SOCK_DGRAM, 0); 
	if (sr<0){
		perror("Ucast: socket");
		exit(1);
	}		 
	name.sin_family=AF_INET;
	name.sin_addr.s_addr=INADDR_ANY;
	name.sin_port=htons(PORT); 


	if( bind(sr, (struct sockaddr *)&name,sizeof(name)) < 0) {

		perror("Ucast: bind");
		exit(1);
	}

	ss= socket(AF_INET, SOCK_DGRAM,0);
	if (ss<0){
		perror("Ucast: Sending Socket");
		exit(1);
	}

	FD_ZERO(&read_sd);
	FD_ZERO(&write_sd);
	FD_SET(sr,&read_sd);

	other_addr.sin_family=AF_INET;
	other_addr.sin_port=htons(PORT);



//	sendto_dbg_init(atoi(argv[1]));
	for(;;){

		temp_read_sd=read_sd; //why??	
		timeout.tv_sec=RECV_TIMEOUT;


		//timeout.tv_sec=5;
		timeout.tv_usec=RECV_U_TIMEOUT;
		num = select( FD_SETSIZE, &temp_read_sd, &write_sd, &write_sd, &timeout);


		if(num>0){
			if(FD_ISSET(sr,&temp_read_sd)){

				from_len = sizeof(from_addr);

				mess_buff2=NULL;
				mess_buff2=(packet*)malloc(sizeof(packet));
				bytes=recvfrom(sr,(char*)mess_buff2,sizeof(packet),0,(struct sockaddr*)&from_addr,&from_len);
				from_ip=from_addr.sin_addr.s_addr;

				switch(mess_buff2->packet_type){



					case SEND_REQ: 
						
						//check currently serving client 
						//if no client  OR if send command of set client has been lost
						if(current_ip==-1 || current_ip==from_ip){
							send_command_packet=create_packet(SEND_COMMAND,-1,NULL);

							/*Sending the SEND_COMMAND packet*/
							current_ip=from_ip;
							conn_set=1;
							dest_ptr=fopen(mess_buff2->payload,"w");
							send_command(ss,current_ip,&send_addr);
							//gettimeofday(&time,NULL);
							//block_start_time=time.tv_sec+time.tv_usec/TIME_CONV;
							//total_start_time=block_start_time;
							bytes_count=0;
						}
						else{
							//send busy packet to client
							printf("\nGoing to send busy packet to client\n");
							packet* busy_packet=create_packet(BUSY,-1,NULL);
							other_addr.sin_addr.s_addr=from_ip;
							sendto(ss, (char*)busy_packet, sizeof(packet), 0,(struct sockaddr *)&other_addr, sizeof(other_addr));
							enqueue(sender_queue,from_ip);
							print_queue(sender_queue);
						}
						break;
					case DATA: 

						/*if receiver gets packet from a previous sender, send a msg saying trans complete*/
						if(current_ip!=from_ip){
							other_addr.sin_addr.s_addr=from_ip;
							packet* transc_packet=create_packet(TRANS_COMPLETE,-1,NULL);

							sendto(ss, (char*)transc_packet, sizeof(packet), 0,(struct sockaddr *)&other_addr, sizeof(other_addr));

						}	
						else{
							/*CHANGE -Sequence number of packet received*/
							int sequence_data_no=(int)mess_buff2->sequence_num;
							/*If sequence number is greater than last packet received in order - might be in order or 
							 * out of order packet*/
							if(sequence_data_no>max_inorder){

								/*Store the window in correct window location first*/
								recv_buff[sequence_data_no%WINDOW]=mess_buff2;

								/*Sequence number received is in order with last packet received in order so
								  we write it to file and send cumulative ACK 
								  We use while loop, to loop till part where things are NOT received so max inorder
								  received ACK can be sent*/



								if(sequence_data_no == (max_inorder+1)){

									counter=sequence_data_no;
									int window_location=counter%WINDOW;
									int temp_byte_cnt = 0;

									//counter=sequence_data_no%WINDOW;
									while(recv_buff[window_location]!=NULL){

										//window_location=sequence_data_no%WINDOW;
										int sz = strlen(recv_buff[window_location]->payload);
										int s = sz>SIZE?SIZE:(sz);
										int nwritten=fwrite(recv_buff[window_location]->payload,1,s,dest_ptr);
										temp_byte_cnt+= nwritten;

										recv_buff[window_location]=NULL;
										/*Increment sequence number to check if
										 * future packets have been received*/
										counter++;
										window_location=counter%WINDOW;
									}

									max_inorder=max_inorder+(counter-max_inorder-1);
								//	printf("a");
								//	max_inorder=counter-1;
									bytes_count += temp_byte_cnt; 
									long kbytes=bytes_count/1024;
								//	printf("b");
									long bignum=51200;
								//	printf("a");
									if(kbytes>=bignum){

							//			//printf("\nCompared\n");
										gettimeofday(&time,NULL);
								//	printf("c");
		double time_taken=time.tv_sec+time.tv_usec/TIME_CONV;
//
										time_taken=time_taken-block_start_time;
										printf("\nTime taken :%lf",time_taken);
								//	printf("d");
										printf("\n50 MB received\n");
									printf("\n50 MB data received in order in %lf time\n",time_taken);
										printf("\nData received : %ld",kbytes/1024);
										printf("\nAverage rate of transfer: %lf",bytes_count*8/(1024.0*1024*time_taken));
								gettimeofday(&time,NULL);
								//	printf("e");
										block_start_time=time.tv_sec+time.tv_usec/TIME_CONV;
										bytes_count=bytes_count%BLOCK_SIZE;
								//	printf("f");

									}
									//send an ACK cumulative



								}

								send_ack(max_inorder,sequence_data_no,ss,&send_addr);

							}
													}
						break;
					case DATA_EOF:

						/*if receiver gets packet from a previous sender, send a msg saying trans complete*/
						if(current_ip!=from_ip){
							packet* transc_packet=create_packet(TRANS_COMPLETE,-1,NULL);
							other_addr.sin_addr.s_addr=from_ip;
							sendto(ss, (char*)transc_packet, sizeof(packet), 0,(struct sockaddr *)&other_addr, sizeof(other_addr));

						}
						else{
							/*This is sequence number of last packet of file*/
							last_sequence_no=(int)mess_buff2->sequence_num;

							/*If entire file has been received inorder close file pointer else send nack's for missing packeys*/
							if(last_sequence_no==max_inorder) {

								packet *transc_packet=create_packet(TRANS_COMPLETE,-1,NULL);

								sendto(ss, (char*)transc_packet, sizeof(packet), 0,(struct sockaddr *)&send_addr, sizeof(send_addr));
								printf("\nTransfer completed to %d\n",from_ip);
								/*Reporting Statistics*/
								gettimeofday(&time,NULL);
								double time_taken=time.tv_sec+time.tv_usec/TIME_CONV;
								time_taken=time_taken-total_start_time;
								//printf("max inorder :%d",max_inorder);
								fseek(dest_ptr,0,SEEK_END);
								int data_received=ftell(dest_ptr);
								//printf("\nFseek says :%d",data_received);
								//printf("\nGot size of data\n");
								double megabytes=data_received/(1024*1024.0);
								printf("\nTotal data received in  MBytes order is %lf\n",megabytes);
								printf("\nTotal time taken is :%lf seconds",time_taken);
								printf("\nAverage rate of transfer: %lf Mbits per sec",(megabytes*8.0)/time_taken);
								printf("\nEnd of Transfer\n");
								fclose(dest_ptr);

								/*Now c`heck queue for any pending clients, if so, send them a send command ELSE
								 * resent current_ip to -1*/
								if(!is_empty(sender_queue)){
									current_ip=dequeue(sender_queue);
									print_queue(sender_queue);
									printf("\nGoing to activate next in queue\n");
									last_sequence_no=-3;
									conn_set=0;
									max_inorder=-1;
									packet* activ_packet=create_packet(ACTIVATE,-1,NULL);
									other_addr.sin_addr.s_addr=current_ip;
									sendto(ss, (char*)activ_packet, sizeof(packet), 0,(struct sockaddr *)&other_addr, sizeof(other_addr));

								}
								else{
									current_ip=-1;
									max_inorder=-1;
									conn_set=0;
									last_sequence_no=-3;
								}

							}
														/*If EOF packet has been reached but receiver does not have things in order*/	
							else{
								send_ack(max_inorder,-2,ss,&send_addr);


							}
						}
						break;
				}
			}
		}

		else{
			/*Some client is connected and EOF has been reached*/
			
			if(conn_set==0 && current_ip!=-1){
				packet* activ_packet=create_packet(ACTIVATE,-1,NULL);
				other_addr.sin_addr.s_addr=current_ip;
				sendto(ss, (char*)activ_packet, sizeof(packet), 0,(struct sockaddr *)&other_addr, sizeof(other_addr));

			}
			if(current_ip!=-1 && conn_set==1 && max_inorder!=-1){
				send_ack(max_inorder,-2,ss,&send_addr);
			}
			

		}


	} 	


}

void send_ack(int max_inorder,int res, int ss, struct sockaddr_in *send_addr){

	char * nack = malloc(8*sizeof(int));
	sprintf(nack, "%d", res);
	packet* ack_packet=create_packet(ACK,max_inorder,nack);
	sendto(ss, (char*)ack_packet, sizeof(packet), 0,(struct sockaddr *)send_addr, sizeof(*send_addr));


}

void send_command(int ss, int from_ip, struct sockaddr_in *send_addr){

	packet* send_command_packet=create_packet(SEND_COMMAND,-1,NULL);

	/*Setting send address*/
	send_addr->sin_addr.s_addr=from_ip;
	send_addr->sin_family=AF_INET;
	send_addr->sin_port=htons(PORT);
	sendto(ss, (char*)send_command_packet, sizeof(packet), 0,(struct sockaddr *)send_addr, sizeof(*send_addr));


}

#include "net_include.h"
#include "net_include_common.h"
#include <arpa/inet.h>
#define NAME_LENGTH 80
/**SENDER**/

char** get_host_name(char*);
void file_read(packet*, FILE* , int*, int*,int);
void send_packets(packet*,int,struct sockaddr_in *, int *, int);
void send_eof(int ,int , struct sockaddr_in *);


int main(int argc, char *argv[]){
	FILE *src_ptr;

	/*refers to self*/ 
	struct sockaddr_in name;

	/*refers to address of receiver*/
	struct sockaddr_in send_addr;	
	struct sockaddr_in from_addr;

	/*receiver address details*/
	struct hostent h_ent;		
	struct hostent *p_h_ent;

	/*Holds IP name*/
	char host_name[NAME_LENGTH]={'\0'}; 

	/*Receiver IP*/
	int host_num;	
	int from_ip;	
	int bytes;

	int out_of_order=0;
	/*Socket descriptors*/
	int ss,sr;	
	/*Socket descriptor sets*/
	fd_set read_sd,temp_mask; 
	fd_set write_sd;

	/*Sender timeouts*/
	struct timeval timeout;
	socklen_t from_len;

	/*sequence number at which EOF was obtained*/
	int sequence_no_eof=0;		

	/*Array to hold pointers to filename & hostname*/
	char** file_host;

	int num,i;
	int to_send=0;

	/*Next sequence number from which file read should begin*/
	int current_sequence_no=0;

	/*Next sequence number from which SEND should begin*/
	int window_first;
	/*Flag to indicate EOF is reached*/
	int eof_flag=0; 

	/*Variable indicating connection is established and sender is in the process of file transfer*/
	int conn_set=0;
	packet* send_req_packet;
	packet* recv_data; 

	/*Sending packet buffer*/
	packet send_buff[WINDOW];

	/*To hold the last sequence number acknowledged (it was received in order)*/
	int max_inorder_seq_ack;

	/*Receiver busy flag*/
	int receiver_busy=0;

	int no_of_packets_to_read;

	if(argc<4){
		printf("\nUsage: <ncp> <source file name> <destinationfile name> <destination_hostIP>\n");
	}
	sr=socket(AF_INET, SOCK_DGRAM, 0); 
	if (sr<0){
		perror("Ucast: socket");
		exit(1);
	}		 
	name.sin_family=AF_INET;
	name.sin_addr.s_addr=INADDR_ANY;
	name.sin_port=htons(PORT); 
	/*Bind the port to read socket*/
	if( bind(sr, (struct sockaddr *)&name,sizeof(name)) < 0) {
		perror("Ucast: bind");
		exit(1);
	}

	/*Socket for sending UDP data*/
	ss= socket(AF_INET, SOCK_DGRAM,0);
	if (ss<0){
		perror("Ucast: Sending Socket");
		exit(1);
	}

	/*Get file name at destination and host name*/
	//file_host=get_host_name(argv[3]);

	/*Get IP address and details of receiver*/
	//struct in_addr addr;
	//printf("\nHere\n");
	//fflush(stdout);
	//addr.s_addr = inet_addr(file_host[1]);
	//if (addr.s_addr == INADDR_NONE){
	//	printf("\n Enter a valid IP\n");
	//	exit(1);
	//}
	//p_h_ent = gethostbyaddr((char*) &addr, 4, AF_INET);

	//p_h_ent=gethostbyname(file_host[1]);
	//if(p_h_ent==NULL){
	//	printf("\nUcast: gethostbyname error\n");
	//	exit(1); 
	//	return 0;
	//}
	//memcpy(&h_ent,p_h_ent,sizeof(h_ent));
	//memcpy(&host_num,h_ent.h_addr_list[0],sizeof(host_num));
	send_addr.sin_family=AF_INET;
	send_addr.sin_addr.s_addr=host_num;
	send_addr.sin_port=htons(PORT);
	//addition - rujuta 27th april
	inet_pton(AF_INET, argv[3], &send_addr.sin_addr);

	FD_ZERO(&read_sd);
	FD_ZERO(&write_sd);
	FD_SET(sr,&read_sd); 

	/*First packet to be sent is of type SEND_REQ and packet data is destination filename*/
	send_req_packet=create_packet(SEND_REQ,-1,argv[2]);
	from_ip=send_addr.sin_addr.s_addr;

	/*First chunk of data sent*/	
	sendto(ss, (char*)send_req_packet, sizeof(packet), 0,
			(struct sockaddr *)&send_addr, sizeof(send_addr));


	//sendto_dbg_init(atoi(argv[1]));
	/**Statistics**/
	double total_time_taken=0;
	double total_start_time=0;
	double block_start_time=0;
	struct timeval time;
	int bytes_count=0;

	for(;;){
		temp_mask=read_sd;	
		timeout.tv_sec=SEND_TIMEOUT;
		timeout.tv_usec=SEND_U_TIMEOUT;
		num = select( FD_SETSIZE, &temp_mask, &write_sd, &write_sd, &timeout);
		if(num>0){
			if(FD_ISSET(sr,&temp_mask)){
				from_len = sizeof(from_addr);
				recv_data=NULL;
				recv_data=(packet*)malloc(sizeof(packet));
				bytes=recvfrom(sr,(char*)recv_data,sizeof(packet),0,(struct sockaddr*)&from_addr,&from_len); 

				switch(recv_data->packet_type){

					case SEND_COMMAND: 	

						/*Connection established*/
						conn_set=1;	
						//receiver_busy=0;

						/*No ACK has been received so far*/
						max_inorder_seq_ack=-1;

						/*Open the file to read*/
						if((src_ptr = fopen(argv[1], "r")) == NULL) {
							perror("fopen");
							exit(0);
						}
						printf("Opened %s for reading...\n", argv[1]);
						/*Read the file and create n packets where n=no of packets in one window*/
						/*current sequence num must be 0*/
						current_sequence_no=0;
						file_read(send_buff,src_ptr,&current_sequence_no,&eof_flag,WINDOW);
						/*Send packets numbered from last packet received +1 uptil current sequence number*/
						window_first=max_inorder_seq_ack+1;
						send_packets(send_buff,ss,&send_addr,&window_first,current_sequence_no-window_first);
						gettimeofday(&time,NULL);
						total_start_time=time.tv_sec+time.tv_usec/TIME_CONV;
						block_start_time=total_start_time;
						bytes_count=(WINDOW)*SIZE;


						/*If EOF is reached in first chunk of data to be sent, send DATA_EOF packet*/
						if(eof_flag==1){
							sequence_no_eof=current_sequence_no-1;
							send_eof(sequence_no_eof,ss , &send_addr);

						}

						break;
					case ACK: 
						out_of_order=atoi(recv_data->payload);

						if((eof_flag ==1)&&(sequence_no_eof == recv_data->sequence_num)){

							send_eof(sequence_no_eof,ss , &send_addr);

						}					


						else if(out_of_order==-2 && conn_set==1){
							/*File end has not been reached */


							max_inorder_seq_ack=recv_data->sequence_num;
							window_first=max_inorder_seq_ack+1;


							if(eof_flag!=1){

								/*Read more data from file & send*/
								if(current_sequence_no==window_first){

									no_of_packets_to_read=WINDOW;
									file_read(send_buff,src_ptr,&current_sequence_no,&eof_flag,no_of_packets_to_read);

									/*Sequence ACK is NOT received for whole window, so some packets ahead of
									 * this ACK are LOST/received out of order*/
									to_send=current_sequence_no-window_first;
									send_packets(send_buff,ss,&send_addr,&window_first,(current_sequence_no-window_first));
									bytes_count+=(to_send)*SIZE;
									//printf("\n bytes count:%d\n",bytes_count);
									if(bytes_count>=BLOCK_SIZE){
										double time_taken;
										gettimeofday(&time,NULL);
										time_taken=time.tv_sec+time.tv_usec/TIME_CONV;
										time_taken=time_taken-block_start_time;
										int total_data=(max_inorder_seq_ack+1)*SIZE;
										printf("\n50 MB data sent in order in %lf time\n",time_taken);
										printf("\n Total amount of data successfully transferred: %lf  MB \n",(total_data/(1024*1024.0)));
										printf("\nAverage rate of transfer: %lf Mbps ",((bytes_count*8)/(1024*1024*time_taken)));
										bytes_count=bytes_count%(BLOCK_SIZE);
										block_start_time=time.tv_sec+time.tv_usec/TIME_CONV;

									}

									if(eof_flag==1){
										sequence_no_eof=current_sequence_no-1;
										send_eof(sequence_no_eof,ss , &send_addr);
									}
								}
								else{
									send_packets(send_buff,ss,&send_addr,&window_first,current_sequence_no-window_first);
								}

							}
							/*File end has been reached and fewer packets need to be sent*/
							else{
								if(current_sequence_no==window_first){
									send_eof(sequence_no_eof,ss,&send_addr);

								}
								else{

									send_packets(send_buff,ss,&send_addr,&window_first,(sequence_no_eof-window_first+1));
								}
							}

						}


						else if(out_of_order>=max_inorder_seq_ack){
							send_buff[out_of_order%WINDOW].packet_type=NACK;





							if(max_inorder_seq_ack < (int)recv_data->sequence_num){

								no_of_packets_to_read=recv_data->sequence_num-max_inorder_seq_ack;
								max_inorder_seq_ack=recv_data->sequence_num;


								if(eof_flag!=1){



									/*If entire window is ACKed we move forward with sending
									  remaining file*/

									file_read(send_buff,src_ptr,&current_sequence_no,&eof_flag,no_of_packets_to_read);
									max_inorder_seq_ack=recv_data->sequence_num;
									/*Sequence ACK is NOT received for whole window, so some packets ahead of
									 * this ACK are LOST/received out of order*/
									to_send=current_sequence_no-window_first;
									//printf("TOSEND %d",to_send);
									send_packets(send_buff,ss,&send_addr,&window_first,(current_sequence_no-window_first));
									bytes_count=bytes_count+to_send*SIZE;
									//printf(" bytes count %d",bytes_count);
									if(bytes_count>=BLOCK_SIZE){
										double time_taken;
										gettimeofday(&time,NULL);
										time_taken=time.tv_sec+time.tv_usec/TIME_CONV;
										time_taken=time_taken-block_start_time;
										int total_data=(max_inorder_seq_ack+1)*SIZE;
										printf("\nReading from file\n");
										printf("\n50 MB data sent in order in %lf time\n",time_taken);
										printf("\n Total amount of data successfully transferred: %lf MB \n",(total_data/(1024*1024.0)));
										printf("\nAverage rate of transfer: %lf Mbps",((bytes_count*8)/(1024*1024*time_taken)));
										bytes_count=bytes_count%(BLOCK_SIZE);
										block_start_time=time.tv_sec+time.tv_usec/TIME_CONV;

									}

									if(eof_flag==1){
										sequence_no_eof=current_sequence_no-1;
										send_eof(sequence_no_eof,ss , &send_addr);
									}



								}

							}}	
							break;

					case BUSY:  	printf("\nSetting received BUSY\n");
							conn_set=2;

							break;
					case ACTIVATE: 						       send_req_packet=create_packet(SEND_REQ,-1,file_host[0]);
												       sendto(ss, (char*)send_req_packet, sizeof(packet), 0,(struct sockaddr *)&send_addr, sizeof(send_addr));
												       conn_set=0;
												       break;
					case TRANS_COMPLETE: 
												       if (conn_set==1){
													       fclose(src_ptr);
													       printf("\nTransfer Completed Successfully, exiting..\n");
													           gettimeofday(&time,NULL);
													         double time_taken=time.tv_sec+time.tv_usec/TIME_CONV;
													       time_taken=time_taken-total_start_time;

													       printf("\nTime taken: %lf",time_taken);
													       int data_sent=(sequence_no_eof)*SIZE+(strlen(send_buff[sequence_no_eof%WINDOW].payload))*sizeof(char);
													       int tmp_size= strlen(send_buff[sequence_no_eof%WINDOW].payload);
													       double megabytes=data_sent/(1024*1024.0);
													       printf("\nTotal data sent in  MBytes order is %lf\n",megabytes);
													       printf("\nTotal time taken is :%lf",time_taken);
													       printf("\nAverage rate of transfer: %lf Mbits per sec",(megabytes*8.0)/time_taken);

													       exit(0);				
												       }
												       break;

				}
			}	
		}
		else{
			if(conn_set==2){ //receiver is busy
				printf("\nStill waiting for my turn\n");
				continue;
			}

			/*Time out because SEND_REQ was lost*/
			if(conn_set==0){
				sendto(ss,(char*)send_req_packet,sizeof(packet),0,(struct sockaddr *)&send_addr,sizeof(send_addr));
			}
			/*Timeout because a chunk of packets was lost*/
			else{
				/*DATA_EOF packet was lost*/
				if(max_inorder_seq_ack==sequence_no_eof){
					send_eof(sequence_no_eof,ss , &send_addr);
				}
				/*End of file is not sent and packets need to be sent - WE DO NOT read file here as file contents 
				 * are already in send buffer by now*/
				else{
					/*File end has not been reached */

					window_first=max_inorder_seq_ack+1;

					if(eof_flag!=1){
						send_packets(send_buff,ss,&send_addr,&window_first,current_sequence_no-window_first);

					}
					/*File end has been reached and fewer packets need to be sent*/
					else{


						send_packets(send_buff,ss,&send_addr,&window_first,(sequence_no_eof-window_first+1));
					}
				}
			}
		} 	
	}
}
/*Returns an array of pointers - index 0 is filename at destination & index 1 is hostname*/
char** get_host_name(char *hostname){
	char *pch;
	char ** file_host = malloc(2*sizeof(char*));
	int i;
	for(i=0;i<2;i++)
	{
		file_host[i]=malloc(sizeof(char)*NAME_LENGTH);
		strcpy(file_host[i],"\0");
	}
	pch=strtok(hostname,"@"); /*Separates the string on @*/
	memcpy(file_host[0],pch,strlen(pch));
	pch=strtok(NULL,"@");
	memcpy(file_host[1],pch,strlen(pch));
	return file_host;
}
/*Reads bytes from file in units of SIZE. Data equivalent to 'n' packets that need to be sent is specified. The data is filled into the send buffer*/
void file_read(packet* send_buff, FILE* src_ptr, int *current_sequence_no,int *eof_flag,int no_of_packets){
	int nread; 

	/*keeps track of no of file read operations to carry out*/ 	
	int i;
	int index=0;

	for(i=0;i<no_of_packets;i++){
		index=(*current_sequence_no)%WINDOW;
		/*set sequence no,type,file data in send buffer*/
		send_buff[index].sequence_num=*current_sequence_no; 
		send_buff[index].packet_type=DATA;
		//strcpy(send_buff[index].payload,"\0");
		memset(send_buff[index].payload,'\0',SIZE);
		//strncpy(send_buff[index].payload, "", SIZE);
		nread = fread(send_buff[index].payload, 1, SIZE, src_ptr);
		(*current_sequence_no)++; /*Increment current sequence number*/
		/* fread returns a short count either at EOF or when an error occurred */
		if(nread < SIZE) {

			/* Did we reach the EOF? */
			if(feof(src_ptr)) {

				/*No of bytes read into file, so that we can NULL terminate it and not print garbage at receiver*/
				int data_len=strlen(send_buff[index].payload);
				send_buff[index].payload[data_len+1]='\0';
				i++;
				/*Set EOF flag so sender can send EOF packet*/
				*eof_flag=1;
				break;
			}
			else {
				printf("An error occurred...\n");
				exit(0);
			}
		}
	}
}

/*Routine to send packets*/
void send_packets(packet* send_buff,int ss, struct sockaddr_in *send_addr, int *window_first, int no_of_packets ){

	int i,index;
	for(i=0;i<no_of_packets;i++){

		index=(*window_first)%WINDOW;
		if(send_buff[index].packet_type!=NACK){

			sendto(ss, (char*)&send_buff[index], sizeof(packet), 0,
					(struct sockaddr *)send_addr, sizeof(*send_addr));
		}

		(*window_first)++;


	}

}

/*Function that sends an EOF packet*/
void send_eof(int sequence_no_eof,int ss, struct sockaddr_in *send_addr){

	packet *eof_packet=create_packet(DATA_EOF,sequence_no_eof,NULL);
	sendto(ss, (char*)eof_packet, sizeof(packet), 0,
			(struct sockaddr *)send_addr, sizeof(*send_addr));

}

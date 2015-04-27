#include "net_include.h"
#define BLOCK 52428800
#define CONV 1000000.0
#include <time.h>
int main()
{
	struct sockaddr_in name;
	int                s;
	fd_set             mask;
	int                recv_s[10];
	int                valid[10];  
	fd_set             dummy_mask,temp_mask;
	int                i,j,num;
	int                mess_len;
	int                neto_len;
	char               mess_buf[MAX_MESS_LEN];
	long               on=1;
	char 	       fname[80];
	int 		jj;
	FILE *dest_ptr;
	int nwritten;


	/**Statistics**/
	double total_time_taken=0;
	double total_start_time=0;
	double block_start_time=0;
	struct timeval tm;
	long bytes_count=0;
	long total_data=0;


	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s<0) {
		perror("Net_server: socket");
		exit(1);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
	{
		perror("Net_server: setsockopt error \n");
		exit(1);
	}

	name.sin_family = AF_INET;
	name.sin_addr.s_addr = INADDR_ANY;
	name.sin_port = htons(PORT);

	if ( bind( s, (struct sockaddr *)&name, sizeof(name) ) < 0 ) {
		perror("Net_server: bind");
		exit(1);
	}

	if (listen(s, 4) < 0) {
		perror("Net_server: listen");
		exit(1);
	}

	i = 0;
	FD_ZERO(&mask);
	FD_ZERO(&dummy_mask);
	FD_SET(s,&mask);
	for(;;)
	{
		temp_mask = mask;
		num = select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, NULL);
		if (num > 0) {
			if ( FD_ISSET(s,&temp_mask) ) {
				recv_s[i] = accept(s, 0, 0) ;
				FD_SET(recv_s[i], &mask);
				valid[i] = 1;
				printf("\nConnection Established...Receiving File..\n");
				i++;
			}
			for(j=0; j<i ; j++)
			{   	printf("\nEntered first for loop\n");
				fflush(stdout);
				if (valid[j])    
				if ( FD_ISSET(recv_s[j],&temp_mask) ) {
					int r = recv(recv_s[j],mess_buf,MAX_MESS_LEN,0); 
					printf("\nReceived something valid\n");
					fflush(stdout);
					if( r > 0) {

						if(valid[j] ==1){
							gettimeofday(&tm,NULL);
							total_start_time=tm.tv_sec+tm.tv_usec/CONV;
							block_start_time=total_start_time;

							memcpy(&mess_len,mess_buf,sizeof(int));
							neto_len = mess_len - sizeof(int);
							memcpy(fname,&mess_buf[sizeof(int)],neto_len);
							fname[neto_len]='\0';

							dest_ptr=fopen(fname,"w");
							printf("\nopened file for writing..\n");
							valid[j]=2;

							nwritten=fwrite(&mess_buf[neto_len+sizeof(int)],1,r-neto_len-sizeof(int),dest_ptr);

							bytes_count+=(long)nwritten;
							total_data+=(long)nwritten;


						}	
						else{
							nwritten=fwrite(mess_buf,1,r,dest_ptr);

							bytes_count+=nwritten;
							total_data+=nwritten;

							if( bytes_count >= BLOCK){

								gettimeofday(&tm,NULL);
								double time_taken = tm.tv_sec+tm.tv_usec/CONV;
								time_taken=time_taken-block_start_time;
//

								printf("\n50 MB sent in order\n");
								printf("\n Total amount of data successfully transferred so far: %lf MB \n",(total_data/(1024.0*1024.0)));
								printf("\nAverage rate of transfer: %lf",(bytes_count*8/(time_taken*1024.0*1024)));
								bytes_count=bytes_count%(BLOCK);
								block_start_time=tm.tv_sec+tm.tv_usec/CONV;
							}	        



						}
					}
					else
					{
						printf("\nFile Transfer Complete: \n",j);

						printf("\n Total amount of data successfully transferred: %lf MB \n",(total_data/(1024.0*1024.0)));

						FD_CLR(recv_s[j], &mask);
						close(recv_s[j]);
						valid[j] = 0;  
						fclose(dest_ptr);
						gettimeofday(&tm,NULL);
						double t = tm.tv_sec+tm.tv_usec/CONV;
						t=t-total_start_time;
						printf("\nTime Taken for the Transfer %lf time\n",t);
						printf("\nAverage rate of transfer: %lf Mbps",(total_data*8/(t*1024.0*1024)));
						printf("\nExiting..Adios!!\n");
						exit(0);

					}
				}
			}
		}
	}

	return 0;

}


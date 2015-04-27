#include "net_include.h"
#define NAME_LENGTH 80
#define BLOCK 52428800
#define CONV 1000000.0

char** get_host_name(char*);

int main(int argc, char *argv[]){
    struct sockaddr_in host;
    struct hostent     h_ent, *p_h_ent;

    char               *c;

    int                s;
    int                ret;
    int                mess_len;
    char               mess_buf[MAX_MESS_LEN];
    char               *neto_mess_ptr = &mess_buf[sizeof(mess_len)];
    char 	       read_buff[MAX_MESS_LEN]; 
    int 	       nread=0;


    /*Array to hold pointers to filename & hostname*/
    char** file_host;

    FILE *src_ptr;
    /**Statistics**/
        double total_time_taken=0;
        double total_start_time=0;
        double block_start_time=0;
        struct timeval time;
        long bytes_count=0;
        long total_data=0;



    if(argc<3){
                printf("\nUsage: <ncp> <source file name> <destination file name> <destination IP address>\n");
        }


    s = socket(AF_INET, SOCK_STREAM, 0); /* Create a socket (TCP) */
    if (s<0) {
        perror("Net_client: socket error");
        exit(1);
    }

    host.sin_family = AF_INET;
    host.sin_port   = htons(PORT);
    inet_pton(AF_INET, argv[3], &host.sin_addr);	
    /*Open the file to read*/
        if((src_ptr = fopen(argv[1], "r")) == NULL) {
                perror("fopen");
                exit(0);
        }
        printf("Opened %s for reading...\n", argv[1]);


    /*Get file name at destination and host name*/

//=    strncpy(file_host,argv[2],sizeof(argv[2]));
	
    	//struct in_addr addr;
	//addr.s_addr = inet_addr(file_host[3]);
	//if (addr.s_addr == INADDR_NONE)
	//{
	//	printf("\n IP error\n");
	//	exit(0);
	//}
	//p_h_ent = gethostbyaddr((char*) &addr, 4, AF_INET);
	
	//if ( p_h_ent == NULL ) {
        //printf("net_client: gethostbyname error.\n");
        //exit(1);
    //}

   // memcpy( &h_ent, p_h_ent, sizeof(h_ent) );
   // memcpy( &host.sin_addr, h_ent.h_addr_list[0],  sizeof(host.sin_addr) );

    ret = connect(s, (struct sockaddr *)&host, sizeof(host) ); /* Connect! */
    if( ret < 0)
    {
        perror( "Net_client: could not connect to server"); 
        exit(1);
    }

   

        printf("\nConnected...Sending FileName:...\n");

	gettimeofday(&time,NULL);
        total_start_time=time.tv_sec+time.tv_usec/CONV;
        block_start_time=total_start_time;


        mess_len = strlen(argv[2]) + sizeof(mess_len);
        memcpy( mess_buf, &mess_len, sizeof(mess_len));
        memcpy( &mess_buf[sizeof(mess_len)], argv[2], strlen(argv[2]));


        printf("\nConnected...Sending FileData:... \n");

		nread = fread(read_buff, 1, MAX_MESS_LEN-mess_len, src_ptr);
		bytes_count=nread;
		total_data=nread;


       		memcpy( &mess_buf[mess_len], read_buff, nread);
        	
		ret = send( s, mess_buf, nread+mess_len, 0);
	
	        if(ret != mess_len+nread) 
        		{
            			perror( "Net_client: error in writing");
            			exit(1);
        		}

		while(!feof(src_ptr)){

		nread = fread(read_buff, 1, MAX_MESS_LEN, src_ptr);
       	

		memcpy( mess_buf, read_buff, nread);
		ret = send( s, mess_buf, nread, 0);
	
		bytes_count+=nread;
		total_data+=nread;

                if( bytes_count >= BLOCK){
			
			gettimeofday(&time,NULL);
		
			double time_taken = time.tv_sec+time.tv_usec/CONV;
		        time_taken=time_taken-block_start_time;
	
			
			printf("\n50 MB sent in order in %lf time\n",time_taken);			
			printf("\n Total amount of data successfully transferred so far: %lf MB \n",(total_data/(1024.0*1024.0)));
                        printf("\nAverage rate of transfer: %lf",(bytes_count*8/(time_taken*1024.0*1024)));
                        bytes_count=bytes_count%(BLOCK);
                        block_start_time=time.tv_sec+time.tv_usec/CONV;


		} 
	        if(ret != nread) 
        		{
            			perror( "Net_client: error in writing");
            			exit(1);
        		}

	}

		printf("\nFile Transfer Successful\n");
		
		gettimeofday(&time,NULL);

                double t = time.tv_sec+time.tv_usec/CONV;
                t=t-total_start_time;
		printf("\nTime Taken for the Transfer is %lf seconds\n",t);

                printf("\n Total amount of data successfully transferred: %lf MB \n",(total_data/(1024.0*1024.0)));
                printf("\nAverage rate of transfer: %lf Mbps",(total_data*8/(t*1024.0*1024)));
        
                printf("\nExiting..Have a Good Day!!\n");
		exit(0);



    return 0;

}


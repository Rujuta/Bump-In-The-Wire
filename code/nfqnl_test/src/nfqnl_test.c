#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <errno.h>
#include <netinet/ip.h>


#include <libnetfilter_queue/libnetfilter_queue.h>

/**libnetfilter queue receives packets from the kernel nfnetlink_queue subsystem
It can issue verdicts and reinject packets into the same sub system*/
/*A short introduction of the structures used
 nfq_handle
{
	struct nfnl_handle * - this is a structure that amongst other fields has a pointer to nlmsghdr - which is the header used in net link sockets, it also consists of some flags, recv buffer size and other meta data
	struct nfnl_subsys_handle * -contains a pointer to a call back function, a pointer to nfnl_handle, call back count and other meta data
	struct nfq_q_handle * {
				struct nfq_q_handle * next - pointer to the next queue
				struct nfq_handle 
				nfq_callback* 
				void *data
				int id
		} 
}**/

void print_packet_contents(unsigned char *buffer, int size){

	struct iphdr *iph = (struct iphdr*) buffer;
	
	/*Printing ip header*/
	printf("Protocol: %d\n",(unsigned int)iph->protocol);
	printf("Identification: %d\n", ntohs(iph->id));

	/*Printing data*/
	int i;
	for(i=0; i < size; i++){//these many bytes need to be printed

		//print each hex character line by line
		printf("%x ", buffer[i] & 0xff);	
	}


}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);
	
	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
		
	ret = nfq_get_payload(tb, &data);
	//data now points to the payload
	if (ret >= 0){
		printf("payload_len=%d ", ret);
		print_packet_contents(data,ret);
	}
	fputc('\n',stdout);
	return id;
}	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        u_int32_t id = print_pkt(nfa);
	/*This is where the encryption will take place and same as print pkt, an id will be returned*/
        printf("entering callback\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	
	struct nfq_handle *nfq_h;
	struct nfq_q_handle *q_h;
	struct nfnl_handle *nfnl_h;
	int fd;
	int rv;
	char buf[4096]; // some attribute aligned thingy 
	
	/*This step opens a NFQUEUE handler*/
	nfq_h = nfq_open();
	if (!nfq_h){

		fprintf(stderr, "Error during nfq_open()\n");
		exit(1);
	}
	
	/*Unbinding existing nf_queue handler for AF_INET if any*/
	if ( nfq_unbind_pf(nfq_h,AF_INET) < 0 )
	{
		fprintf(stderr,"Error during nfq_unbind_pf()\n");
		exit(1);
	}

	/*Now will bind nfnetlink_queue as nf_handler for AF_INET*/
	if ( nfq_bind_pf(nfq_h, AF_INET) < 0 ){
		fprintf(stderr, "Error during nfq_bind_pf()\n");
		exit(1);
	}

	/*Now handler has been established*/
	/*Calling the function below, binds this program to a specific queue - the previous bind operation, just tuned the handler to listen to 	packets of type AF_INET. TODO: make this accept a generic number specified as argument*/
	printf("\nBinding this socket to queue '0'\n");
	q_h = nfq_create_queue(nfq_h, 0, &cb, NULL); 

/*this returns a pointer to the newly created queue - cb is actually a function pointer and data are the parameters it takes - they will be passed unchanged */
	if (!q_h){
		fprintf(stderr, "Error during nfq_create_queue()\n");
		exit(1);
	}	
	/*This function sets the amount of packet data that nfqueue copies to user space
	 @params: pointer to queue, part of packet we're interested in, size of packet we want to get- current setting is copy entire packet */	
	if ( nfq_set_mode(q_h, NFQNL_COPY_PACKET, 0xffff) < 0){

		fprintf(stderr,"Can't set packet_copy mode\n");
		exit(1);

	}

	/*Gets the file descriptor associated with the nfqueue handler - returns 
	a file descriptor for the netlink connection associated with the given queue connection handle.
	This descriptor is used to recv packets for processing*/
	fd = nfq_fd(nfq_h);

	/*Code to receive packets*/
	for(;;){

		if ((rv = recv(fd, buf, sizeof(buf), 0)) >=0 ){
			printf("pkt received\n");
			nfq_handle_packet(nfq_h, buf, rv);
			continue;

		}
		/*If app is too slow to digest packets sent from kernel space*/
		if (rv < 0 && errno == ENOBUFS){
			printf("\nLosing packets!\n");
			continue;
		}
		perror("Recv failed\n");
		break;
		
	}

	printf("\n Unbinding from queue - 0\n");
	nfq_destroy_queue(q_h);
        
	printf("unbinding from AF_INET\n");
        nfq_unbind_pf(nfq_h, AF_INET);
//#endif

        printf("closing library handle\n");
        nfq_close(nfq_h);

        exit(0);
	
}


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>

#define DEBUG 1
#define TCP 6
#define ICMP 1
#define UDP 17

static char KEY = (char) 0xFF; //Key for XOR

struct sockaddr_in source, dest;
FILE *log;



void calculate_ip_checksum(struct iphdr* iph){

	fprintf(log, "entered compute ip checksum\n");
	fflush(log);
	iph->check = 0;
	register unsigned long sum = 0; 
	int count = (iph->ihl)*4;//length of the IP header 
	unsigned short *ipheader = (unsigned short*) iph; // cast to unsigned short so you can sum 16 bits at a time
	while ( count > 1){

		sum += *ipheader; //add 16 bits at a time to sum 
		ipheader++;      
		count -= 2;
	}
	//the header length was odd and 1 byte still needs to be summed
	if (count == 1){
		sum += *((unsigned char*)ipheader); // CHECK if this is right
	}
	// Now add the carry 

	while ( sum >> 16){
		sum = (sum >> 16) + (sum&0xffff);
	}	
	sum = ~sum;
	iph->check = (short) sum;  	
	fprintf(log,"\nLeaving compute ip checksum, ip total len:%d\n",ntohs(iph->tot_len));
}

void calculate_tcp_checksum(struct iphdr *iph, unsigned short *ip_payload){

	fprintf(log, "entering tcp checksum\n");
	fflush(log);
	register unsigned long sum = 0;
	fprintf(log,"\nip total len:%d",ntohs(iph->tot_len));
	fflush(log);
	fprintf(log,"\n ip hdr length:%d",(iph->ihl << 2));
	fflush(stdout); 
	unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2); //length of whole packet - ip header 
	fprintf(log, "got tcp length it is :%d\n",tcp_len);
	fflush(log);

	struct tcphdr *tcph = (struct tcphdr*) ip_payload; // now extract just the tcp header portion 
	fprintf(log, "got payload\n");
	fflush(log);


	tcph->check = 0; 
	//add pseudohdr
	//the source ip 

	sum += (iph->saddr>>16) & 0xffff; // these are fields in the pseudoheader 
	sum += (iph->saddr) & 0xffff;   //
	//dest ip 
	sum += (iph->daddr >> 16) & 0xffff;	
	sum += (iph->daddr) & 0xffff;
	//protocol and reserved 6
	sum += htons(IPPROTO_TCP);
	//length
	sum += htons(tcp_len);
	// add the IP payload 

	while (tcp_len > 1){

		sum += *ip_payload++;
		tcp_len -= 2;
	}


	// if bytes left, add value of that byte as well
	if (tcp_len == 1){

		sum +=  *((unsigned char*)(ip_payload));
	}

	//now adding the carry
	while (sum >> 16){

		sum = (sum & 0xffff) + (sum >> 16);
	}

	sum = ~sum;
	tcph->check = (unsigned short) sum;
	fprintf(log, "Leaving tcp checksum\n");
	fflush(log);
}	


void calculate_udp_checksum(struct iphdr *iph, unsigned short *ip_payload){

	fprintf(log, "entering udp checksum\n");
	fflush(log);
	register unsigned long sum = 0;
	fprintf(log,"\nip total len:%d",ntohs(iph->tot_len));
	fflush(log);
	fprintf(log,"\n ip hdr length:%d",(iph->ihl << 2));
	fflush(stdout); 

	struct udphdr *udph = (struct udphdr*) ip_payload; // now extract just the tcp header portion 
	int udp_len = htons(udph->len);
	fprintf(log, "got payload\n");
	fflush(log);


	udph->check = 0; 
	//add pseudohdr
	//the source ip 

	sum += (iph->saddr>>16) & 0xffff; // these are fields in the pseudoheader 
	sum += (iph->saddr) & 0xffff;   //
	//dest ip 
	sum += (iph->daddr >> 16) & 0xffff;	
	sum += (iph->daddr) & 0xffff;
	//protocol and reserved 6
	sum += htons(IPPROTO_UDP);
	//length
	sum += udph->len;
	// add the IP payload 
	udph->check = 0; 
	fprintf(log, "\nUDP length is %d\n", udp_len);
	fflush(log);
	while (udp_len > 1){

		sum += *ip_payload++;
		udp_len -= 2;
		//fprintf(log, "udp length:%d\n",udp_len);
		//fflush(log);
	}


	// if bytes left, add value of that byte as well
	if (udp_len == 1){

		sum +=  *((unsigned char*)(ip_payload));
	}

	//now adding the carry
	while (sum >> 16){

		sum = (sum & 0xffff) + (sum >> 16);
	}

	sum = ~sum;
	if ((unsigned short) sum == 0x0000){
		fprintf(log, "\nsum is 0\n");
		fflush(log);
		sum = 0xffff;
	}
	udph->check = (unsigned short) sum;
	fprintf(log, "\nLeaving udp checksum\n");
	fflush(log);


}
/* returns packet id */
static u_int32_t xor_pkt (struct nfq_data *tb)
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
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
	}

	mark = nfq_get_nfmark(tb);

	ifi = nfq_get_indev(tb);

	ifi = nfq_get_outdev(tb);
	ifi = nfq_get_physindev(tb);

	ifi = nfq_get_physoutdev(tb);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		struct iphdr *iph = (struct iphdr*) data; //typecast  to iphdr 
		struct tcphdr *tcph;
		struct udphdr *udph;

		int iphdr_len = iph->ihl << 2; //get the total len of iphdr 
		unsigned char *ch;
		int offset; 

		unsigned short ip_checksum = iph->check;
		fprintf(log,"\n IP checksum : %04x\n",ip_checksum);
		calculate_ip_checksum(iph);
		fflush(log);
		fprintf(log,"calculated ip checksum: %04x\n",iph->check);
		fflush(log);

		if(iph->check!=ip_checksum){

			fprintf(log,"\n checksum calculation is wrong\n");
			fflush(log);
			exit(0);
		}
		unsigned char *payload_data;

		switch(iph->protocol){

			case ICMP: offset = iphdr_len +  sizeof(struct icmphdr); 
				   break;

			case IPPROTO_UDP: fprintf(log,"\nNow in UDP section\n");
					  fflush(log);
					  udph = (struct udphdr*) (data + (iph->ihl*4));
					  unsigned udp_checksum = udph->check; 
					  fprintf(log,"UDP checksum is %04x\n",udph->check);
					  fflush(log);

					  if(udph->check != udp_checksum){
						  fprintf(log, "udp checksum calculation is wrong\n");
						  fflush(log);
						  exit(1);
					  }

					  offset =  iphdr_len + sizeof(struct udphdr);
					  xor_data(ret, offset, data);
					  calculate_udp_checksum(iph,(unsigned short*)udph);
					  fprintf(log,"\nRecalculatng udp checksum\n");
					  fflush(log);

					  fprintf(log,"recalculated udp checksum: %04x\n",udph->check);	
					  fflush(log);


					  break;

			case IPPROTO_TCP:
					  fprintf(log,"\nOkay now in tcp SECTION\n");
					  fflush(log); 
					  tcph = (struct tcphdr*) (data + (iph->ihl * 4)); // CHANGE ThiS 

					  unsigned tcp_checksum = tcph->check;
					  fprintf(log, "Tcp checksum is %04x\n",tcph->check);
					  fflush(log);
					  calculate_tcp_checksum(iph,(unsigned short*)tcph);
					  fprintf(log, "Calculated Tcp checksum is %04x\n",tcph->check);
					  fflush(log);

					  if(tcph->check != tcp_checksum){
						  fprintf(log, "tcp checksum calculation is wrong\n");
						  fflush(log);
						  exit(1);
					  }
					  offset = iphdr_len + sizeof(struct tcphdr);
					  xor_data(ret, offset, data);
					  calculate_tcp_checksum(iph,(unsigned short*)tcph);
					  fprintf(log,"\nRecalculatng tcp checksum\n");
					  fflush(log);

					  fprintf(log,"recalculated tcp checksum: %04x\n",tcph->check);	
					  fflush(log);
					  break;

		}


		fprintf(log,"\nRecalculating IP checksum\n");
		fflush(log);
		calculate_ip_checksum(iph);
		fprintf(log,"recalculated ip checksum: %04x\n",iph->check);	
		fflush(log);		
	}
	return id;
}

void xor_data(int total_length, int offset, unsigned char* data){

	int payload_len = total_length - offset;
	unsigned char *ch = data + offset;
	int i;
	for(i = 0; i < payload_len; i++) {
		*ch = *ch ^ KEY; 
		ch++;
	}


}
void print_ip(struct nfq_data *tb){

	unsigned char *data;	
	int ret = nfq_get_payload(tb, &data);

	struct iphdr *iph = (struct iphdr*) data; //typecast  to iphdr 
	int iphdr_len = iph->ihl*4; //get the total len of iphdr 

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;


	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	//print source IP and destination IP
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(source.sin_addr), str, INET_ADDRSTRLEN);
	fprintf(log,"Source addr: %s\n",str);
	fflush(log);
	inet_ntop(AF_INET, &(dest.sin_addr), str, INET_ADDRSTRLEN);
	fprintf(log,"Destination addr: %s",str);

	fflush(log);
	/*Print out packet details*/
	fprintf(log,"Protocol: %d\n",(unsigned int)iph->protocol);

	fflush(log);
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
		fprintf(log,"hw_protocol=0x%04x hook=%u id=%u ",
				ntohs(ph->hw_protocol), ph->hook, id);

		fflush(log);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		fprintf(log,"hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			fprintf(log,"%02x:", hwph->hw_addr[i]);
		fprintf(log,"%02x ", hwph->hw_addr[hlen-1]);

		fflush(log);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		fprintf(log,"mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		fprintf(log,"indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		fprintf(log,"outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		fprintf(log,"physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		fprintf(log,"physoutdev=%u ", ifi);

	fflush(log);
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		fprintf(log,"payload_len=%d ", ret);
		unsigned char *ch = data;
		int gap;
		int i;
		for(i = 0; i < ret; i++) {


			fprintf(log,"%02x ", *((unsigned int*)ch) & 0xFF);
			ch++;
			/* print extra space after 8th byte for visual aid */
			if (i == 7)
				fprintf(log," ");
		}
		/* print space to handle line less than 8 bytes */
		if (ret < 8)
			fprintf(log," ");

		/* fill hex gap with spaces if not full line */
		if (ret < 16) {
			gap = 16 - ret;
			for (i = 0; i < gap; i++) {
				fprintf(log,"   ");
			}
		}

		fflush(log);
		fprintf(log,"   ");
	}

	fprintf(log,"\n");
	fputc('\n', stdout);

	return id;
}


static int cb_encrypt(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	printf("\nEntered call back\n");
	fflush(log);
	if (DEBUG) {
		fprintf(log,"entering encrypt callback\n");
		fflush(log);
		id = print_pkt(nfa);
		print_ip(nfa);
		printf(log,"\n Printing packet After XOR\n");
		fflush(log);

	}
	id = xor_pkt(nfa);
	if(DEBUG) {
		print_ip(nfa);
		print_pkt(nfa);
	}
	char *payload;
	int len = nfq_get_payload(nfa, &payload);
	if (DEBUG)
		printf(log,"\nDone with Call back\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int cb_decrypt(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	if (DEBUG) {
		fprintf(log,"entering decrypt callback\n");
		fflush(log);
		id = print_pkt(nfa);
		print_ip(nfa);
		fprintf(log,"\n Printing packet After XOR\n");
		fflush(log);

	}
	id = xor_pkt(nfa);
	if(DEBUG) {
		print_ip(nfa);
		print_pkt(nfa);
	}
	char *payload;
	int len = nfq_get_payload(nfa, &payload);
	if (DEBUG){
		fprintf(log,"\nDone with Call back\n");
		fflush(log);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void unbind_queue(struct nfq_handle *h){

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	printf("\n Done unbinding\n");
	fflush(stdout);


}

struct nfq_handle* open_queue(struct nfq_handle *h){

	h  = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open() for h_in\n");
		exit(1);
	}
	return h; 
	
}
struct nfq_q_handle* bind_queue(struct nfq_q_handle *qh,struct nfq_handle *h, int queue_num, nfq_callback *cb){
	
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue equals %d\n",queue_num);
	qh = nfq_create_queue(h,  queue_num, cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	return qh;
}

void set_packet_copy_mode(struct nfq_q_handle *qh){
	
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}



}
int main(int argc, char **argv)
{
	struct nfq_handle *h_in_lan, *h_in_wan; 
	struct nfq_q_handle *qh_in_lan, *qh_in_wan;
	struct nfnl_handle *nh;
	int fd_in_lan, fd_in_wan; 
	int rv;
	char buf_in_lan[4096] __attribute__ ((aligned));
	char buf_in_wan[4096];
	fd_set read_sd; // read set of descriptors 
	FD_ZERO(&read_sd);
	//add both descriptors to the set
	log = fopen("log.txt","w");
	if (log == NULL){
		printf("\nError opening file\n");
		exit(1);
	}
	printf("opening library handle for both incoming and outgoing queues\n");

	h_in_lan = open_queue(h_in_lan);
	h_in_wan = open_queue(h_in_wan);
	unbind_queue(h_in_lan);
	unbind_queue(h_in_wan);
	qh_in_lan = bind_queue(qh_in_lan, h_in_lan, 0, &cb_encrypt);
	qh_in_wan = bind_queue(qh_in_wan,h_in_wan,1, &cb_decrypt);
	set_packet_copy_mode(qh_in_lan);
	set_packet_copy_mode(qh_in_wan);


	fd_in_lan= nfq_fd(h_in_lan);
	fd_in_wan= nfq_fd(h_in_wan);
	int max_sd;
	if (fd_in_lan > fd_in_wan)
		max_sd = fd_in_lan;
	else
		max_sd = fd_in_wan;
		
	int num; 	
	while(1){
		
		FD_ZERO(&read_sd);
		FD_SET(fd_in_lan,&read_sd);
		FD_SET(fd_in_wan, &read_sd);
	
			
		num = select(max_sd+1, &read_sd, NULL, NULL, NULL);
		if (num > 0 ){

			if (FD_ISSET(fd_in_lan, &read_sd)){
				
				if (DEBUG){
					fprintf(log,"pkt received from LAN\n");
					fflush(log);
				}
				rv = recv(fd_in_lan, buf_in_lan, sizeof(buf_in_lan),0);
				if (rv < 0)
					printf("\nSome error in receive\n");
				fprintf(log,"Going to handle packet now");
				fflush(log);
				nfq_handle_packet(h_in_lan, buf_in_lan, rv);

			}	
			else if (FD_ISSET(fd_in_wan,&read_sd)){
				if (DEBUG){
					fprintf(log,"\n Packet received from WAN\n");
					fflush(log);
				}
				rv = recv(fd_in_wan, buf_in_wan, sizeof(buf_in_wan), 0 );
				if (rv < 0)
					printf("\n Some error in receiving packet\n");
				
				fprintf(log,"Going to handle packet now");
				nfq_handle_packet(h_in_wan, buf_in_wan, rv);
			}
		}

	}	

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh_in_lan);
	nfq_destroy_queue(qh_in_wan);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h_in_lan, AF_INET);
	nfq_unbind_pf(h_in_wan, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h_in_lan);
	nfq_close(h_in_wan);

	exit(0);
}

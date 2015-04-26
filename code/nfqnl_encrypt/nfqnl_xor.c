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

#define DEBUG 1
#define TCP 6
#define ICMP 1
#define UDP 17

static char KEY = (char) 0xFF; 

struct sockaddr_in source, dest;
FILE *log;

static unsigned short compute_checksum(unsigned short *addr, unsigned int count){
	
	fprintf(log,"entered compute checksum for ip, count = %d",count);
	fflush(log);
	register unsigned long sum = 0; 
	while (count > 1){
		fprintf(log,"count is %d",count);
		fflush(stdout);
		sum += *addr++;
		count -= 2;
	}

	if (count > 0){
		fprintf(log,"entered count>0 condition, count is %d\n",count);
		fflush(log);
		sum += ((*addr) &htons(0xFF00));
	}

	while (sum >> 16){
			
		sum = (sum & 0xffff) + (sum >> 16);
	}
	
	sum = ~sum;
	fprintf(log,"leavin compute checksum for ip\n");
	fflush(log);
	

	return ((unsigned short) sum);
	}

void compute_ip_checksum(struct iphdr* iph){
	
	fprintf(log, "entered compute ip checksum\n");
	fflush(log);
	iph->check = 0;
	iph->check = compute_checksum((unsigned short*)iph, iph->ihl << 2);
	fprintf(log,"\nLeaving compute ip checksum, ip total len:%d\n",ntohs(iph->tot_len));
}

void compute_tcp_checksum(struct iphdr *iph, unsigned short *ip_payload){

	fprintf(log, "entering tcp checksum\n");
	fflush(log);
	register unsigned long sum = 0;
	fprintf(log,"\nip total len:%d",ntohs(iph->tot_len));
	fflush(log);
	fprintf(log,"\n ip hdr length:%d",(iph->ihl << 2));
	fflush(stdout); 
	unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
	fprintf(log, "got tcp length it is :%d\n",tcp_len);
	fflush(log);
	
	struct tcphdr *tcph = (struct tcphdr*) ip_payload;
	fprintf(log, "got payload\n");
	fflush(log);
	
	//add pseudohdr
	//the source ip 

	sum += (iph->saddr>>16) & 0xFFFF;
	sum += (iph->saddr) & 0xFFFF;
	fprintf(log, "did the ANDING\n");
	fflush(log);
	
	//dest ip 

	sum += (iph->daddr >> 16) & 0xFFFF;	
	sum += (iph->daddr) & 0xFFFF;
	fprintf(log, "did ANDING of daddr\n");
	fflush(log);
	
	//protocol and reserved 6
	
	sum += htons(IPPROTO_TCP);
	fprintf(log, "stored protocol detals\n");
	fflush(log);
	
	//length
	sum += htons(tcp_len);
	fprintf(log, "put in length details\n");
	fflush(log);
	
	// add the IP payload 
	
	tcph->check = 0; 
	fprintf(log, "put tcp check = 0\n");
	fflush(log);
	int prev = tcp_len;	
	while (tcp_len > 0){
		fprintf(log, "tcp length is > 0\n");
		fflush(log);
	
		sum += *ip_payload++;
		prev = tcp_len;
		tcp_len -= 2;
		if (tcp_len > prev){
			if (tcp_len == 1){
				sum += *ip_payload++;
			}
			break;
		}
		fprintf(log, "adding to sum tcp len = %d\n",tcp_len);
		fflush(log);
	

	}
	fprintf(log, "added value of payload\n");
	fflush(log);
	
	// if any bytes left, pad bytes and add 

	if (tcp_len > 0){

		sum += ( (*ip_payload) &htons(0xFF00));
		fprintf(log, " addded payload after and\n");
	fflush(log);
	
	}

	while (sum >> 16){

		sum = (sum & 0xffff) + (sum >> 16);
		fprintf(log, "added sum\n");
	fflush(log);
	
	}

	sum = ~sum;
	tcph->check = (unsigned short) sum;
	fprintf(log, "Leaving tcp checksum\n");
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
		compute_ip_checksum(iph);
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

			case UDP: offset =  iphdr_len + sizeof(struct udphdr);
				  break;

			case IPPROTO_TCP:
				  fprintf(log,"\nOkay now in tcp SECTION\n");
				  fflush(log); 
				  tcph = (struct tcphdr*) (data + (iph->ihl << 2)); // CHANGE ThiS 
				  
				  unsigned tcp_checksum = tcph->check;
				  fprintf(log, "Tcp checksum is %04x\n",tcph->check);
				  fflush(log);
				  compute_tcp_checksum(iph,(unsigned short*)tcph);
				   fprintf(log, "Calculated Tcp checksum is %04x\n",tcph->check);
				  fflush(log);
				 
				  if(tcph->check != tcp_checksum){
						fprintf(log, "tcp checksum calculation is wrong\n");
						fflush(log);
						exit(1);
					}
				  offset = iphdr_len + sizeof(struct tcphdr);
				  break;

		}

		int payload_len = ret - offset;
		ch = data + offset;
		int i;
		for(i = 0; i < payload_len; i++) {
			*ch = *ch ^ KEY; 
			ch++;
		}

		fprintf(log,"\nRecalculatng tcp checksum\n");
		fflush(log);
	 	compute_tcp_checksum(iph,(unsigned short*)tcph);
		
		fprintf(log,"recalculated tcp checksum: %04x\n",tcph->check);	
		fprintf(log,"\nRecalculating IP checksum\n");
		fflush(log);
		compute_ip_checksum(iph);
		fprintf(log,"recalculated ip checksum: %04x\n",iph->check);	
		fflush(log);		
	}
	return id;
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


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	if (DEBUG) {
		fprintf(log,"entering callback\n");
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
	return nfq_set_verdict(qh, id, NF_ACCEPT, len, payload);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	log = fopen("log.txt","w");
	if (log == NULL){
		printf("\nError opening file\n");
		exit(1);
	}
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		if (DEBUG)
			fprintf(log,"pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

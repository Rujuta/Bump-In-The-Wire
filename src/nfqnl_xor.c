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

static char KEY = (char) 0xFF; // why is ths typecast to a char?

struct sockaddr_in source, dest;
 
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
         if (ret >= 0) {
                printf("payload_len=%d ", ret);
		struct iphdr *iph = (struct iphdr*) data; //typecast  to iphdr 
		int iphdr_len = iph->ihl*4; //get the total len of iphdr 
		//struct icmphr *icmp;
		unsigned char* ch = data+iphdr_len + sizeof(struct icmphdr);  //only modify and print data packets. 
	        //icmp = (struct icmphdr*) data;
		int payload_len = ret - iphdr_len;
		//unsigned char *ch = data;
		int gap;
		int i;
		for(i = 0; i < payload_len; i++) {
			*ch = *ch ^ KEY; 
			//printf("%02x ", *((unsigned int*)ch) & 0xFF); //why is it type cast to an unsigned int?//xored packet
			ch++;
			/* print extra space after 8th byte for visual aid */
			if (i == 7)
				printf(" ");
		}
		/* print space to handle line less than 8 bytes */
		if (payload_len < 8)
			printf(" ");
		
		/* fill hex gap with spaces if not full line */
		if (payload_len < 16) {
			gap = 16 - payload_len;
			for (i = 0; i < gap; i++) {
				printf("   ");
			}
		}
		printf("   ");
	}
 
         fputc('\n', stdout);
 
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
		printf("Source addr: %s\n",str);
		inet_ntop(AF_INET, &(dest.sin_addr), str, INET_ADDRSTRLEN);
		printf("Destination addr: %s",str);
		
		/*Print out packet details*/
		printf("Protocol: %d\n",(unsigned int)iph->protocol);
		
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
         if (ret >= 0) {
                printf("payload_len=%d ", ret);
		unsigned char *ch = data;
		int gap;
		int i;
		for(i = 0; i < ret; i++) {
			
			
			printf("%02x ", *((unsigned int*)ch) & 0xFF);
			ch++;
			/* print extra space after 8th byte for visual aid */
			if (i == 7)
				printf(" ");
		}
		/* print space to handle line less than 8 bytes */
		if (ret < 8)
			printf(" ");
		
		/* fill hex gap with spaces if not full line */
		if (ret < 16) {
			gap = 16 - ret;
			for (i = 0; i < gap; i++) {
				printf("   ");
			}
		}
		printf("   ");
	}
 
         fputc('\n', stdout);
 
         return id;
 }
         
 
 static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
               struct nfq_data *nfa, void *data)
 {
	
	 printf("entering callback\n");
         u_int32_t id = print_pkt(nfa);
	 print_ip(nfa);
	 printf("\n Printing packet After XOR\n");
         id = xor_pkt(nfa);
	 print_ip(nfa);
	 print_pkt(nfa);
	 char *payload;
	 int len = nfq_get_payload(nfa, &payload);
	 printf("\nDone with Call back\n");
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
                 printf("pkt received\n");
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

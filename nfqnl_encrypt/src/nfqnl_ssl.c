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
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define DEBUG 1
#define TCP 6
#define ICMP 1
#define UDP 17

static char KEY = (char) 0xFF; //Key for XOR

struct sockaddr_in source, dest;
FILE *log;



void calculate_ip_checksum(struct iphdr* iph) {
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
}

void calculate_tcp_checksum(struct iphdr *iph, unsigned short *ip_payload){
    register unsigned long sum = 0;
	unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2); //length of whole packet - ip header 
	struct tcphdr *tcph = (struct tcphdr*) ip_payload; // now extract just the tcp header portion 
	
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
}	


void calculate_udp_checksum(struct iphdr *iph, unsigned short *ip_payload){
    register unsigned long sum = 0;
	struct udphdr *udph = (struct udphdr*) ip_payload; // now extract just the tcp header portion 
	int udp_len = htons(udph->len);

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

	while (udp_len > 1){

		sum += *ip_payload++;
		udp_len -= 2;
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
        sum = 0xffff;
	}
	udph->check = (unsigned short) sum;
}
/*

void print_ip(struct nfq_data *tb, unsigned char * payload){

	if (payload == NULL) {
      nfq_get_payload(tb, &payload);
    }
    
	struct iphdr *iph = (struct iphdr*) payload; //typecast  to iphdr 
	int iphdr_len = iph->ihl*4; //get the total len of iphdr 

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;


	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	//print source IP and destination IP
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(source.sin_addr), str, INET_ADDRSTRLEN);
	fprintf(log,"Source addr: %s\n",str);
	inet_ntop(AF_INET, &(dest.sin_addr), str, INET_ADDRSTRLEN);
	fprintf(log,"Destination addr: %s",str);

	/*Print out packet details
	fprintf(log,"Protocol: %d\n",(unsigned int)iph->protocol);
}

/* returns packet id 
static u_int32_t print_pkt (struct nfq_data *tb, unsigned char *payload, int payload_len)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		fprintf(log,"hw_protocol=0x%04x hook=%u id=%u ",
				ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		fprintf(log,"hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			fprintf(log,"%02x:", hwph->hw_addr[i]);
		fprintf(log,"%02x ", hwph->hw_addr[hlen-1]);
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

    if (payload == NULL) {
      payload_len = nfq_get_payload(tb, &payload);
    }
	if (payload_len >= 0) {
		fprintf(log,"payload_len=%d ", payload_len);
		unsigned char *ch = payload;
		int gap;
		int i;
        fprintf(log,"\n");
		for(i = 0; i < payload_len; i++) {
			fprintf(log,"%02x ", *((unsigned int*)ch) & 0xFF);
			ch++;
			/* print extra space after 8th byte for visual aid 
			if ((i+1)%4 == 0)
				fprintf(log,"\n");
		}
	}
	fprintf(log,"\n");
	//fputc('\n', stdout);
	return id;
}
*/
int print_ip(struct iphdr *iph){ 
    int iphdr_len = iph->ihl << 2; //get the total len of iphdr 

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;


    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    fprintf(log, "IP Header\n");
    fprintf(log,"\n Header length:%d",iphdr_len);
    //print source IP and destination IP
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(source.sin_addr), str, INET_ADDRSTRLEN);
    fprintf(log,"Source addr: %s\n",str);
    inet_ntop(AF_INET, &(dest.sin_addr), str, INET_ADDRSTRLEN);
    fprintf(log,"Destination addr: %s\n",str);

    /*Print out packet details*/
    fprintf(log,"Protocol: %d\n",(unsigned int)iph->protocol);
    return iphdr_len;
}

int print_tcp_hdr(struct tcphdr *tp) {
    u_short sport, dport, win, urp, checksum,len;
    u_int32_t seq, ack;

    sport = ntohs(tp->source);
    dport = ntohs(tp->dest);
    seq = ntohl(tp->seq);
    ack = ntohl(tp->ack_seq);
    win = ntohs(tp->window);
    urp = ntohs(tp->urg_ptr);
    checksum = ntohs(tp->check);
    len = ntohs(tp->doff);
    len = ((len >> 8)&0xFF)<<2;

    fprintf(log, "TCP header:\n");
    fprintf(log, "source port: %u, ", sport);
    fprintf(log, "dest port: %u, ", dport);
    fprintf(log, "seq num: %u, ", seq);
    fprintf(log, "ack num: %u, ", ack);
    fprintf(log, "Header size: %d bytes, ", len);
    fprintf(log, "checksum (hex): %04x\n", checksum);
    return len;
}

int print_udp_hdr(struct udphdr *up) {
    u_short sport, dport,checksum,len;

    sport = ntohs(up->source);
    dport = ntohs(up->dest);
    checksum = ntohs(up->check);
    len = ntohs(up->len);

    fprintf(log, "UDP header:\n");
    fprintf(log, "source port: %u, ", sport);
    fprintf(log, "dest port: %u, ", dport);
    fprintf(log, "Datagram size: %d bytes, ", len);
    fprintf(log, "checksum (hex): %04x\n", checksum);
    return sizeof(struct udphdr);
}


int print_icmp_hdr(struct icmphdr *ih) {
    fprintf(log, "ICMP Header:\n");
    return sizeof(struct icmphdr);
}

static void print_pkt_complete(struct nfq_data *tb, unsigned char *payload, int payload_len) {
    /* Internal info/hw info/device info/etc.*/
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        int id = ntohl(ph->packet_id);
        fprintf(log,"hw_protocol=0x%04x hook=%u id=%u ",
                ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        fprintf(log,"hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            fprintf(log,"%02x:", hwph->hw_addr[i]);
        fprintf(log,"%02x ", hwph->hw_addr[hlen-1]);
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

    if (payload == NULL) {
      payload_len = nfq_get_payload(tb, &payload);
    }
    
    unsigned char * payload_ptr = payload;
    int offset = 0;
    /*Print IP Header */
    offset += print_ip((struct iphdr *)payload);
    payload_ptr += offset;
    /* Print protocol header.*/
    switch(((struct iphdr *)payload)->protocol) {
      case IPPROTO_ICMP:
        offset += print_icmp_hdr((struct icmphdr *)payload_ptr);
        break;
      case IPPROTO_TCP:
        offset += print_tcp_hdr((struct tcphdr *)payload_ptr);
        break;
      case IPPROTO_UDP:
        offset += print_udp_hdr((struct udphdr *)payload_ptr);
        break;  
    }
    payload_ptr = payload + offset;

    if (payload_len-offset >= 0) {
        fprintf(log,"payload_len=%d ", payload_len);
        unsigned char *ch = payload_ptr;
        int gap;
        int i;
        fprintf(log,"\n");
        for(i = 0; i < payload_len-offset; i++) {
            fprintf(log,"%02x ", *((unsigned int*)ch) & 0xFF);
            ch++;
            /* print extra space after 8th byte for visual aid */
            if ((i+1)%4 == 0)
                fprintf(log,"\n");
        }
    }
    fprintf(log,"\n");
    //fputc('\n', stdout);
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

static int get_packet_id(struct nfq_data *tb) {
    int id = -1;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    return id;
}


static int encrypt_data(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext) {

  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

static int encrypt_calc_checksum(struct nfq_data *tb, unsigned char *key, unsigned char *iv,
        unsigned char *buffer) {
  unsigned char *payload;
  unsigned char *ciphertext;
  int ciphertext_len = -1;
  int payload_len = nfq_get_payload(tb, &payload);
  if (payload_len >= 0) {
    struct iphdr *iph = (struct iphdr*) payload; //typecast  to iphdr 
    struct tcphdr *tcph;
    struct udphdr *udph;

    int iphdr_len = iph->ihl << 2; //get the total len of iphdr 
    unsigned char *ch;
    int offset; 

    unsigned short ip_checksum = iph->check;
    calculate_ip_checksum(iph);
    if(iph->check!=ip_checksum){
        fprintf(stderr,"\n checksum calculation is wrong\n");
        exit(1);
    }
    
    switch(iph->protocol){

        case ICMP: 
                  offset = iphdr_len +  sizeof(struct icmphdr);
                  ciphertext = buffer+offset;
                  ciphertext_len = encrypt_data(payload+offset, payload_len-offset,key, iv,ciphertext);
                  if (ciphertext_len >= 0) {
                     /* Set new length in IP header */
                     memcpy(buffer, payload, offset);
                     iph = (struct iphdr*) buffer; //typecast  to iphdr 
                     iph->tot_len = htons(ciphertext_len+offset);
                  }
               break;

        case IPPROTO_UDP: 
                  udph = (struct udphdr*) (payload + iphdr_len);
                  unsigned udp_checksum = udph->check; 
                  
                  calculate_udp_checksum(iph,(unsigned short*)udph);
                  
                  if(udph->check != udp_checksum){
                      fprintf(stderr, "udp checksum calculation is wrong\n");
                      exit(1);
                  }

                  offset =  iphdr_len + sizeof(struct udphdr);
                  ciphertext = buffer+offset;
                  ciphertext_len = encrypt_data(payload+offset, payload_len-offset,key, iv,ciphertext);
                  if (ciphertext_len >= 0) {
                    /* Set new length in IP header */
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    udph = (struct udphdr*) (buffer + iphdr_len); // CHANGE ThiS
                    udph->len = htons(ciphertext_len+sizeof(struct udphdr));
                    iph->tot_len = htons(ciphertext_len+offset);
                    calculate_udp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  break;
        case IPPROTO_TCP:
                  tcph = (struct tcphdr*) (payload + iphdr_len); // CHANGE ThiS 

                  unsigned tcp_checksum = tcph->check;
                  calculate_tcp_checksum(iph,(unsigned short*)tcph);
                  if(tcph->check != tcp_checksum){
                      fprintf(stderr, "tcp checksum calculation is wrong\n");
                      exit(1);
                  }
                  offset = iphdr_len + sizeof(struct tcphdr);
                  ciphertext = buffer+offset;
                  ciphertext_len = encrypt_data(payload+offset, payload_len-offset,key, iv,ciphertext);
                  if (ciphertext_len >= 0) {
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    tcph = (struct tcphdr*) (buffer + iphdr_len); // CHANGE ThiS 
                    /* Set new length in IP header */
                    iph->tot_len = htons(ciphertext_len+offset);
                    calculate_tcp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  break;
    }
    /* Recalcuate ip header Checksum*/
    calculate_ip_checksum(iph);
    payload_len = ciphertext_len + offset;
  }

  return payload_len;
}

static int cb_encrypt(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	u_int32_t id = get_packet_id(nfa);
	if (DEBUG) {
        fprintf(log,"\n Printing packet before encrypt\n");
        /*print_ip(nfa, NULL);
		print_pkt(nfa, NULL, 0);*/
        print_pkt_complete(nfa, NULL, 0);
	}
	int newpayload_len = 4096;
	unsigned char newpayload[newpayload_len];
    unsigned char * final_payload = newpayload;

    /* Set up the key and iv. Do I need to say to not hard code these in a
    * real application? :-)
    */

    /* A 256 bit key */
    unsigned char *key = "01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = "01234567890123456";


    /* Encrypt the plaintext */
    newpayload_len = encrypt_calc_checksum(nfa, key, iv, newpayload);   
    
    
    if (newpayload_len < 0) {
        if (DEBUG) {
          fprintf(log,"\n encryption appears to have failed. Sending as plaintext \n");
        }
        newpayload_len = nfq_get_payload(nfa,&final_payload);
    }
    
    if(DEBUG) {
        fprintf(log,"\n Printing packet after encrypt\n");
        /*print_ip(nfa, final_payload);
        print_pkt(nfa, final_payload, newpayload_len);*/
        print_pkt_complete(nfa, final_payload, newpayload_len);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, newpayload_len, final_payload);
}


static int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {

  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  
  return plaintext_len;
}

/* TODO: It really isn't safe to not provide the size of the buffer, 
 * but we are going to just assume it's big enough for now */
static int decrypt_calc_checksum(struct nfq_data *tb, unsigned char *key, unsigned char *iv,
        unsigned char *buffer) {
  unsigned char *plaintext;
  unsigned char *payload;
  int plaintext_len = -1;
  int payload_len = nfq_get_payload(tb, &payload);
  if (payload_len >= 0) {
    struct iphdr *iph = (struct iphdr*) payload; //typecast  to iphdr 
    struct tcphdr *tcph;
    struct udphdr *udph;

    int iphdr_len = iph->ihl << 2; //get the total len of iphdr 
    unsigned char *ch;
    int offset; 

    unsigned short ip_checksum = iph->check;
    calculate_ip_checksum(iph);
    if(iph->check!=ip_checksum){

        fprintf(stderr,"\n checksum calculation is wrong\n");
        exit(1);
    }
    
    switch(iph->protocol){

        case ICMP: 
                  offset = iphdr_len +  sizeof(struct icmphdr);
                  plaintext = buffer+offset;
                  plaintext_len = decrypt_data(payload+offset, payload_len-offset,key, iv,plaintext);
                  if (plaintext_len >= 0) {
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    /* Set new length in IP header */
                    iph->tot_len = htons(plaintext_len+offset);
                  }
               break;

        case IPPROTO_UDP: 
                  udph = (struct udphdr*) (payload + iphdr_len);
                  unsigned udp_checksum = udph->check; 
                  
                  calculate_udp_checksum(iph,(unsigned short*)udph);
                  
                  if(udph->check != udp_checksum){
                      fprintf(stderr, "udp checksum calculation is wrong\n");
                      exit(1);
                  }

                  offset = iphdr_len + sizeof(struct udphdr);
                  plaintext = buffer+offset;
                  plaintext_len = decrypt_data(payload+offset, payload_len-offset,key, iv,plaintext);
                  if (plaintext_len >= 0) {
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    udph = (struct udphdr*) (buffer + iphdr_len); // CHANGE ThiS 
                    udph->len = htons(plaintext_len+sizeof(struct udphdr));
                    /* Set new length in IP header */
                    iph->tot_len = htons(plaintext_len+offset);
                    calculate_udp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  break;

        case IPPROTO_TCP:
                  tcph = (struct tcphdr*) (payload + iphdr_len); // CHANGE ThiS 

                  unsigned tcp_checksum = tcph->check;
                  calculate_tcp_checksum(iph,(unsigned short*)tcph);
                  if(tcph->check != tcp_checksum){
                      fprintf(stderr, "tcp checksum calculation is wrong\n");
                      exit(1);
                  }
                  offset = iphdr_len + sizeof(struct tcphdr);
                  plaintext = buffer+offset;
                  plaintext_len = decrypt_data(payload+offset, payload_len-offset,key, iv,plaintext);
                  if (plaintext_len >= 0) {
                    memcpy(buffer,payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    tcph = (struct tcphdr*) (buffer + iphdr_len); // CHANGE ThiS 
                    /* Set new length in IP header */
                    iph->tot_len = htons(plaintext_len+offset);
                    calculate_tcp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  break;
    }     
    calculate_ip_checksum(iph);
    payload_len = plaintext_len+offset;
  }

  return payload_len;
}
static int cb_decrypt(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    u_int32_t id = get_packet_id(nfa);
    if (DEBUG) {
        fprintf(log,"\n Printing packet Before Decryption\n");
       /* print_ip(nfa, NULL);
        print_pkt(nfa, NULL, 0);*/
        print_pkt_complete(nfa, NULL, 0);
    }
    
    int newpayload_len = 4096;
    unsigned char newpayload[newpayload_len];
    unsigned char * final_payload = newpayload;
    
    /* Set up the key and iv. Do I need to say to not hard code these in a
    * real application? :-)
    */

    /* A 256 bit key */
    unsigned char *key = "01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = "01234567890123456";

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */


    /* Encrypt the plaintext */
    newpayload_len = decrypt_calc_checksum(nfa, key, iv, newpayload);   
   

    if (newpayload_len < 0) {
      if (DEBUG) {
          fprintf(log,"\n It seems that decryption failed. Passing along encrypted packet. \n");
      }
      newpayload_len = nfq_get_payload(nfa,&final_payload);
    }
    
    if(DEBUG) {
        fprintf(log,"\n Printing packet after decrypt\n");
       /* print_ip(nfa, final_payload);
        print_pkt(nfa, final_payload, newpayload_len);*/
        print_pkt_complete(nfa, final_payload, newpayload_len);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, newpayload_len, final_payload);
}

void unbind_queue(struct nfq_handle *h){
    if (DEBUG) {
      fprintf(log, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    }
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
}

struct nfq_handle* open_queue(){

	struct nfq_handle *h  = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	return h; 
}
struct nfq_q_handle* bind_queue(struct nfq_handle *h, int queue_num, nfq_callback *cb){
	if (DEBUG)
      fprintf(log, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
    struct nfq_q_handle *qh;
    if (DEBUG)
      fprintf(log, "binding this socket to queue equals %d\n",queue_num);
	qh = nfq_create_queue(h,  queue_num, cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	return qh;
}

void set_packet_copy_mode(struct nfq_q_handle *qh){
	if (DEBUG)
      fprintf(log, "setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
}
int main(int argc, char **argv)
{
	struct nfq_handle *h_in_lan, *h_in_wan; 
	struct nfq_q_handle *qh_in_lan, *qh_in_wan;
	int fd_in_lan, fd_in_wan; 
	int rv_lan, rv_wan;
	char buf_in_lan[4096] __attribute__ ((aligned));
	char buf_in_wan[4096];
	fd_set read_sd; // read set of descriptors
    fd_set temp_mask, dummy_mask; 
	FD_ZERO(&read_sd);
    FD_ZERO(&dummy_mask);
	//add both descriptors to the set
	log = fopen("log.txt","w");
	if (log == NULL){
		fprintf(stderr, "\nError opening file\n");
		exit(1);
	}
	if (DEBUG)
      fprintf(log, "opening library handle for both incoming and outgoing queues\n");

	h_in_lan = open_queue();
	unbind_queue(h_in_lan);
	qh_in_lan = bind_queue(h_in_lan, 0, &cb_encrypt);
    set_packet_copy_mode(qh_in_lan);
	fd_in_lan= nfq_fd(h_in_lan);

	h_in_wan = open_queue();
	unbind_queue(h_in_wan);
	qh_in_wan = bind_queue(h_in_wan,1, &cb_decrypt);
	set_packet_copy_mode(qh_in_wan);
	fd_in_wan= nfq_fd(h_in_wan);

	int max_sd;
	if (fd_in_lan > fd_in_wan)
		max_sd = fd_in_lan;
	else
		max_sd = fd_in_wan;
		
    FD_SET(fd_in_lan,&read_sd);
    FD_SET(fd_in_wan,&read_sd);
    
    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
	int num; 	
	while(1){
        rv_lan = -1;
        rv_wan = -1;
        temp_mask = read_sd;		
		num = select(max_sd+1, &temp_mask, &dummy_mask, &dummy_mask, NULL);
		if (num > 0 ) {
			if (FD_ISSET(fd_in_lan, &temp_mask)){
				if (DEBUG){
					fprintf(log,"pkt received from LAN\n");
				}
				rv_lan = recv(fd_in_lan, buf_in_lan, sizeof(buf_in_lan),0);
				if (rv_lan < 0) {
					fprintf(log, "\nSome error in receiving LAN packet\n");
                    /* Call some sort of "clean up and exit" fxn. Or Maybe use a goto?*/                
                }

			}	
            /* Changed from "else if," is this necessary? */
			if (FD_ISSET(fd_in_wan,&temp_mask)) {
				if (DEBUG){
					fprintf(log,"\n Packet received from WAN\n");
				}
				rv_wan = recv(fd_in_wan, buf_in_wan, sizeof(buf_in_wan), 0 );
				if (rv_wan < 0)
					fprintf(log, "\n Some error in receiving WAN packet\n");
			}
			if (rv_lan >= 0) {
              nfq_handle_packet(h_in_lan, buf_in_lan, rv_lan);
            }
            if (rv_wan >= 0) {
              nfq_handle_packet(h_in_wan, buf_in_wan, rv_wan);
            }
            if (DEBUG) {
              /* flush log after handling packets to better ensure debug prints written to log. */
              fflush(log);
            }
		}
	}	
    if (DEBUG)
      fprintf(log, "unbinding from queues\n");
	nfq_destroy_queue(qh_in_lan);
	nfq_destroy_queue(qh_in_wan);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
    if (DEBUG)
      fprintf(log, "unbinding from AF_INET\n");
	nfq_unbind_pf(h_in_lan, AF_INET);
	nfq_unbind_pf(h_in_wan, AF_INET);
#endif
    if (DEBUG)
      fprintf(log, "closing library handle\n");
	nfq_close(h_in_lan);
	nfq_close(h_in_wan);
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings(); 

	exit(0);
}

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

#define DEBUG 0
#define TCP 6
#define ICMP 1
#define UDP 17

static char KEY = (char) 0xFF; //Key for XOR

struct sockaddr_in source, dest;
FILE *log;



void calculate_ip_checksum(struct iphdr* iph) {
    if (DEBUG) {
      fprintf(log, "entered compute ip checksum\n");
      fflush(log);
    }
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
    if (DEBUG) {
      fprintf(log,"\nLeaving compute ip checksum, ip total len:%d\n",ntohs(iph->tot_len));
    }
}

void calculate_tcp_checksum(struct iphdr *iph, unsigned short *ip_payload){
    if (DEBUG) {
      fprintf(log, "entering tcp checksum\n");
      fflush(log);
    }
    register unsigned long sum = 0;
	if (DEBUG) {
      fprintf(log,"\nip total len:%d",ntohs(iph->tot_len));
      fflush(log);
      fprintf(log,"\n ip hdr length:%d",(iph->ihl << 2));
      fflush(log); 
    }
	unsigned short tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2); //length of whole packet - ip header 
    if (DEBUG) {
      fprintf(log, "got tcp length it is :%d\n",tcp_len);
      fflush(log);
    }
      
	struct tcphdr *tcph = (struct tcphdr*) ip_payload; // now extract just the tcp header portion 
	if (DEBUG) {
      fprintf(log, "got payload\n");
      fflush(log);
    }


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
    if (DEBUG) {
      fprintf(log, "Leaving tcp checksum\n");
      fflush(log);
    }
}	


void calculate_udp_checksum(struct iphdr *iph, unsigned short *ip_payload){
    if (DEBUG) {
      fprintf(log, "entering udp checksum\n");
      fflush(log);
    }
    register unsigned long sum = 0;
    if (DEBUG) {
      fprintf(log,"\nip total len:%d",ntohs(iph->tot_len));
      fflush(log);
      fprintf(log,"\n ip hdr length:%d",(iph->ihl << 2));
      fflush(log); 
    }
	struct udphdr *udph = (struct udphdr*) ip_payload; // now extract just the tcp header portion 
	int udp_len = htons(udph->len);
	if (DEBUG) {
      fprintf(log, "got payload\n");
      fflush(log);
    }

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
    if (DEBUG) {
      fprintf(log, "\nUDP length is %d\n", udp_len);
      fflush(log);
    }
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
        if (DEBUG) {
          fprintf(log, "\nsum is 0\n");
          fflush(log);
        }
        sum = 0xffff;
	}
	udph->check = (unsigned short) sum;
    if (DEBUG) {
      fprintf(log, "\nLeaving udp checksum\n");
      fflush(log);
    }

}


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
	fflush(log);
	inet_ntop(AF_INET, &(dest.sin_addr), str, INET_ADDRSTRLEN);
	fprintf(log,"Destination addr: %s",str);

	fflush(log);
	/*Print out packet details*/
	fprintf(log,"Protocol: %d\n",(unsigned int)iph->protocol);

	fflush(log);
}

/* returns packet id */
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
			/* print extra space after 8th byte for visual aid */
			if ((i+1)%4 == 0)
				fprintf(log,"\n");
		}

		fflush(log);
		fprintf(log,"   ");
	}

	fprintf(log,"\n");
	fputc('\n', stdout);

	return id;
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
    if (DEBUG) {
      fprintf(log,"\n IP checksum : %04x\n",ip_checksum);
      fflush(log);
    }
    calculate_ip_checksum(iph);
    if (DEBUG) {
      fprintf(log,"calculated ip checksum: %04x\n",iph->check);
      fflush(log);
    }
    if(iph->check!=ip_checksum){
        fprintf(log,"\n checksum calculation is wrong\n");
        fflush(log);
        exit(1);
    }
    
    switch(iph->protocol){

        case ICMP: offset = iphdr_len +  sizeof(struct icmphdr);
                   ciphertext_len = payload_len-offset;
                   return -1;
               break;

        case IPPROTO_UDP: 
                  if (DEBUG) {
                    fprintf(log,"\nNow in UDP section\n");
                    fflush(log);
                  }
                  udph = (struct udphdr*) (payload + iphdr_len);
                  unsigned udp_checksum = udph->check; 
                  if (DEBUG) {
                    fprintf(log,"UDP checksum is %04x\n",udph->check);
                    fflush(log);
                  }
                  if(udph->check != udp_checksum){
                      fprintf(log, "udp checksum calculation is wrong\n");
                      fflush(log);
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
                    iph->tot_len = htons(ciphertext_len+offset);
                    calculate_udp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  if (DEBUG) {
                    fprintf(log,"\nRecalculatng udp checksum\n");
                    fflush(log);

                    fprintf(log,"recalculated udp checksum: %04x\n",udph->check); 
                    fflush(log);
                  }
                  break;

        case IPPROTO_TCP:
                  if (DEBUG) {
                    fprintf(log,"\nOkay now in tcp SECTION\n");
                    fflush(log); 
                  }
                  tcph = (struct tcphdr*) (payload + iphdr_len); // CHANGE ThiS 

                  unsigned tcp_checksum = tcph->check;
                  if (DEBUG) {
                    fprintf(log, "Tcp checksum is %04x\n",tcph->check);
                    fflush(log);
                  }
                  calculate_tcp_checksum(iph,(unsigned short*)tcph);
                  if (DEBUG) {
                    fprintf(log, "Calculated Tcp checksum is %04x\n",tcph->check);
                    fflush(log);
                  }
                  if(tcph->check != tcp_checksum){
                      fprintf(log, "tcp checksum calculation is wrong\n");
                      fflush(log);
                      exit(1);
                  }
                  offset = iphdr_len + sizeof(struct tcphdr);
                  ciphertext = buffer+offset;
                  ciphertext_len = encrypt_data(payload+offset, payload_len-offset,key, iv,ciphertext);
                  if (ciphertext_len >= 0) {
                    if (DEBUG) {
                      fprintf(log, "\nciphertext_len in hex is %04x\n", (unsigned short)ciphertext_len);
                      fflush(log);
                    }
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    tcph = (struct tcphdr*) (buffer + iphdr_len); // CHANGE ThiS 
                    /* Set new length in IP header */
                    iph->tot_len = htons(ciphertext_len+offset);
                    calculate_tcp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  if (DEBUG) {
                    fprintf(log,"\nRecalculatng tcp checksum\n");
                    fflush(log);

                    fprintf(log,"recalculated tcp checksum: %04x\n",tcph->check); 
                    fflush(log);
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
		fprintf(log,"entering encrypt callback\n");
        fprintf(log,"\n Printing packet before encrypt\n");
		fflush(log);
        print_ip(nfa, NULL);
		print_pkt(nfa, NULL, 0);
		fflush(log);

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

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Encrypt the plaintext */
    newpayload_len = encrypt_calc_checksum(nfa, key, iv, newpayload);   
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    
    if (newpayload_len < 0) {
        if (DEBUG) {
          fprintf(log,"\n ENCRYPTION FAILED \n");
          fflush(log);
        }
        newpayload_len = nfq_get_payload(nfa,&final_payload);
    }
    
    if(DEBUG) {
        fprintf(log,"\n Printing packet after encrypt\n");
        print_ip(nfa, final_payload);
        print_pkt(nfa, final_payload, newpayload_len);
        fprintf(log,"\nDone with Call back\n");
        fflush(log);
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
    if (DEBUG) {
      fprintf(log,"\n IP checksum : %04x\n",ip_checksum);
      fflush(log);
    }
    calculate_ip_checksum(iph);
    if (DEBUG) {
      fprintf(log,"calculated ip checksum: %04x\n",iph->check);
      fflush(log);
    }
    if(iph->check!=ip_checksum){

        fprintf(log,"\n checksum calculation is wrong\n");
        fflush(log);
        exit(1);
    }
    
    switch(iph->protocol){

        case ICMP: offset = iphdr_len +  sizeof(struct icmphdr);
                   plaintext_len = payload_len-offset;
                   return -1;
               break;

        case IPPROTO_UDP: 
                  if (DEBUG) {
                    fprintf(log,"\nNow in UDP section\n");
                    fflush(log);
                  }
                  udph = (struct udphdr*) (payload + iphdr_len);
                  unsigned udp_checksum = udph->check; 
                  if (DEBUG) {
                    fprintf(log,"UDP checksum is %04x\n",udph->check);
                    fflush(log);
                  }
                  if(udph->check != udp_checksum){
                      fprintf(log, "udp checksum calculation is wrong\n");
                      fflush(log);
                      exit(1);
                  }

                  offset = iphdr_len + sizeof(struct udphdr);
                  plaintext = buffer+offset;
                  plaintext_len = decrypt_data(payload+offset, payload_len-offset,key, iv,plaintext);
                  if (plaintext_len >= 0) {
                    memcpy(buffer, payload, offset);
                    iph = (struct iphdr*) buffer; //typecast  to iphdr 
                    udph = (struct udphdr*) (buffer + iphdr_len); // CHANGE ThiS 
                    /* Set new length in IP header */
                    iph->tot_len = htons(plaintext_len+offset);
                    calculate_udp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  if (DEBUG) {
                    fprintf(log,"\nRecalculatng udp checksum\n");
                    fflush(log);

                    fprintf(log,"recalculated udp checksum: %04x\n",udph->check); 
                    fflush(log);
                  }
                  break;

        case IPPROTO_TCP:
                  if (DEBUG) {
                    fprintf(log,"\nOkay now in tcp SECTION\n");
                    fflush(log); 
                  }
                  tcph = (struct tcphdr*) (payload + iphdr_len); // CHANGE ThiS 

                  unsigned tcp_checksum = tcph->check;
                  if (DEBUG) {
                    fprintf(log, "Tcp checksum is %04x\n",tcph->check);
                    fflush(log);
                  }
                  calculate_tcp_checksum(iph,(unsigned short*)tcph);
                  if (DEBUG) {
                    fprintf(log, "Calculated Tcp checksum is %04x\n",tcph->check);
                    fflush(log);
                  }
                  if(tcph->check != tcp_checksum){
                      fprintf(log, "tcp checksum calculation is wrong\n");
                      fflush(log);
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
                    if (DEBUG) {
                      fprintf(log, "\nplaintext_len in hex is %04x\n", (unsigned short)plaintext_len);
                      fflush(log);
                    }
                    iph->tot_len = htons(plaintext_len+offset);
                    calculate_tcp_checksum(iph,(unsigned short*)(buffer+iphdr_len));
                  }
                  if (DEBUG) {
                    fprintf(log,"\nRecalculatng tcp checksum\n");
                    fflush(log);

                    fprintf(log,"recalculated tcp checksum: %04x\n",tcph->check); 
                    fflush(log);
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
        fprintf(log,"entering decrypt callback\n");
        fprintf(log,"\n Printing packet Before Decryption\n");
        fflush(log);
        print_ip(nfa, NULL);
        print_pkt(nfa, NULL, 0);
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


    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    /* Encrypt the plaintext */
    newpayload_len = decrypt_calc_checksum(nfa, key, iv, newpayload);   
    
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings(); 

    if (newpayload_len < 0) {
      if (DEBUG) {
          fprintf(log,"\n DECRYPTION FAILED \n");
          fflush(log);
      }
      newpayload_len = nfq_get_payload(nfa,&final_payload);
    }
    
    if(DEBUG) {
        fprintf(log,"\n Printing packet after decrypt\n");
        print_ip(nfa, final_payload);
        print_pkt(nfa, final_payload, newpayload_len);
        fprintf(log,"\nDone with Call back\n");
        fflush(log);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, newpayload_len, final_payload);
}

void unbind_queue(struct nfq_handle *h){
    if (DEBUG) {
      printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    }
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	if (DEBUG) {
      printf("\n Done unbinding\n");
      fflush(stdout);
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
      printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
    struct nfq_q_handle *qh;
    if (DEBUG)
      printf("binding this socket to queue equals %d\n",queue_num);
	qh = nfq_create_queue(h,  queue_num, cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}
	return qh;
}

void set_packet_copy_mode(struct nfq_q_handle *qh){
	if (DEBUG)
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
	int fd_in_lan, fd_in_wan; 
	int rv;
	char buf_in_lan[4096] __attribute__ ((aligned));
	char buf_in_wan[4096];
	fd_set read_sd; // read set of descriptors
    fd_set temp_mask, dummy_mask; 
	FD_ZERO(&read_sd);
    FD_ZERO(&dummy_mask);
	//add both descriptors to the set
	log = fopen("log.txt","w");
	if (log == NULL){
		printf("\nError opening file\n");
		exit(1);
	}
	if (DEBUG)
      printf("opening library handle for both incoming and outgoing queues\n");

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
	int num; 	
	while(1){
        temp_mask = read_sd;		
		num = select(max_sd+1, &temp_mask, &dummy_mask, &dummy_mask, NULL);
		if (num > 0 ){
			if (FD_ISSET(fd_in_lan, &temp_mask)){
				if (DEBUG){
					fprintf(log,"pkt received from LAN\n");
					fflush(log);
				}
				rv = recv(fd_in_lan, buf_in_lan, sizeof(buf_in_lan),0);
				if (rv < 0) {
					printf("\nSome error in receive\n");
                    /* Call some sort of "clean up and exit" fxn. Or Maybe use a goto?*/                
                }
                if (DEBUG) {
                  fprintf(log,"Going to handle packet now");
                  fflush(log);
                }
				nfq_handle_packet(h_in_lan, buf_in_lan, rv);

			}	
            /* Changed from "else if," is this necessary? */
			if (FD_ISSET(fd_in_wan,&temp_mask)) {
				if (DEBUG){
					fprintf(log,"\n Packet received from WAN\n");
					fflush(log);
				}
				rv = recv(fd_in_wan, buf_in_wan, sizeof(buf_in_wan), 0 );
				if (rv < 0)
					printf("\n Some error in receiving packet\n");
				if (DEBUG) {
                  fprintf(log,"Going to handle packet now");
                  fflush(log);
                }
				nfq_handle_packet(h_in_wan, buf_in_wan, rv);
			}
		}

	}	
    if (DEBUG)
      printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh_in_lan);
	nfq_destroy_queue(qh_in_wan);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
    if (DEBUG)
      printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h_in_lan, AF_INET);
	nfq_unbind_pf(h_in_wan, AF_INET);
#endif
    if (DEBUG)
      printf("closing library handle\n");
	nfq_close(h_in_lan);
	nfq_close(h_in_wan);

	exit(0);
}

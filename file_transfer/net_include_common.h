#define WINDOW 400
#define SIZE 1392
#define RECV_TIMEOUT 0
#define SEND_TIMEOUT 0
#define ACK_WINDOW 20
#define RECV_U_TIMEOUT 1000
#define SEND_U_TIMEOUT 250000
#define BLOCK_SIZE  52428800
#define TIME_CONV 1000000.0
typedef enum {ACK=0,NACK, DATA, SEND_REQ, SEND_COMMAND, BUSY, ACTIVATE, DATA_EOF, TRANS_COMPLETE} type;

typedef struct packet {

int sequence_num;
char payload[SIZE];
type packet_type;
}packet;


packet* create_packet(type,int,char*);


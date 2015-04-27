#include "queue.h"
#include "net_include_common.h"

node* get_node(int sender_ip){

	node *q_node;
	q_node=(node*)malloc(sizeof(node));
	q_node->client_ip=sender_ip;
	q_node->next=NULL;
	return q_node;
}

queue* get_queue(){

	queue *ip_queue;
	ip_queue= (queue*)malloc(sizeof(queue));
	ip_queue->front=NULL;
	ip_queue->rear=NULL;
	return ip_queue;
}

int dequeue(queue *ip_queue){

	node* ip_front;
	int ip;
	ip_front=ip_queue->front;
	ip=ip_front->client_ip;
	ip_queue->front=ip_queue->front->next;
	free(ip_front);
	return ip;
}

void enqueue(queue *ip_queue,int data){

	node *temp;
	printf("\n IN enqueue, enqueuing \n");
	print_ip(data);
	if(is_empty(ip_queue)==1){
		temp=get_node(data);
		ip_queue->front=temp;
		ip_queue->rear=temp;
	}
	else{
		ip_queue->rear->next=get_node(data);
		ip_queue->rear=ip_queue->rear->next;
	}
}


int is_empty(queue *ip_queue){

	if (ip_queue->front!=NULL && ip_queue->rear!=NULL)
		return 0;
	else
		return 1;

}

void print_queue(queue *ip_queue){
	node *temp;
	temp=ip_queue->front;
	printf("\nPrinting QUEUE\n:");
	while(temp!=NULL){
		
		printf("%d",temp->client_ip);
		temp=temp->next;
	}
//	printf("%d\t",temp->client_ip);

}

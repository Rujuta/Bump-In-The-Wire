#include<stdio.h>
#include<stdlib.h>
#include<string.h>

//typedef struct node;
////typedef struct queue;
typedef struct node{

	/*IP address of queued client*/
	int client_ip; 
	struct node *next;
}node;

typedef struct queue{
	node *rear;
	node *front;
}queue;

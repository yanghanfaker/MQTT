/*------------------------------------------
author : Shanyang Ji	CQUPT
date : 11-23-2011
-------------------------------------------*/
/*-------------------------------------------
filename :
	handle_connect.c
description :
	1.accept new tcp (IPv4 & IPv6) connection request from clients.
	2.Add a new client information entry in the client-information-table 
	   when a new connection request is accepted.
-----------------------------------------*/
#include "socket.h"


int s_s4;	//server ipv4 sockfd for tr069 proxier
int s_c4=-1;
int sc4flg=0;

int pcs_s4;	//server ipv4 sockfd for pc managment software
int pcs_c4=-1;
int pcsc4flg=0;

int mps_s4;	//server ipv4 sockfd  for mobile phone managment software
int mps_c4=-1;
int mpsc4flg=0;

int adaptors_s4;	//server ipv4 sockfd  for wiapa adaptor
int adaptors_c4=-1;
int adaptorsc4flg=0;

int sock_sniffer_server;
int sock_sniffer_client=-1;
struct sockaddr_in local_addr4;
struct sockaddr_in local_sinffer;


int s_s6;	//server ipv6 sockfd
int s_c6;
struct sockaddr_in6 local_addr6;



/*-----------------------------------------
name :
	void * handle_connect4(void * arg)
funtion:
	accept a ipv4 tcp connection request from the client side.
parameter:
	arg---the pointer of server's sockfd 
return value:
	void *
---------------------------------------------*/
void * handle_connect4(void * arg){
	char addrstr[100];

	struct sockaddr_in from;
	unsigned int len = sizeof(from);

	creat_server_sockfd4(&s_s4,&local_addr4,SERVER_PORT4);

	while(1)//ready to reaceive clients connection request
	{
		s_c4 = accept(s_s4, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(s_c4 == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		struct timeval time;
		gettimeofday(&time, NULL);
		printf("time:%lds, %ldus\n",time.tv_sec,time.tv_usec);
		printf("a IPv4 client from:%s\n",inet_ntop(AF_INET, &(from.sin_addr), addrstr, INET_ADDRSTRLEN));
	}	
	return NULL;
}

/*handle pc background managment software connection*/
void * handle_pcbms_connect4(void * arg){
	char addrstr[100];

	struct sockaddr_in from;
	unsigned int len = sizeof(from);

	creat_server_sockfd4(&pcs_s4,&local_addr4,PCBMS_SERVER_PORT4);

	while(1)//ready to reaceive clients connection request
	{
		pcs_c4 = accept(pcs_s4, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(pcs_c4 == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		struct timeval time;
		gettimeofday(&time, NULL);
		printf("time:%lds, %ldus\n",time.tv_sec,time.tv_usec);
		printf("pc management software:%s\n",inet_ntop(AF_INET, &(from.sin_addr), addrstr, INET_ADDRSTRLEN));
	}	
	return NULL;
}

/*handle mobile phone background managment software connection*/
void * handle_mpbms_connect4(void * arg){
	char addrstr[100];

	struct sockaddr_in from;
	unsigned int len = sizeof(from);

	creat_server_sockfd4(&mps_s4,&local_addr4,MPBMS_SERVER_PORT4);

	while(1)//ready to reaceive clients connection request
	{
		mps_c4 = accept(mps_s4, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(mps_c4 == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		struct timeval time;
		gettimeofday(&time, NULL);
		printf("time:%lds, %ldus\n",time.tv_sec,time.tv_usec);
		printf("mobile phone management software:%s\n",inet_ntop(AF_INET, &(from.sin_addr), addrstr, INET_ADDRSTRLEN));
	}	
	return NULL;
}

void * handle_adaptor_connect4(void * arg){
	char addrstr[100];

	struct sockaddr_in from;
	unsigned int len = sizeof(from);

	creat_server_sockfd4(&adaptors_s4,&local_addr4,WIAPA_ADAPTOR_SERVER_PORT4);

	while(1)//ready to reaceive clients connection request
	{
		adaptors_c4 = accept(adaptors_s4, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(adaptors_c4 == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		struct timeval time;
		gettimeofday(&time, NULL);
		printf("time:%lds, %ldus\n",time.tv_sec,time.tv_usec);
		printf("wiapa adaptor:%s\n",inet_ntop(AF_INET, &(from.sin_addr), addrstr, INET_ADDRSTRLEN));
	}	
	return NULL;
}

/*-----------------------------------------
name :
	void * handle_connect4(void * arg)
funtion:
	accept a ipv4 tcp connection request from the client side.
parameter:
	arg---the pointer of server's sockfd 
return value:
	void *
---------------------------------------------*/
void * sniffer_connect(void * arg){
	char addrstr[100];

	struct sockaddr_in from;
	unsigned int len = sizeof(from);

	creat_server_sockfd4(&sock_sniffer_server, &local_sinffer,SNIFFER_PORT);

	while(1)//ready to reaceive clients connection request
	{
		sock_sniffer_client= accept(sock_sniffer_server, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(sock_sniffer_client == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		struct timeval time;
		gettimeofday(&time, NULL);
		printf("time:%lds, %ldus\n",time.tv_sec,time.tv_usec);
		printf("a IPv4 client from:%s\n",inet_ntop(AF_INET, &(from.sin_addr), addrstr, INET_ADDRSTRLEN));
	}	
	return NULL;
}



/*-----------------------------------------
name :
	void * handle_connect4(void * arg)
funtion:
	accept a ipv6 tcp connection request from the client side.
parameter:
	arg---the pointer of server's sockfd 
return value:
	void *
---------------------------------------------*/
/*
void * handle_connect6(void * arg){
	char addrstr[100];
	struct sockaddr_in6 from;
	unsigned int len = sizeof(from);

	creat_server_sockfd6(&s_s6,&local_addr6);
	
	while(1)//ready to accept clients connection request
	{
		s_c6 = accept(s_s6, (struct sockaddr*)&from, &len);//accept the connection request form client
		if(s_c6 == -1){
			perror("accept");
			exit(EXIT_FAILURE);
		}
		printf("handle connect %d:a IPv6 client from:%s\n\n",__LINE__,inet_ntop(AF_INET6, &(from.sin6_addr), addrstr, INET6_ADDRSTRLEN));
		pthread_mutex_lock(&cltinfo_scfd_mutex);	
		add_clientinfo( &cltinfo_head_p, s_c6);
		FDSET_ADD(s_c6, scan_fdset);
		pthread_mutex_unlock(&cltinfo_scfd_mutex);

	}	
	return NULL;
}
*/


/*-----------------------------------------
name :
	
funtion:
	
parameter:
	
return value:
	
---------------------------------------------*/
/*
void creat_server_sockfd6(int *sockfd,struct sockaddr_in6 *local6){
	int err;
	int optval = YES;
	int nodelay = YES;
	//step1--creat socket
	*sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	if(*sockfd == -1){
		perror("socket");
		exit(EXIT_FAILURE);
	}
	//kill "bind : address already in use" message error
	err = setsockopt(*sockfd,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
	if(err){
		perror("setsockopt");
	}
	err = setsockopt(*sockfd,IPPROTO_TCP,TCP_NODELAY,&nodelay,sizeof(nodelay));
	if(err){
		perror("setsockopt");
	}
	
	//step2--initialize the address struct 
	memset(local6, 0, sizeof(*local6));			
	local6->sin6_family = AF_INET6;		
	if ( inet_pton(AF_INET6, "0::0", &(local6->sin6_addr)) == 0 )
		perror("inet_pton");						
	local6->sin6_port = htons(SERVER_PORT6);	
//	local6->sin6_port = htons(SERVER_PORT4);	
	
	//step3--bind the socket file descriptor to the local address and port number
	err = bind(*sockfd, (struct sockaddr*)local6, sizeof(*local6));
	if(err == -1){
		perror("bind");
		exit(EXIT_FAILURE);
	}
	
	//step4--listen the socket
	err = listen(*sockfd, BACKLOG);	
	if(err == -1){
		perror("listen");
		exit(EXIT_FAILURE);
	}
}
*/

/*-----------------------------------------
name :
	
funtion:
	
parameter:
	
return value:
	
---------------------------------------------*/
void creat_server_sockfd4(int *sockfd, struct sockaddr_in *local, int portnum){
	int err;
	int optval = YES;
	int nodelay = YES;
	
	*sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(*sockfd < 0){
		perror("socket");
		exit(EXIT_FAILURE);
	}
	err = setsockopt(*sockfd,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
	if(err){
		perror("setsockopt");
	}
	err = setsockopt(*sockfd,IPPROTO_TCP,TCP_NODELAY,&nodelay,sizeof(nodelay));
	if(err){
		perror("setsockopt");
	}


	memset(local, 0, sizeof(struct sockaddr_in));		
	local->sin_family = AF_INET;				
	local->sin_addr.s_addr = htonl(INADDR_ANY);	
	local->sin_port = htons(portnum);		
	
	err = bind(*sockfd, (struct sockaddr*)local, sizeof(struct sockaddr_in));
	if(err < 0){
		perror("bind");
		exit(EXIT_FAILURE);
	}
	
	err = listen(*sockfd, BACKLOG);	
	if(err < 0){
		perror("listen");
		exit(EXIT_FAILURE);
	}

}



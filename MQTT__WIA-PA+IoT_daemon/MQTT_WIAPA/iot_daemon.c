/*
 * Copyright (c) 2001, Adam Dunkels.
 * Copyright (c) 2009, 2010 Joakim Eriksson, Niclas Finne, Dogan Yazar.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

 /* Below define allows importing saved output into Wireshark as "Raw IP" packet type */
#define WIRESHARK_IMPORT_FORMAT 1
 
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <err.h>
#include "socket.h"
#include "open62541.h"
#include "cJSON.h"
#include "mosquitto.h"
#include <sys/stat.h>

#define KEEP_ALIVE 60
#define MSG_MAX_SIZE  512
 
bool session = true;

typedef enum _BDROUTER_MODE {
	BDROUTER_MODE_MONITOR,
	BDROUTER_MODE_CAPTURE,
	BDROUTER_MODE_NORMAL,
} BDROUTER_MODE;

//define the work mode of the bdrouter
//the default work mode of the bdroute is monitor
BDROUTER_MODE bdrouter_mode=BDROUTER_MODE_NORMAL;

extern int s_c4;
//---add 20140817---
extern int sc4flg;
extern int pcs_c4;
extern int pcsc4flg;
extern int mps_c4;
extern int mpsc4flg;

extern int adaptors_c4;
extern int adaptorsc4flg;

//---end add---
extern int sock_sniffer_client;
pthread_t  thread_do[6];
int verbose = 1;
const char *ipaddr;
const char *netmask;
int slipfd = 0;
uint16_t basedelay=0,delaymsec=0;
uint32_t startsec,startmsec,delaystartsec,delaystartmsec;
int timestamp = 0, flowcontrol=0;


int ssystem(const char *fmt, ...)
	__attribute__((__format__ (__printf__, 1, 2)));
void write_to_serial(int outfd, void *inbuf, int len);

void slip_send(int fd, unsigned char c);
void slip_send_char(int fd, unsigned char c);


void * opcuaServerRoutine(void * arg);
void  Opcua_Server_Parse(UA_Byte *opcuabuf,UA_UInt16 opcualen);
void AddUintNode(UA_Byte *node);  // add the node to the server
void  changeNodeValue(UA_Server *server, UA_NodeId node, UA_Float value);
int getDevShortAddr(int* shortAddr, char* data, int len);



//#define PROGRESS(s) fprintf(stderr, s)
#define PROGRESS(s) do { } while (0)

char tundev[32] = { "" };

//opcua¶¨Òå
UA_Boolean running = true;
UA_Server *server;
UA_Variant wValue;

size_t get_file_size(const char *filepath)
{
    /*check input para*/
    if(NULL == filepath)
        return 0;
    struct stat filestat;
    memset(&filestat,0,sizeof(struct stat));
    /*get file information*/
    if(0 == stat(filepath,&filestat))
        return filestat.st_size;
    else
        return 0;
}

char *read_file_to_buf(const char *filepath)
{
    /*check input para*/
    if(NULL == filepath)
    {
        return NULL;
    }
    /*get file size*/
    size_t size = get_file_size(filepath);
    if(0 == size)
        return NULL;
        
    /*malloc memory*/
    char *buf = malloc(size+1);
    if(NULL == buf)
        return NULL;
    memset(buf,0,size+1);
    
    /*read string from file*/
    FILE *fp = fopen(filepath,"r");
    size_t readSize = fread(buf,1,size,fp);
    if(readSize != size)
    {
        /*read error*/
        free(buf);
        buf = NULL;
    }

    buf[size] = 0;
    return buf;
}
cJSON *prepare_parse_json(const char *filePath)
{
    /*check input para*/
    if(NULL == filePath)
    {
        printf("input para is NULL\n");
        return NULL;
    }
    /*read file content to buffer*/
    char *buf = read_file_to_buf(filePath);
    if(NULL == buf)
    {
        printf("read file to buf failed\n");
        return NULL;
    }
    /*parse JSON*/
    cJSON *pTemp = cJSON_Parse(buf);
    free(buf);
    buf = NULL;
    return pTemp;
} 

int
ssystem(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));

int
ssystem(const char *fmt, ...)
{
  char cmd[128];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  printf("%s\n", cmd);
  fflush(stdout);
  return system(cmd);
}

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335


/* get sockaddr, IPv4 or IPv6: */
void *
get_in_addr(struct sockaddr *sa)
{
  if(sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
void
stamptime(void)
{
  static long startsecs=0,startmsecs=0;
  long secs,msecs;
  struct timeval tv;
  time_t t;
  struct tm *tmp;
  char timec[20];
 
  gettimeofday(&tv, NULL) ;
  msecs=tv.tv_usec/1000;
  secs=tv.tv_sec;
  if (startsecs) {
    secs -=startsecs;
    msecs-=startmsecs;
    if (msecs<0) {secs--;msecs+=1000;}
    fprintf(stderr,"%04lu.%03lu ", secs, msecs);
  } else {
    startsecs=secs;
    startmsecs=msecs;
    t=time(NULL);
    tmp=localtime(&t);
    strftime(timec,sizeof(timec),"%T",tmp);
//    fprintf(stderr,"\n%s.%03lu ",timec,msecs);
    fprintf(stderr,"\n%s ",timec);
  }
}

int
is_sensible_string(const unsigned char *s, int len)
{
  int i;
  for(i = 1; i < len; i++) {
    if(s[i] == 0 || s[i] == '\r' || s[i] == '\n' || s[i] == '\t') {
      continue;
    } else if(s[i] < ' ' || '~' < s[i]) {
      return 0;
    }
  }
  return 1;
}

/*
 * Read from serial, when we have a packet write it to tun. No output
 * buffering, input buffered by stdio.
 */
void
serial_to_otherfd(FILE *inslip, int outfd, struct mosquitto *mosq, const char *TOPIC)
{
  static union {
    unsigned char inbuf[2000];
  } uip;
  static int inbufptr = 0;
  int ret,i;
  unsigned char c;

  unsigned char sensor_name[20];
    unsigned char StringToInt[20];
    unsigned char send_buf[80];
    int DATA;
    int s = 0;
    int n = 0;
    int s_add = 0;
    char *p = NULL;

#ifdef linux
  ret = fread(&c, 1, 1, inslip);
  if(ret == -1 || ret == 0) err(1, "serial_to_tun: read");
  goto after_fread;
#endif

 read_more:
  if(inbufptr >= sizeof(uip.inbuf)) {
     if(timestamp) stamptime();
     fprintf(stderr, "*** dropping large %d byte packet\n",inbufptr);
	 inbufptr = 0;
  }
  ret = fread(&c, 1, 1, inslip);
#ifdef linux
 after_fread:
#endif
  if(ret == -1) {
    err(1, "serial_to_tun: read");
  }
  if(ret == 0) {
    clearerr(inslip);
    return;
  }
  /*  fprintf(stderr, ".");*/
  switch(c) {
	  case SLIP_END:
	    if(inbufptr > 0) {
#ifdef DEBUG
	int i;
	printf("the nember of data is:%d\n",inbufptr);
	for(i=0; i<inbufptr; i++){
		printf("0x%2x ",uip.inbuf[i]);
	}printf("\n");
#endif
	      if(uip.inbuf[0] == '!') {
		      if(uip.inbuf[1] == 'M') {
			 	/* Read gateway MAC address and autoconfigure tap0 interface */
			  	char macs[24];
			  	int i, pos;
			  	for(i = 0, pos = 0; i < 16; i++) {
			    		macs[pos++] = uip.inbuf[2 + i];
			    		if((i & 1) == 1 && i < 14) {
			      			macs[pos++] = ':';
		    			}
		  		}
	          		if(timestamp) stamptime();
		  		macs[pos] = '\0';
					//printf("*** Gateway's MAC address: %s\n", macs);
		  		fprintf(stderr,"*** Gateway's MAC address: %s\n", macs);
	          		if (timestamp) stamptime();
		  		ssystem("ifconfig %s down", tundev);
			        if (timestamp) stamptime();
		  		ssystem("ifconfig %s hw ether %s", tundev, &macs[6]);
			        if (timestamp) stamptime();
		  		ssystem("ifconfig %s up", tundev);
			}
	      } 
		  
	      else if(uip.inbuf[0] == '?') {
		//now, we recieve a command request from the bdrouter.
		//we need to forward the command request to the bdrouter GUI software
		if(uip.inbuf[1] == 'P') {
	          /* Prefix info requested */
	          struct in6_addr addr;
		  int i;
		  char *s = strchr(ipaddr, '/');
		  if(s != NULL) {
		    *s = '\0';
		  }
	          inet_pton(AF_INET6, ipaddr, &addr);
	          if(timestamp) stamptime();
	          fprintf(stderr,"*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
	          //printf("*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			 			ipaddr, 
			 			addr.s6_addr[0], addr.s6_addr[1],
			 			addr.s6_addr[2], addr.s6_addr[3],
			 			addr.s6_addr[4], addr.s6_addr[5],
			 			addr.s6_addr[6], addr.s6_addr[7]);
	          slip_send(slipfd, '!');
	          slip_send(slipfd, 'P');
	          for(i = 0; i < 8; i++) {
	         	 /* need to call the slip_send_char for stuffing */
	         	 slip_send_char(slipfd, addr.s6_addr[i]);
	          }
		  slip_send(slipfd, SLIP_END);
	        }
		#define DEBUG_LINE_MARKER '\r'


		//forword the command request to the bdrouter GUI software
		//if(s_c4!=-1){
		//	if(-1==write(s_c4, uip.inbuf, inbufptr)){
		//		close(s_c4);
		//	}//inbufptr
		//}
	      }


		else if ((uip.inbuf[0] == 0xA1) && (uip.inbuf[1] == 0xA2)) 
		{	      //now, we recieve a application data from the coordinator
	      //we need to forward the data to the background GUI
			/*/-----add 20140817 for tr069 and background managment software------------------
			//-----forward scheduling report message
			if(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0){
				if(pcs_c4!=-1) {
					fprintf(stderr,"Application data, forward to pc background software. \n");
					if(-1==write(pcs_c4, uip.inbuf, inbufptr)){
						close(pcs_c4);
					}
				}	
				
				if(mps_c4!=-1) {
					fprintf(stderr,"Application data, forward to mobile phone background software. \n");
					if(-1==write(mps_c4, uip.inbuf, inbufptr)){
						close(mps_c4);
					}
				}	
			}
			//-----end add 20140817 for tr069 and background managment software---------------*/
		 	Opcua_Server_Parse(uip.inbuf, inbufptr);

		 	//point
			memset(StringToInt,'\0',strlen(StringToInt));
    	memset(send_buf,'\0',strlen(send_buf));
    	memset(sensor_name,'\0',strlen(sensor_name));  
        
        if(uip.inbuf[11] == 0xa3)
        {
            switch(uip.inbuf[31])
            {
            case('t'):
                strcpy(sensor_name,"TEMP_HUMI");
                break;
            case('d'):
                strcpy(sensor_name,"DUST");
                break;
            default:
                //printf("$$$$err sensor$$$$\n");
                //mosquitto_publish(mosq,NULL,TOPIC,strlen("err sensor")+1,"err sensor",0,0);
            	break;
            }

          	if(strcmp(sensor_name,"TEMP_HUMI")==0)
           	{   
           		s = 0;
                p = &uip.inbuf[41]; //temp
                
                while(*p != ',')
                {
                    StringToInt[s++] = *p;
                    p++;
                }
                

                n = strlen(StringToInt);
                n = s-n;
                

                DATA = atoi(StringToInt);

                
                for(int k=0;k<n;k++)
                {
                    DATA=DATA*10;
                }

                s_add = uip.inbuf[7]*256 + uip.inbuf[8];
                sprintf(send_buf,"SHORT_ADDR:%d,TEMP:%d",s_add,DATA);
                printf("\t %s \t\n",send_buf);
                mosquitto_publish(mosq,NULL,TOPIC,strlen(send_buf)+1,send_buf,0,0);
                memset(StringToInt,'\0',strlen(StringToInt));
                memset(send_buf,'\0',strlen(send_buf));
                i = 0;
                s = 0 ;
                p = &uip.inbuf[44]; //humi
                while(s<2)
                {
                    StringToInt[s++] = *p;
                    p++;
                }
                n = strlen(StringToInt);
                n = s-n;
                DATA = atoi(StringToInt);
                for(int k=0;k<n;k++)
                {
                    DATA=DATA*10;
                }
                
                sprintf(send_buf,"SHORT_ADDR:%d,HUMI:%d",s_add,DATA);
                printf("\t %s \t\n",send_buf);
                mosquitto_publish(mosq,NULL,TOPIC,strlen(send_buf)+1,send_buf,0,0);
                memset(StringToInt,'\0',strlen(StringToInt));
                memset(send_buf,'\0',strlen(send_buf));
            }

        //     else if(strcmp(sensor_name,"DUST")==0)
        //         {   
        //             printf("test11\n");
        //             p = &uip.inbuf[36]; //dust
        //             while(*p != ',')
        //             {
        //                 StringToInt[s++] = *p;
        //                 p++;
        //             }
        //             n = strlen(StringToInt);
        //             n = s-n;
        //             DATA = atoi(StringToInt);
        //             for(int k=0;k<n;k++)
        //             {
        //                 DATA=DATA*10;
        //             }
        //             DATA = DATA*19/900;
        //             s_add = uip.inbuf[7]*256 + uip.inbuf[8];
        //             sprintf(send_buf,"SHORADD:%d,DUST:%d",s_add,DATA);
        //             mosquitto_publish(mosq,NULL,TOPIC,strlen(send_buf)+1,send_buf,0,0);
        //             memset(StringToInt,'\0',strlen(StringToInt));
        //             memset(send_buf,'\0',strlen(send_buf));
        //         }
        //         else
        //         {
        //             mosquitto_publish(mosq,NULL,TOPIC,strlen("err sensor")+1,"err sensor",0,0); 
        //         }
        // }
        // else 
        // {
        //   mosquitto_publish(mosq,NULL,TOPIC,strlen("err sensor")+1,"err sensor",0,0);  
        }   



			if(s_c4!=-1 && (sc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
				fprintf(stderr,"Application data, forward to background GUI. \n");
				sc4flg = 0;
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}	
			//-----add 20140817 for tr069 and background managment software------------------
			if(pcs_c4!=-1 && (pcsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
				fprintf(stderr,"Application data, forward to pc background software. \n");
				pcsc4flg = 0;
				if(-1==write(pcs_c4, uip.inbuf, inbufptr)){
					close(pcs_c4);
				}
			}	

			if(mps_c4!=-1 && (mpsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))){
				fprintf(stderr,"Application data, forward to mobile phone background software. \n");
				mpsc4flg = 0;
				if(-1==write(mps_c4, uip.inbuf, inbufptr)){
					close(mps_c4);
				}
			}	
			
			if(adaptors_c4!=-1 ){
				if(uip.inbuf[11]==0xA0||uip.inbuf[11]==0xB1||uip.inbuf[11]==0xB2||
					uip.inbuf[11]==0xa3||uip.inbuf[11]==0xa4||uip.inbuf[11]==0xa5){
					fprintf(stderr,"Application data, forward to wiapa adaptor. \n");
					adaptorsc4flg = 0;
					if(-1==write(adaptors_c4, uip.inbuf, inbufptr)){
						close(adaptors_c4);
					}
				}
			}	
			//-----end add 20140817 for tr069 and background managment software---------------
	 }

		
		else if ((uip.inbuf[0] == 0xB7) && (uip.inbuf[1] == 0xB8)) {
	      //now, we recieve a sinffer IEEE 802.15.4 packet from the sinffer
	      //we need to forward the sinffer data to the sinffer GUI software
		fprintf(stderr,"IEEE 802.15.4 packet, forward to sniffer GUI. \n");
	  	   if(sock_sniffer_client !=-1){
		   	if(-1==write(sock_sniffer_client, uip.inbuf, inbufptr)){
				close(sock_sniffer_client);
			}//inbufptr
		   }
		
	      } 

		  
	      else if(uip.inbuf[0] == DEBUG_LINE_MARKER) {    
				fwrite(uip.inbuf + 1, inbufptr - 1, 1, stdout);
	      } 
		  
	      else if(is_sensible_string(uip.inbuf, inbufptr)) {
	        if(verbose==1) {   /* strings already echoed below for verbose>1 */
	          if (timestamp) stamptime();
	          fwrite(uip.inbuf, inbufptr, 1, stdout);
	        }
	      } 	  
	      else {
	        if(verbose>2) {
	          if (timestamp) stamptime();
	          printf("Packet from SLIP of length %d - write TUN\n", inbufptr);
	          if (verbose>4) {
#if WIRESHARK_IMPORT_FORMAT
	            printf("0000");
		        	for(i = 0; i < inbufptr; i++) printf(" %02x",uip.inbuf[i]);
#else
	            printf("         ");
	            for(i = 0; i < inbufptr; i++) {
	              printf("%02x", uip.inbuf[i]);
	              if((i & 3) == 3) printf(" ");
	              if((i & 15) == 15) printf("\n         ");
	            }
#endif
	            printf("\n");
	          }
	        }
		
		//now, we recieve a ipv6 packet.
		// Maybe we can do some checking. It is useful but out of the scope of this daemon.
		//we should forward the packet to orther node or capture it,
		//according to the work mode of the bdrouter.
		//BDROUTER_MODE_MONITOR---forward the ipv6 packte and copy it to the bdroute GUI software.
		//BDROUTER_MODE_CAPTURE---capture the packet and send it to the bdroute GUI software.
		//BDROUTER_MODE_MORMAL---just forward the ipv6 packet to the next hop.
		if(bdrouter_mode == BDROUTER_MODE_NORMAL){	//normal
			printf("the bdroute in working in the normal mode\n");
			if(write(outfd, uip.inbuf, inbufptr) != inbufptr) {
			   err(1, "serial_to_tun: write");
			}
		}else if(bdrouter_mode == BDROUTER_MODE_CAPTURE){	//capture
			printf("the bdroute in working in the capture mode\n");
			if(s_c4!=-1){
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}
		}else if(bdrouter_mode == BDROUTER_MODE_MONITOR){	//nornitor
			printf("the bdroute in working in the mointor mode\n");
			if(write(outfd, uip.inbuf, inbufptr) != inbufptr) {
			   err(1, "serial_to_tun: write");
			}
			if(s_c4!=-1){
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}

		}
	      }
	      inbufptr = 0;
	    }
	    memset(uip.inbuf, '\0', sizeof(uip.inbuf));
	    break;
	
	  case SLIP_ESC:
	    if(fread(&c, 1, 1, inslip) != 1) {
	      clearerr(inslip);
	      /* Put ESC back and give up! */
	      ungetc(SLIP_ESC, inslip);
	      return;
	    }
	
	    switch(c) {
	    	case SLIP_ESC_END:
	      	c = SLIP_END;
	     		break;
	    	case SLIP_ESC_ESC:
	      	c = SLIP_ESC;
	      	break;
	    }
	    /* FALLTHROUGH */
	  default:
	    uip.inbuf[inbufptr++] = c;
	
	    /* Echo lines as they are received for verbose=2,3,5+ */
	    /* Echo all printable characters for verbose==4 */
	    if((verbose==2) || (verbose==3) || (verbose>4)) {
	      if(c=='\n') {
	        if(is_sensible_string(uip.inbuf, inbufptr)) {
	          if (timestamp) stamptime();
	          fwrite(uip.inbuf, inbufptr, 1, stdout);
	          inbufptr=0;
	        }
	      }
	    } else if(verbose==4) {
	      if(c == 0 || c == '\r' || c == '\n' || c == '\t' || (c >= ' ' && c <= '~')) {
					fwrite(&c, 1, 1, stdout);
	        if(c=='\n') if(timestamp) stamptime();
	      }
	    }
    	break;
  }

  goto read_more;
}

unsigned char slip_buf[2000];   //test
int slip_end, slip_begin;

void
slip_send_char(int fd, unsigned char c)
{
  switch(c) {
  case SLIP_END:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_END);
    break;
  case SLIP_ESC:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_ESC);
    break;
  default:
    slip_send(fd, c);
    break;
  }
}

void
slip_send(int fd, unsigned char c)             //test1
{
  if(slip_end >= sizeof(slip_buf)) {
    err(1, "slip_send overflow");
  }
  slip_buf[slip_end] = c;
  slip_end++;
}

int
slip_empty()
{
  return slip_end == 0;
}

void
slip_flushbuf(int fd)		//test2
{
  int n;
  
  if(slip_empty()) {
    return;
  }

  n = write(fd, slip_buf + slip_begin, (slip_end - slip_begin));

  if(n == -1 && errno != EAGAIN) {
    err(1, "slip_flushbuf write failed");
  } else if(n == -1) {
    PROGRESS("Q");		/* Outqueueis full! */
  } else {
    slip_begin += n;
    if(slip_begin == slip_end) {
      slip_begin = slip_end = 0;
    }
  }
}

void
write_to_serial(int outfd, void *inbuf, int len)		//test3
{
  u_int8_t *p = inbuf;
  int i;

  if(verbose>2) {
    if (timestamp) stamptime();
    printf("Packet from TUN of length %d - write SLIP\n", len);
    if (verbose>4) {
#if WIRESHARK_IMPORT_FORMAT
      printf("0000");
	  for(i = 0; i < len; i++) printf(" %02x", p[i]);
#else
      printf("         ");
      for(i = 0; i < len; i++) {
        printf("%02x", p[i]);
        if((i & 3) == 3) printf(" ");
        if((i & 15) == 15) printf("\n         ");
      }
#endif
      printf("\n");
    }
  }

  /* It would be ``nice'' to send a SLIP_END here but it's not
   * really necessary.
   */
  /* slip_send(outfd, SLIP_END); */

  for(i = 0; i < len; i++) {
    switch(p[i]) {
    case SLIP_END:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_END);
      break;
    case SLIP_ESC:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_ESC);
      break;
    default:
      slip_send(outfd, p[i]);
      break;
    }
  }
  slip_send(outfd, SLIP_END);
  PROGRESS("t");
}


/*
 * Read from tun, write to slip.
 */
int
tun_to_serial(int infd, int outfd)			//test4
{
  struct {
    unsigned char inbuf[2000];
  } uip;    
  uip.inbuf[0]='\0';

  int size;
  if((size = read(infd, uip.inbuf, 2000)) == -1) err(1, "tun_to_serial: read");
  write_to_serial(outfd, uip.inbuf, size);
  return size;
}
/*
 * Read from socket, write to slip.
 */
int
bdrtfd_to_serial(int infd, int outfd)			//test6
{
  struct {
    unsigned char inbuf[2000];
  } uip;
  int size;
  //*uip.inbuf='!';
 // *(uip.inbuf+1)='P';
//  if((size = read(infd, uip.inbuf, 2000)) == -1) err(1, "tun_to_serial: read");
    size = read(infd, uip.inbuf, 2000);

  	if(size <=0){
		close(infd);printf("close the socket %d\n",infd);
		return 0;//indicate the socket has been closed on the remote side
	}
	if(size > 0){
		if(0x2A==uip.inbuf[0]){
		//control the work mode of the bdrouter
			if(0x01==uip.inbuf[1]){	
			//set The bdrouter works in the monitor mode
				bdrouter_mode = BDROUTER_MODE_MONITOR;
				printf("set the bdroute work in monitor mode\n");
			}else if(0x02==uip.inbuf[1]){	
			//set the bdrouter works in the capture mode
				bdrouter_mode = BDROUTER_MODE_CAPTURE;
				printf("set the bdroute work in capture mode\n");
			}
			else if(0x03==uip.inbuf[1]){	
			//set the bdrouter works in the normal mode
				bdrouter_mode = BDROUTER_MODE_NORMAL;
				printf("set the bdroute work in normal mode\n");
			}
			return 1;
		}
		//forward the control command to the bdrouter
	 	write_to_serial(outfd, uip.inbuf, size);
	}
  return size;
}


/*
 * Read from socket, write to slip.
 */
int
sniffd_to_serial(int infd, int outfd)		//test5
{
  struct {
    unsigned char inbuf[2000];
  } uip;
  int size;
  //*uip.inbuf='!';
  //*(uip.inbuf+1)='P';
//  if((size = read(infd, uip.inbuf+2, 2000)) == -1) err(1, "tun_to_serial: read");
  	//if((size = read(infd, uip.inbuf, 2000)) == -1) err(1, "tun_to_serial: read");
  	size = read(infd, uip.inbuf, 2000);
  	if(size <=0){
		close(infd);printf("close the socket %d\n",infd);
		return 0;//indicate the socket has been closed on the remote side
	}
	if(size > 0){
//	  printf("478 the data counet:%d\n",size+2);
//	  write_to_serial(outfd, uip.inbuf, size+2);
	  write_to_serial(outfd, uip.inbuf, size);

	}
  return size;
}



#ifndef BAUDRATE
#define BAUDRATE B115200
#endif
speed_t b_rate = BAUDRATE;

void
stty_telos(int fd)
{
  struct termios tty;
  speed_t speed = b_rate;
  int i;

  if(tcflush(fd, TCIOFLUSH) == -1) err(1, "tcflush");

  if(tcgetattr(fd, &tty) == -1) err(1, "tcgetattr");

  cfmakeraw(&tty);

  /* Nonblocking read. */
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 0;
  if (flowcontrol)
    tty.c_cflag |= CRTSCTS;
  else
    tty.c_cflag &= ~CRTSCTS;
  tty.c_cflag &= ~HUPCL;
  tty.c_cflag &= ~CLOCAL;

  cfsetispeed(&tty, speed);
  cfsetospeed(&tty, speed);

  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) err(1, "tcsetattr");

#if 1
  /* Nonblocking read and write. */
  /* if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1) err(1, "fcntl"); */

  tty.c_cflag |= CLOCAL;
  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) err(1, "tcsetattr");

  i = TIOCM_DTR;
  if(ioctl(fd, TIOCMBIS, &i) == -1) err(1, "ioctl");
#endif

  usleep(10*1000);		/* Wait for hardware 10ms. */

  /* Flush input and output buffers. */
  if(tcflush(fd, TCIOFLUSH) == -1) err(1, "tcflush");
}

int
devopen(const char *dev, int flags)
{
  char t[32];
  strcpy(t, "/dev/");
  strncat(t, dev, sizeof(t) - 5);
  return open(t, flags);
}

#ifdef linux
#include <linux/if.h>
#include <linux/if_tun.h>

int
tun_alloc(char *dev, int tap)
{
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = (tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
  if(*dev != 0)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}
#else
int
tun_alloc(char *dev, int tap)
{
  return devopen(dev, O_RDWR);
}
#endif

void
cleanup(void)
{
#ifndef __APPLE__
  if (timestamp) stamptime();
  ssystem("ifconfig %s down", tundev);
#ifndef linux
  ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
#endif
  /* ssystem("arp -d %s", ipaddr); */
  if (timestamp) stamptime();
  ssystem("netstat -nr"
	  " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
	  " | sh",
	  tundev);
#else
  {
    char *  itfaddr = strdup(ipaddr);
    char *  prefix = index(itfaddr, '/');
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 %s remove", tundev, ipaddr);
    if (timestamp) stamptime();
    ssystem("ifconfig %s down", tundev);
    if ( prefix != NULL ) *prefix = '\0';
    ssystem("route delete -inet6 %s", itfaddr);
    free(itfaddr);
  }
#endif
}

void
sigcleanup(int signo)
{
  fprintf(stderr, "signal %d\n", signo);
  exit(0);			/* exit(0) will call cleanup() */
}

static int got_sigalarm;

void
sigalarm(int signo)
{
  got_sigalarm = 1;
  return;
}

void
sigalarm_reset()
{
#ifdef linux
#define TIMEOUT (997*1000)
#else
#define TIMEOUT (2451*1000)
#endif
  ualarm(TIMEOUT, TIMEOUT);
  got_sigalarm = 0;
}

void
ifconf(const char *tundev, const char *ipaddr)
{
#ifdef linux
  if (timestamp) stamptime();
  ssystem("ifconfig %s inet `hostname` up", tundev);
  if (timestamp) stamptime();
  ssystem("ifconfig %s add %s", tundev, ipaddr);

/* radvd needs a link local address for routing */
#if 0
/* fe80::1/64 is good enough */
  ssystem("ifconfig %s add fe80::1/64", tundev);
#elif 1
/* Generate a link local address a la sixxs/aiccu */
/* First a full parse, stripping off the prefix length */
  {
    char lladdr[40];
    char c, *ptr=(char *)ipaddr;
    uint16_t digit,ai,a[8],cc,scc,i;
    for(ai=0; ai<8; ai++) {
      a[ai]=0;
    }
    ai=0;
    cc=scc=0;
    while((c=*ptr++)) {
      if(c=='/') break;
      if(c==':') {
	if(cc)
	  scc = ai;
	cc = 1;
	if(++ai>7) break;
      } 
      else {
	cc=0;
	digit = c-'0';
	if (digit > 9) 
	  digit = 10 + (c & 0xdf) - 'A';
	a[ai] = (a[ai] << 4) + digit;
      }
    }
    /* Get # elided and shift what's after to the end */
    cc=8-ai;
    for(i=0;i<cc;i++) {
      if ((8-i-cc) <= scc) {
	a[7-i] = 0;
      } else {
	a[7-i] = a[8-i-cc];
	a[8-i-cc]=0;
      }
    }
    sprintf(lladdr,"fe80::%x:%x:%x:%x",a[1]&0xfefd,a[2],a[3],a[7]);
    if (timestamp) stamptime();
    ssystem("ifconfig %s add %s/64", tundev, lladdr);
  }
#endif /* link local */
#elif defined(__APPLE__)
  {
	char * itfaddr = strdup(ipaddr);
	char * prefix = index(itfaddr, '/');
	if ( prefix != NULL ) {
		*prefix = '\0';
		prefix++;
	} else {
		prefix = "64";
	}
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 up", tundev );
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 %s add", tundev, ipaddr );
    if (timestamp) stamptime();
    ssystem("sysctl -w net.inet6.ip6.forwarding=1");
    free(itfaddr);
  }
#else
  if (timestamp) stamptime();
  ssystem("ifconfig %s inet `hostname` %s up", tundev, ipaddr);
  if (timestamp) stamptime();
  ssystem("sysctl -w net.inet.ip.forwarding=1");
#endif /* !linux */

  if (timestamp) stamptime();
  ssystem("ifconfig %s\n", tundev);
}

void AddUintNode(UA_Byte *node)  // add the node to the server
{
	
	UA_Float myInteger = 123;
	UA_VariableAttributes attr;
	UA_VariableAttributes_init(&attr);
	UA_Variant_setScalar(&attr.value, &myInteger, &UA_TYPES[UA_TYPES_FLOAT]);
	attr.displayName = UA_LOCALIZEDTEXT("en_US", node);

		    /* 2) define where the variable shall be added with which browsename */
	UA_NodeId newNodeId = UA_NODEID_STRING(1, node);
	UA_NodeId parentNodeId = UA_NODEID_STRING(1,"WIA_PA");
	UA_NodeId parentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
	UA_NodeId variableType = UA_NODEID_NULL; /* no variable type defined */
	UA_QualifiedName browseName = UA_QUALIFIEDNAME(1, node);

		    /* 3) add the variable */
	 UA_Server_addVariableNode(server, newNodeId, parentNodeId, parentReferenceNodeId,
		                              browseName, variableType, attr, NULL, NULL);

}

int getDevShortAddr(int* shortAddr, char* data, int len){
	*shortAddr = (data[7]<<8)+data[8];
	return 1;
}

void  Opcua_Server_Parse(UA_Byte *opcuabuf,UA_UInt16 opcualen)
{
	char nodeName[20];
	UA_NodeId nodeId;
	UA_Float UinNodeData = 0;
	char saddr[20];
	int saddrdata = 0;
	char *p = NULL;
    	int i = 0;  
	int result = 0;
	char StringToInt[20];
	memset(nodeName,'\0',20);
	memset(StringToInt,'\0',20);
	if(opcuabuf[11] == 0xa3){
		if(opcuabuf[31] == 't'){
			//printf("get the temp data\n");
			getDevShortAddr(&saddrdata, opcuabuf, opcualen);
			strcat(nodeName,"WIA_PA_TEMP_");
			p = strstr(nodeName,"WIA_PA_TEMP_");
			if(p != NULL)
				sprintf(p,"WIA_PA_TEMP_%d",saddrdata);//transfer the char to int 
			nodeName[strlen(nodeName)] = '\0';
			nodeId = UA_NODEID_STRING(1, nodeName);
			p = &opcuabuf[41];
			while(*p != ',')
			{
				StringToInt[i++] = *p;
				p++;
			}	
			UinNodeData =  (UA_Float)atoi(StringToInt);
			UinNodeData = UinNodeData;
			result = Get_Node_Fromaddresspace(server, &nodeId);
			if(!result){
				AddUintNode(nodeName);
				//printf("add the temp data to opcua server\n");
			}
			else{
				if((UinNodeData > 0)&&(UinNodeData < 50))
					changeNodeValue(server, nodeId,UinNodeData);
				//printf("the data of the temp node is %d\n",UinNodeData);
			}
			memset(nodeName,'\0',strlen(nodeName));
			memset(StringToInt,'\0',strlen(StringToInt));
			//memset(saddr,'\0',strlen(saddr));
			i = 0;


			strcat(nodeName,"WIA_PA_HUMI_");
			p = strstr(nodeName,"WIA_PA_HUMI_");
			if(p != NULL)
				sprintf(p,"WIA_PA_HUMI_%d",saddrdata);//transfer the char to int 
			nodeName[strlen(nodeName)] = '\0';
			nodeId = UA_NODEID_STRING(1, nodeName);
			p = &opcuabuf[44];
			while(*p != ';')
			{
				StringToInt[i++] = *p;
				p++;
			}	
			UinNodeData =  (UA_Float)atoi(StringToInt);
			UinNodeData = UinNodeData;
			result = Get_Node_Fromaddresspace(server, &nodeId);
			if(!result){
				AddUintNode(nodeName);
				//printf("add the humi data to opcua server\n");
			}
			else{
				if((UinNodeData > 0)&&(UinNodeData < 100))
					changeNodeValue(server, nodeId,UinNodeData);
				//printf("the data of the humi node is %d\n",UinNodeData);
			}
			memset(nodeName,'\0',strlen(nodeName));
			memset(StringToInt,'\0',strlen(StringToInt));
			memset(saddr,'\0',strlen(saddr));
			i = 0;
		}
		if(opcuabuf[31] == 'd'){
			//printf("get the dust data\n");
			getDevShortAddr(&saddrdata, opcuabuf, opcualen);
			strcat(nodeName,"WIA_PA_DUST_");
			p = strstr(nodeName,"WIA_PA_DUST_");
			if(p != NULL)
				sprintf(p,"WIA_PA_DUST_%d",saddrdata);
			nodeName[strlen(nodeName)] = '\0';
			nodeId = UA_NODEID_STRING(1, nodeName);
			//p = strstr(opcuabuf,"dust");
			p = &opcuabuf[36];
			//opcuabuf = 
			while(*p != ';')
			{
				StringToInt[i++] = *p;
				p++;
			}	
			UinNodeData =  (UA_Float)atoi(StringToInt);
			UinNodeData = UinNodeData *19/900;
			result = Get_Node_Fromaddresspace(server, &nodeId);
			if(!result){
				AddUintNode(nodeName);
				//printf("add the dust data to opcua server\n");
			}	
			else{
				changeNodeValue(server, nodeId,UinNodeData);
				//printf("the data of the dust node is %d\n",UinNodeData);
			}
			memset(nodeName,'\0',strlen(nodeName));	
			memset(StringToInt,'\0',strlen(StringToInt));
			memset(saddr,'\0',strlen(saddr));
			i = 0;	 
		}	
	}
	 if((opcuabuf[12] == 0x04)&&(opcuabuf[13] == 0xfe)&&(opcuabuf[14] == 0xfe)){
		//printf("get the meters data\n");
		getDevShortAddr(&saddrdata, opcuabuf, opcualen);
		strcat(nodeName,"WIA_PA_METERS_");
		p = strstr(nodeName,"WIA_PA_METERS_");
		if(p != NULL)
			sprintf(p,"WIA_PA_METERS_%d",saddrdata);
		nodeName[strlen(nodeName)] = '\0';
		nodeId = UA_NODEID_STRING(1, nodeName);
		
		
		UinNodeData = (UA_Float)(((opcuabuf[33]-0x33)/16*10 + (opcuabuf[33]-0x33)%16)*10000+
		((opcuabuf[32]-0x33)/16*10 + (opcuabuf[32]-0x33)%16)*100 + (opcuabuf[31]-0x33)/16*10 + (opcuabuf[31]-0x33)%16)/100;
		result = Get_Node_Fromaddresspace(server, &nodeId);
		if(!result){
			AddUintNode(nodeName);
			//printf("add the meters data to opcua server\n");
		}	
		else{
			if((UinNodeData>0)&&(UinNodeData<100))
				changeNodeValue(server, nodeId,UinNodeData);
			//printf("the data of the meters node is %f\n",UinNodeData);
		}
		memset(nodeName,'\0',strlen(nodeName));	
		//memset(StringToInt,'\0',strlen(StringToInt));
		memset(saddr,'\0',strlen(saddr));
		i = 0;	 
	}
}


void  changeNodeValue(UA_Server *server, UA_NodeId node, UA_Float value)
{
	//UA_Int32 nodeNum = node.identifier.numeric;
	//UA_Variant *wValue = UA_Variant_new();
	//UA_Variant_init(wValue);
	UA_StatusCode retval = UA_STATUSCODE_GOOD;
	wValue.type = &UA_TYPES[UA_TYPES_FLOAT];
	wValue.storageType = UA_VARIANT_DATA;
	wValue.data = &value;
	retval=UA_Server_writeValue(server,node,wValue);
	//printf("write %d retval %x\n",node.identifier.string.data,retval);
	//UA_Variant_deleteMembers(wValue);
	//UA_Variant_delete(wValue);
}

void * opcuaServerRoutine(void * arg)
{
	/* init the server */
	UA_ServerConfig config = UA_ServerConfig_standard;
	UA_ServerNetworkLayer nl = UA_ServerNetworkLayerTCP(UA_ConnectionConfig_standard, 15000);
	config.networkLayers = &nl;
	config.networkLayersSize = 1;
	server = UA_Server_new(config);
	

	UA_ObjectAttributes object_attr;
    UA_ObjectAttributes_init(&object_attr);
    object_attr.description = UA_LOCALIZEDTEXT("en_US", "WIA_PA");
    object_attr.displayName = UA_LOCALIZEDTEXT("en_US", "WIA_PA");
    UA_Server_addObjectNode(server, UA_NODEID_STRING(1, "WIA_PA"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
        UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES), UA_QUALIFIEDNAME(1,"WIA_PA"),
        UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE), object_attr, NULL, NULL);



	/* run the server loop */
	UA_StatusCode retval = UA_Server_run(server, &running);
	UA_Server_delete(server);
	nl.deleteMembers(&nl);

	return (int)retval;
}

int main(int argc, char **argv)
{
  int c;
  int tunfd, maxfd;
  int ret;
  fd_set rset, wset;
  FILE *inslip;
  const char *siodev = NULL;
  const char *host = NULL;
  const char *port = NULL;
  const char *prog;
  int baudrate = -2;
  int tap = 0;
  slipfd = 0;

  char *filename = "./test.json";

  cJSON *pJson = NULL;
  cJSON *pTemp = NULL;
  pJson = prepare_parse_json(filename);

  if(NULL == pJson)
  {
      printf("parse json failed\n");
      return -1;
  }
  /*port*/
  pTemp = cJSON_GetObjectItem(pJson,"port");
  //printf("name is :%s\n",pTemp->valuestring);
  int PORT = atoi(pTemp->valuestring);
  

  /*获取site值*/
  pTemp = cJSON_GetObjectItem(pJson,"site");
  //printf("site is :%s\n",pTemp->valuestring);
  const char *HOST = pTemp->valuestring;

  /*获取topic值*/
  pTemp = cJSON_GetObjectItem(pJson,"topic");
  //printf("site is :%s\n",pTemp->valuestring);
  const char *TOPIC = pTemp->valuestring;
  

  printf("port:%d\n",PORT);
  printf("site:%s\n",HOST);
  printf("topic:%s\n",TOPIC);

  char buff[MSG_MAX_SIZE];
  struct mosquitto *mosq = NULL;
  //libmosquitto 库初始化
  mosquitto_lib_init();
  //创建mosquitto客户端
  mosq = mosquitto_new(NULL,session,NULL);
  if(!mosq){
      printf("create client failed..\n");
      mosquitto_lib_cleanup();
      return 1;
  }
  //连接服务器
  if(mosquitto_connect(mosq, HOST, PORT, KEEP_ALIVE)){
      fprintf(stderr, "Unable to connect.\n");
      return 1;
  }
  //开启一个线程，在线程里不停的调用 mosquitto_loop() 来处理网络信息
  int loop = mosquitto_loop_start(mosq);
  if(loop != MOSQ_ERR_SUCCESS)
  {
      printf("mosquitto loop error\n");
      return 1;
  }

  fprintf(stderr, "******** IoT Daemon, Ver. 1.1 ********'\n");

//======================================================================
// .bref: start of parsing typical unix command line options
//======================================================================
  prog = argv[0];
  setvbuf(stdout, NULL, _IOLBF, 0); /* Line buffered output. */

  while((c = getopt(argc, argv, "B:HLhs:t:v::d::a:p:T")) != -1) {
    switch(c) {
    case 'B':
      baudrate = atoi(optarg);
      break;

    case 'H':
      flowcontrol=1;
      break;
 
    case 'L':
      timestamp=1;
      break;

    case 's':
      if(strncmp("/dev/", optarg, 5) == 0) {
	siodev = optarg + 5;
      } else {
	siodev = optarg;
      }
      break;

    case 't':
      if(strncmp("/dev/", optarg, 5) == 0) {
	strncpy(tundev, optarg + 5, sizeof(tundev));
      } else {
	strncpy(tundev, optarg, sizeof(tundev));
      }
      break;

    case 'a':
      host = optarg;
      break;

    case 'p':
      port = optarg;
      break;

    case 'd':
      basedelay = 10;
      if (optarg) basedelay = atoi(optarg);
      break;

    case 'v':
      verbose = 2;
      if (optarg) verbose = atoi(optarg);
      break;

    case 'T':
      tap = 1;
      break;
 
    case '?':
    case 'h':
    default:
fprintf(stderr,"usage:  %s [options] ipaddress\n", prog);
fprintf(stderr,"example: iot_daemon -L -v2 -s ttyUSB1 aaaa::1/64\n");
fprintf(stderr,"Options are:\n");
#ifndef __APPLE__
fprintf(stderr," -B baudrate    9600,19200,38400,57600,115200 (default),230400,460800,921600\n");
#else
fprintf(stderr," -B baudrate    9600,19200,38400,57600,115200 (default),230400\n");
#endif
fprintf(stderr," -H             Hardware CTS/RTS flow control (default disabled)\n");
fprintf(stderr," -L             Log output format (adds time stamps)\n");
fprintf(stderr," -s siodev      Serial device (default /dev/ttyUSB0)\n");
fprintf(stderr," -T             Make tap interface (default is tun interface)\n");
fprintf(stderr," -t tundev      Name of interface (default tap0 or tun0)\n");
fprintf(stderr," -v[level]      Verbosity level\n");
fprintf(stderr,"    -v0         No messages\n");
fprintf(stderr,"    -v1         Encapsulated SLIP debug messages (default)\n");
fprintf(stderr,"    -v2         Printable strings after they are received\n");
fprintf(stderr,"    -v3         Printable strings and SLIP packet notifications\n");
fprintf(stderr,"    -v4         All printable characters as they are received\n");
fprintf(stderr,"    -v5         All SLIP packets in hex\n");
fprintf(stderr,"    -v          Equivalent to -v3\n");
fprintf(stderr," -d[basedelay]  Minimum delay between outgoing SLIP packets.\n");
fprintf(stderr,"                Actual delay is basedelay*(#6LowPAN fragments) milliseconds.\n");
fprintf(stderr,"                -d is equivalent to -d10.\n");
fprintf(stderr," -a serveraddr  \n");
fprintf(stderr," -p serverport  \n");
exit(1);
      break;
    }
  }

//======================================================================
//.bref: end of parsing typical unix command line options
//======================================================================
//.bref: start to configrate arguments and open  
//======================================================================
  
  argc -= (optind - 1);
  argv += (optind - 1);

  if(argc != 2 && argc != 3) {
    err(1, "usage: %s [-B baudrate] [-H] [-L] [-s siodev] [-t tundev] [-T] [-v verbosity] [-d delay] [-a serveraddress] [-p serverport] ipaddress", prog);
  }
  ipaddr = argv[1];

  switch(baudrate) {
  case -2:
    break;			/* Use default. */
  case 9600:
    b_rate = B9600;
    break;
  case 19200:
    b_rate = B19200;
    break;
  case 38400:
    b_rate = B38400;
    break;
  case 57600:
    b_rate = B57600;
    break;
  case 115200:
    b_rate = B115200;
    break;
  case 230400:
    b_rate = B230400;
    break;
#ifndef __APPLE__
  case 460800:
    b_rate = B460800;
    break;
  case 921600:
    b_rate = B921600;
    break;
#endif
  default:
    err(1, "unknown baudrate %d", baudrate);
    break;
  }

  if(*tundev == '\0') {
    /* Use default. */
    if(tap) {
      strcpy(tundev, "tap0");
    } else {
      strcpy(tundev, "tun0");
    }
  }
  
  if(host != NULL) {//creat tunnel via network interface
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if(port == NULL) {
      port = "60001";
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
      err(1, "getaddrinfo: %s", gai_strerror(rv));
    }

    /* loop through all the results and connect to the first we can */
    for(p = servinfo; p != NULL; p = p->ai_next) {
      if((slipfd = socket(p->ai_family, p->ai_socktype,
                          p->ai_protocol)) == -1) {
        perror("client: socket");
        continue;
      }

      if(connect(slipfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(slipfd);
        perror("client: connect");
        continue;
      }
      break;
    }

    if(p == NULL) {
      err(1, "can't connect to ``%s:%s''", host, port);
    }

    fcntl(slipfd, F_SETFL, O_NONBLOCK);

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof(s));
    fprintf(stderr, "slip connected to ``%s:%s''\n", s, port);

    /* all done with this structure */
    freeaddrinfo(servinfo);

  } 
  else {//creat tunnel via other native devices(.e.g usb interface, serial interface)
    if(siodev != NULL) {
      slipfd = devopen(siodev, O_RDWR | O_NONBLOCK);
      if(slipfd == -1) {
				err(1, "can't open siodev ``/dev/%s''", siodev);
      }
    } 
    else {
      static const char *siodevs[] = {
        "ttyUSB0", "cuaU0", "ucom0" /* linux, fbsd6, fbsd5 */
      };
      int i;
      for(i = 0; i < 3; i++) {
        siodev = siodevs[i];
        slipfd = devopen(siodev, O_RDWR | O_NONBLOCK);
        if(slipfd != -1) {
          break;
        }
      }
      if(slipfd == -1) {
        err(1, "can't open siodev");
      }
    }
	
    if (timestamp) stamptime();
	
    fprintf(stderr, "********SLIP started on ``/dev/%s''\n", siodev);
    stty_telos(slipfd);
  }
  
  slip_send(slipfd, SLIP_END);
  inslip = fdopen(slipfd, "r");
  if(inslip == NULL) err(1, "main: fdopen");

  tunfd = tun_alloc(tundev, tap);
  if(tunfd == -1) err(1, "main: open");
  
  if (timestamp) stamptime();
  
  fprintf(stderr, "opened %s device ``/dev/%s''\n",
          tap ? "tap" : "tun", tundev);
  
  //enable ipv6 packet forwarding function
 ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
  
  atexit(cleanup);
  signal(SIGHUP, sigcleanup);
  signal(SIGTERM, sigcleanup);
  signal(SIGINT, sigcleanup);
  signal(SIGALRM, sigalarm);
  ifconf(tundev, ipaddr);




 //=================================================================
 //.bref: start---creat pthread processing client ipv4 connection request
 //=================================================================
 pthread_create(&thread_do[0],		
			NULL,			
			handle_connect4,	
			NULL);
  pthread_create(&thread_do[1],		
			NULL,			
			sniffer_connect,	
			NULL);
  //-----------------------------
  //add : 20140817
  pthread_create(&thread_do[2],		
			NULL,			
			handle_pcbms_connect4,	
			NULL);
  pthread_create(&thread_do[3],		
			NULL,			
			handle_mpbms_connect4,	
			NULL);
  //end add.
  
  pthread_create(&thread_do[4],		
			NULL,			
			handle_adaptor_connect4,	
			NULL);
  
   pthread_create(&thread_do[5],		
			NULL,			
			opcuaServerRoutine,	
			NULL);
   sleep(5);
  //-----------------------------
 //=================================================================
 //.bref: end---creat pthread processing client ipv4 connection request
 //=================================================================

  while(1) {
	struct timeval timeout;
	timeout.tv_sec = 5;   
	timeout.tv_usec = 0;  
    maxfd = 0;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

/* do not send IPA all the time... - add get MAC later... */
/*     if(got_sigalarm) { */
/*       /\* Send "?IPA". *\/ */
/*       slip_send(slipfd, '?'); */
/*       slip_send(slipfd, 'I'); */
/*       slip_send(slipfd, 'P'); */
/*       slip_send(slipfd, 'A'); */
/*       slip_send(slipfd, SLIP_END); */
/*       got_sigalarm = 0; */
/*     } */


    if(!slip_empty() ) {	/* Anything to flush? */
      FD_SET(slipfd, &wset);
    }

    /* We only have one packet at a time queued for slip output. */
    if(slip_empty()) {
      FD_SET(tunfd, &rset);
      if(tunfd > maxfd) maxfd = tunfd;
    }
	
    if(slip_empty() && s_c4 !=-1) {
       FD_SET(s_c4, &rset);
      if(s_c4 > maxfd) maxfd = s_c4;
    }
	//-----------------------------
	//add : 20140817
    if(slip_empty() && pcs_c4 !=-1) {
       FD_SET(pcs_c4, &rset);
      if(pcs_c4 > maxfd) maxfd = pcs_c4;
    }
	
    if(slip_empty() && mps_c4 !=-1) {
       FD_SET(mps_c4, &rset);
      if(mps_c4 > maxfd) maxfd = mps_c4;
    }
	//end add : 20140817
    if(slip_empty() && adaptors_c4 !=-1) {
       FD_SET(adaptors_c4, &rset);
      if(adaptors_c4 > maxfd) maxfd = adaptors_c4;
    }
	//-----------------------------
	
    if(slip_empty() && sock_sniffer_client!=-1) {
       FD_SET(sock_sniffer_client, &rset);
      if(sock_sniffer_client > maxfd) maxfd = sock_sniffer_client;
    }	
	
    FD_SET(slipfd, &rset);	/* Read from slip ASAP! */
    if(slipfd > maxfd) maxfd = slipfd;
    

    //ret = select(maxfd + 1, &rset, &wset, NULL, NULL);
    ret = select(maxfd + 1, &rset, &wset, NULL, &timeout);
    if(ret == -1 && errno != EINTR) {
      err(1, "select");
    } 
    else if(ret > 0) {//read data from slip interface
      if(FD_ISSET(slipfd, &rset)) {
        serial_to_otherfd(inslip, tunfd, mosq,TOPIC);

      }
      
      if(FD_ISSET(slipfd, &wset)) {
				slip_flushbuf(slipfd);
				sigalarm_reset();
      }
 
      /* Optional delay between outgoing packets */
      /* Base delay times number of 6lowpan fragments to be sent */
      if(delaymsec) {
       struct timeval tv;
       int dmsec;
       gettimeofday(&tv, NULL) ;
       dmsec=(tv.tv_sec-delaystartsec)*1000+tv.tv_usec/1000-delaystartmsec;
       if(dmsec<0) delaymsec=0;
       if(dmsec>delaymsec) delaymsec=0;
      }
	  
      if(delaymsec==0) {
        int size;
        if(slip_empty() && FD_ISSET(tunfd, &rset)) {//tun--to--serial
          size=tun_to_serial(tunfd, slipfd);		//test6
          slip_flushbuf(slipfd);
          sigalarm_reset();
          if(basedelay) {
            struct timeval tv;
            gettimeofday(&tv, NULL) ;
 //         delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
            delaymsec=basedelay;
            delaystartsec =tv.tv_sec;
            delaystartmsec=tv.tv_usec/1000;
          }
        }
	
		if(s_c4 != -1){
	    	if(slip_empty() && FD_ISSET(s_c4, &rset)) {//socket--to--serial
	            size=bdrtfd_to_serial(s_c4, slipfd);
		    	if(0==size){ 
					s_c4=-1;
					sc4flg = 0;
		    	}
	            else{
					sc4flg = 1;
					slip_flushbuf(slipfd);
	                sigalarm_reset();
	                if(basedelay) {
	                   struct timeval tv;
	                   gettimeofday(&tv, NULL) ;
					   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
	                   delaymsec=basedelay;
	                   delaystartsec =tv.tv_sec;
	                   delaystartmsec=tv.tv_usec/1000;
		        	}
	        	}
	        }
		}
	
		//----add 20140817 for tr069 and background managment software------
		if(pcs_c4 != -1){
        	if(slip_empty() && FD_ISSET(pcs_c4, &rset)) {//socket--to--serial
            	size=bdrtfd_to_serial(pcs_c4, slipfd);
	    		if(0==size){ 
					pcs_c4=-1;
					pcsc4flg = 0;
	    		}
            	else{
					pcsc4flg = 1;
					slip_flushbuf(slipfd);
                	sigalarm_reset();
                	if(basedelay) {
                		struct timeval tv;
                		gettimeofday(&tv, NULL) ;
      					//delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
                	   	delaymsec=basedelay;
                   		delaystartsec =tv.tv_sec;
                   		delaystartmsec=tv.tv_usec/1000;
	        		}
            	}
        	}
		}

	
		if(mps_c4 != -1){
        	if(slip_empty() && FD_ISSET(mps_c4, &rset)) {//socket--to--serial
	            size=bdrtfd_to_serial(mps_c4, slipfd);
		    	if(0==size){ 
					mps_c4=-1;
					mpsc4flg = 0;
		    	}
	            else{
					mpsc4flg = 1;
					slip_flushbuf(slipfd);
	                sigalarm_reset();
	                if(basedelay) {
	                   struct timeval tv;
	                   gettimeofday(&tv, NULL) ;
	      			   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
	                   delaymsec=basedelay;
	                   delaystartsec =tv.tv_sec;
	                   delaystartmsec=tv.tv_usec/1000;
		        	}
	            }
			}
		}
	//----end add 20140817 for tr069 and background managment software------

	
	if(adaptors_c4 != -1){
		if(slip_empty() && FD_ISSET(adaptors_c4, &rset)) {//socket--to--serial
			size=bdrtfd_to_serial(adaptors_c4, slipfd);
			if(0==size){ 
				adaptors_c4=-1;
				adaptorsc4flg = 0;
			}
			else{
				adaptorsc4flg = 1;
				slip_flushbuf(slipfd);
				sigalarm_reset();
				if(basedelay) {
				   struct timeval tv;
				   gettimeofday(&tv, NULL) ;
				   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
				   delaymsec=basedelay;
				   delaystartsec =tv.tv_sec;
				   delaystartmsec=tv.tv_usec/1000;
				}
			}
		}
	}



	if(sock_sniffer_client!= -1){
          if(slip_empty() && FD_ISSET(sock_sniffer_client, &rset)) {//socket--to--serial
            size=sniffd_to_serial(sock_sniffer_client, slipfd);
	    if(0==size){ 
		sock_sniffer_client=-1;
	    }
            else{
		slip_flushbuf(slipfd);
                sigalarm_reset();
                if(basedelay) {
                   struct timeval tv;
                   gettimeofday(&tv, NULL) ;
      //         delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
                   delaymsec=basedelay;
                   delaystartsec =tv.tv_sec;
                   delaystartmsec=tv.tv_usec/1000;
	        }
            }
          }
	}
      }
    }
  }

}

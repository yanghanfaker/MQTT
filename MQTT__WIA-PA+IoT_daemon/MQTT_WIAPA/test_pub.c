#include <stdio.h>
#include <stdlib.h>
#include "mosquitto.h"
#include <string.h>
#include <sys/stat.h>
#include "cJSON.h"

//#define HOST "broker.emqx.io"
//#define PORT  1883

#define KEEP_ALIVE 60
#define MSG_MAX_SIZE  512
 
bool session = true;


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

int main()
{
    
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
    

    printf("port:%d\n",PORT);
    printf("site:%s\n",HOST);

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
    while(fgets(buff, MSG_MAX_SIZE, stdin) != NULL)
    {
                /*发布消息*/
                mosquitto_publish(mosq,NULL,"yanghan",strlen(buff)+1,buff,0,0);
                memset(buff,0,sizeof(buff));
    }
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    /*记得释放相关内存*/
    cJSON_Delete(pJson);
    pJson = NULL;

    return 0;
}

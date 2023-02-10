#CC = mipsel-openwrt-linux-gcc
CC=gcc
#CC = arm-linux-gcc
TARGET = iot_daemon_opcua
OBJS = iot_daemon.o socket.o open62541.o
CFLAGS = -D_REENTRANT -DDEBUG -DDEBUG_PRINT -g -Wall  -std=gnu99
#CFLAGS = -D_REENTRANT -DDEBUG -g -Wall 
RM = rm -f

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -lpthread -lmosquitto -lcjson

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) $(TARGET) $(OBJS)

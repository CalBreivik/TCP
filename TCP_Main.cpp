#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <windows.h>
#include <string>
#include "TCP_Header.h"
#include "TCP_Config.h"
using namespace std;

//解决LNK2019错误
#pragma comment(lib,"ws2_32.lib")

SOCKET TCP_S;
char *Auth_Info = NULL;
char *IP = NULL;
char *Port = NULL;
extern FILE *fp;

int main(int argc, char *argv[])
{
	HANDLE Heart_Signal_Thread;
	unsigned         Thread_ID;
	INT                    ret;
	bool         bflag = false;
	printf("软件版本为:%d.%d\n", TCP_VERSION_MAJOR, TCP_VERSION_MINOR);
	if(Read_Configure_Info())	
	{}
	else
	{
		if(argc == 6)
		{
			IP = (char *)malloc(sizeof(char)*(strlen(argv[1])+1));
			if(IP)
			{
				memset(IP,0,sizeof(char)*(strlen(argv[1])+1));
				memcpy(IP,argv[1],strlen(argv[1]));
			}
			else
			{
				printf("获取命令行参数IP时内存分配失败,下面采用默认参数！\n");
				goto loop;
			}
			Port = (char *)malloc(sizeof(char)*(strlen(argv[2])+1));
			if(Port)
			{
				memset(Port,0,sizeof(char)*(strlen(argv[2])+1));
				memcpy(Port,argv[2],strlen(argv[2]));
			}
			else
			{
				printf("获取命令行参数端口时内存分配失败,下面采用默认参数！\n");
				IP = NULL;
				goto loop;
			}
			bflag = Auth_Info_Fun(argv[3],argv[4],argv[5]);
			if(!bflag)
			{
				IP = NULL;
				Port = NULL;
			}
		}
		if(argc == 4)
		{
			Auth_Info_Fun(argv[1],argv[2],argv[3]);
		}
		if(argc == 3)
		{
			IP = (char *)malloc(sizeof(char)*(strlen(argv[1])+1));
			if(IP)
			{
				memset(IP,0,sizeof(char)*(strlen(argv[1])+1));
				memcpy(IP,argv[1],strlen(argv[1]));
			}
			else
			{
				printf("获取命令行参数IP时内存分配失败,下面采用默认参数！\n");
				goto loop;
			}
			Port = (char *)malloc(sizeof(char)*(strlen(argv[2])+1));
			if(Port)
			{
				memset(Port,0,sizeof(char)*(strlen(argv[2])+1));
				memcpy(Port,argv[2],strlen(argv[2]));
			}
			else
			{
				printf("获取命令行参数端口时内存分配失败,下面采用默认参数！\n");
				IP = NULL;
				goto loop;
			}
		}
	}
loop:	Print_Log();
	TCP_S = SocketConnect(IP, Port);
	if(Auth_Info == NULL)
	{
		//char *Send_Data = "*116439#0123456789qazwsxedc#v1_9*";
		char *Send_Data = "*116439#QJ0001805000002#v1_9*";
		int bytes = send(TCP_S, Send_Data, strlen(Send_Data), 0);
		if(fp)
		{
			fprintf(fp,"鉴权信息为:%s\n",Send_Data);
		}
	}
	else
	{
		int bytes = send(TCP_S, Auth_Info, strlen(Auth_Info), 0);
		if(fp)
		{
			fprintf(fp,"鉴权信息为:%s\n",Auth_Info);
		}
	}
	char Recv_Data[1024];
	memset(Recv_Data, 0, sizeof(Recv_Data));
	ret = recv(TCP_S, Recv_Data, 1024, 0);
	if (ret > 0)
	{
		Recv_Data[0] -= 32;
		printf("%s\n",Recv_Data);
		if(fp)
		{
			fprintf(fp,"接收的信息为:%s\n",Recv_Data);
		}
	}
	if(fp)
	{
		fclose(fp);
		fp = NULL;
	}
	Heart_Signal_Thread = (HANDLE)_beginthreadex(NULL, 0, &SendHeartSignalThreadFunc, NULL, 0, &Thread_ID);
	WaitForSingleObject(Heart_Signal_Thread, INFINITE);
	system("pause");
	if(IP)
	{
		free(IP);
	}
	if(Port)
	{
		free(Port);
	}
	if(Auth_Info)
	{
		free(Auth_Info);
	}
	shutdown(TCP_S, SD_BOTH);
	closesocket(TCP_S);
	WSACleanup();
	return(0);
}

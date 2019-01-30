#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>
#include <windows.h>
#include <string>
#include "TCP_Header.h"
using namespace std;
/*
 解决LNK2019错误
 */
#pragma comment(lib,"ws2_32.lib")

extern SOCKET TCP_S;
extern char *Auth_Info;
extern char *IP;
extern char *Port;
//消息流水号
unsigned int News_SN = 1;
FILE *fp = NULL;
char   cpath[28] = {'\0'};
//HANDLE Thread_Mutex = NULL;
PSTR_ADD Cmd_Message, News_Headers, News_Bodys;
char *News_ID[] = {"0106","0109","010A",
                   "0200","0202","0203",
				   "0204","0205","0206",
				   "0207","0216"};
int News_Body_Lenth[] = { 9, 8, 8, 5, 5, 7, 11, 9, 2, 6, 16 };
char *Recv_News_ID[] = {"0306","0307","0400",
				        "0402","0403","0406",
				        "0407","8408"};

int hex2byte(char *dst, char *src) 
{
	while (*src) 
	{
		if (' ' == *src) 
		{
			src++;
			continue;
		}
		sscanf(src, "%02X", dst);
		src += 2;
		dst++;
	}
	return 0;
}

char *IntToHex(unsigned int Value, char *Src, int len)
{
	unsigned int i;
	int j;
	i = Value;
	j = len - 2;
	do
	{
		if (i % 16 >= 0 && i % 16 <= 9)
		{
			Src[j] = '0' + i % 16;
		}
		else
		{
			Src[j] = 'a' + i % 16 - 10;
		}
		j--;
		i /= 16;
	} while (i);
	return(Src);
}

int FileOP(bool flag, unsigned int *p)
{
	FILE *fp = NULL;
	fp = fopen("SaveData.txt", "r+");
	if (fp == NULL)
	{
		printf("打开文件失败，请检查文件是否存在！\n");
		return (-1);
	}
	if (flag)
	{
		if (*p > 65535)
		{
			fclose(fp);
			FILE *fp_1 = fopen("SaveData.txt", "w+");
			if (fp_1 == NULL)
			{
				printf("打开文件失败，请检查文件是否存在！\n");
				return (-1);
			}
			fclose(fp_1);
			unsigned int i = 1;
			FileOP(true, &i);
			return (1);
		}
		else
		{
			fseek(fp, 0, SEEK_SET);
			fprintf(fp, "%d", *p);
		}
	}
	else
	{
		fseek(fp, 0, SEEK_END);
		if (!ftell(fp))
		{
			printf("文件为空，请检查！\n");
		}
		else
		{
			rewind(fp);
			fscanf(fp, "%d", p);
		}
	}
	fclose(fp);
	return (0);
}

void Print_Log_Time(void)
{
	time_t Timestamp;
	struct  tm *Time;
	char *Week_Day[] = { "星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六" };
	time(&Timestamp);
	Time = localtime(&Timestamp);
	printf("%d-%02d-%02d", Time->tm_year + 1900, Time->tm_mon + 1, Time->tm_mday);
	printf(" %s %02d:%02d:%02d:", Week_Day[Time->tm_wday], Time->tm_hour, Time->tm_min, Time->tm_sec);
	if(fp)
	{
		fprintf(fp,"%d-%02d-%02d", Time->tm_year + 1900, Time->tm_mon + 1, Time->tm_mday);
		fprintf(fp," %s %02d:%02d:%02d:", Week_Day[Time->tm_wday], Time->tm_hour, Time->tm_min, Time->tm_sec);
	}
}

void Print_Log(void)
{
	char         ch;
	if(strlen(cpath) == 0)
	{
		time_t Timestamp;
		struct  tm *Time;
		time(&Timestamp);
		int  i, j, ivalue;
		int times = 1000;
		Time = localtime(&Timestamp);
		int itime[] = {Time->tm_mon + 1, Time->tm_mday, Time->tm_hour, Time->tm_min, Time->tm_sec};
		memset(cpath, 0, sizeof(cpath));
		cpath[0] = 'L';
		cpath[1] = 'o';
		cpath[2] = 'g';
		cpath[strlen(cpath)] = '-';
		ivalue = Time->tm_year + 1900;
		while(times != 0)
		{
			cpath[strlen(cpath)] = ivalue/times + 48;
			ivalue %= times;
			times /= 10;
		}
		for(i = 0; i < 5; i++)
		{
			cpath[strlen(cpath)] = '-';
			ivalue = itime[i];
			times = 10;
			while(times != 0)
			{
				cpath[strlen(cpath)] = ivalue/times + 48;
				ivalue %= times;
				times /= 10;
			}
		}
		cpath[strlen(cpath)] = '.';
		cpath[strlen(cpath)] = 'l';
		cpath[strlen(cpath)] = 'o';
		cpath[strlen(cpath)] = 'g';
	}
	fp = fopen(cpath, "a+");
	if(fp == NULL)
	{
		perror("文件打开失败！");
	}
}

bool String_match(char *str_src,char *str_dst)
{
	if((!str_src)||(!str_dst))
	{
		return (false);
	}
	while(*str_src)
	{
		if((*str_dst)!=(*str_src))
		{
			return (false);
		}
		str_src++;
		str_dst++;
	}
	return (true);
}

bool Read_Configure_Info(void)
{
	FILE         *fp = NULL;
	char    Str[50] = {'0'};
	char *s = "Effective=1";
	int               i = 0;
	int                iLen;
	bool      bflag = false;
	fp = fopen("Initialization.ini","r+");
	if(!fp)
	{
		return (false);
	}
	fgets(Str, 50, fp);
	if(String_match(s,Str))
	{
		if(!feof(fp))
		{
			memset(Str, 0, sizeof(Str));
			fgets(Str, 50, fp);
			while(Str[i] != '=')
			{
				i++;
			}
			IP = (char *)malloc(sizeof(char) * strlen(Str + i + 1));
			if(IP)
			{
				memset(IP, 0, strlen(Str + i + 1));
				memcpy(IP, Str + i + 1, strlen(Str + i + 1) - 1);
			}
			else
			{
				printf("内存分配失败！\n");
				fclose(fp);
				return (false);
			}
			if(!feof(fp))
			{
				memset(Str,0,sizeof(Str));
				i = 0;
				fgets(Str, 50, fp);
				while(Str[i] != '=')
				{
					i++;
				}
				Port = (char *)malloc(sizeof(char) * strlen(Str + i + 1));
				if(Port)
				{
					memset(Port , 0, strlen(Str + i + 1));
					memcpy(Port, Str + i + 1, strlen(Str + i + 1) - 1);
				}
				else
				{
					printf("内存分配失败！\n");
					fclose(fp);
					return (false);
				}
				if(!feof(fp))
				{
					do
					{
						memset(Str,0,sizeof(Str));
						i = 0;
						fgets(Str, 5, fp);
						while(Str[i] != '=' && Str[i] != '\0')
						{
							i++;
						}
						if(i < strlen(Str) - 1)
						{
							if (Str[strlen(Str) - 1] == '\n')
							{
								Auth_Info = (char *)malloc(sizeof(char) * strlen(Str + i) + 1);
								if(Auth_Info)
								{
									memset(Auth_Info, 0, strlen(Str + i) + 1);
									Auth_Info[0] = '*';
									memcpy(Auth_Info + 1, Str + i + 1, strlen(Str + i + 1) - 1);
								}
							}
							else
							{
								Auth_Info = (char *)malloc(sizeof(char) * strlen(Str + i) + 2);
								if(Auth_Info)
								{
									memset(Auth_Info, 0, strlen(Str + i) + 2);
									Auth_Info[0] = '*';
									memcpy(Auth_Info + 1, Str + i + 1, strlen(Str + i + 1));
								}
							}
							if(!Auth_Info)
							{
								printf("内存分配失败！\n");
								fclose(fp);
								return (false);
							}
						}
						else if(i == strlen(Str) - 1)
						{
							Auth_Info = (char *)malloc(sizeof(char) * 2);
							if(Auth_Info)
							{
								memset(Auth_Info, 0, 2);
								Auth_Info[0] = '*';
							}
							else
							{
								printf("内存分配失败！\n");
								fclose(fp);
								return (false);
							}
						}
						else
						{
							if(Auth_Info)
							{
								iLen = strlen(Auth_Info);
								if(Str[strlen(Str) - 1] == '\n')
								{
									Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str) + 1));
									if(Auth_Info)
									{
										memset(Auth_Info + iLen, 0, strlen(Str) + 1);
										memcpy(Auth_Info + iLen, Str, strlen(Str) - 1);
									}
								}
								else
								{
									Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str) + 2));
									if(Auth_Info)
									{
										memset(Auth_Info + iLen, 0, strlen(Str) + 2);
										memcpy(Auth_Info + iLen, Str, strlen(Str));
									}
								}
								if(!Auth_Info)
								{
									printf("内存分配失败！\n");
									fclose(fp);
									return (false);
								}
							}
						}
					}while((Str[strlen(Str) - 1] != '\n') && (!feof(fp)));	
					Auth_Info[strlen(Auth_Info)] = '#';
					if(!feof(fp))
					{
						do
						{
							memset(Str, 0, sizeof(Str));
							i = 0;
							fgets(Str, 5, fp);
							while(Str[i] != '=' && Str[i] != '\0')
							{
								i++;
							}
							iLen = strlen(Auth_Info);
							if(i < strlen(Str) - 1)
							{
								if (Str[strlen(Str) - 1] == '\n')
								{
									Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str + i)));
									if(Auth_Info)
									{
										memset(Auth_Info + iLen, 0, strlen(Str + i));
										memcpy(Auth_Info + iLen, Str + i + 1, strlen(Str + i + 1) - 1);
									}
								}
								else
								{
									Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str + i) + 1));
									if(Auth_Info)
									{
										memset(Auth_Info + iLen, 0, strlen(Str + i) + 1);
										memcpy(Auth_Info + iLen, Str + i + 1, strlen(Str + i + 1));
									}
								}
								if(!Auth_Info)
								{
									printf("内存分配失败！\n");
									fclose(fp);
									return (false);
								}
								bflag = true;
							}
							else if(i == strlen(Str) - 1)
							{
								bflag = true;
							}
							else
							{
								if(bflag)
								{
									if(Str[strlen(Str)-1] == '\n')
									{
										Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str) + 1));
										if(Auth_Info)
										{
											memset(Auth_Info + iLen, 0, strlen(Str) + 1);
											memcpy(Auth_Info + iLen, Str, strlen(Str) - 1);
										}
									}
									else
									{
										Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str) + 2));
										if(Auth_Info)
										{
											memset(Auth_Info + iLen, 0, strlen(Str) + 2);
											memcpy(Auth_Info + iLen, Str, strlen(Str));
										}
									}
									if(!Auth_Info)
									{
										printf("内存分配失败！\n");
										fclose(fp);
										return (false);
									}
								}
							}
						}while((Str[strlen(Str) - 1] != '\n') && (!feof(fp)));
						bflag = false;
						Auth_Info[strlen(Auth_Info)] = '#';
						if(!feof(fp))
						{
							do
							{
								memset(Str, 0, sizeof(Str));
								i = 0;
								fgets(Str, 5, fp);
								while(Str[i] != '=' && Str[i] != '\0')
								{
									i++;
								}
								iLen = strlen(Auth_Info);
								if(i < strlen(Str) - 1)
								{
									if(Str[strlen(Str) - 1] == '\n')
									{
										Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str + i)));
										if(Auth_Info)
										{
											memset(Auth_Info + iLen, 0, strlen(Str + i));
											memcpy(Auth_Info + iLen, Str + i + 1, strlen(Str + i + 1) - 1);
										}
									}
									else
									{
										Auth_Info = (char *)realloc((void *)Auth_Info, sizeof(char) * (iLen + strlen(Str + i) + 1));
										if(Auth_Info)
										{
											memset(Auth_Info + iLen, 0, strlen(Str + i) + 1);
											memcpy(Auth_Info + iLen, Str + i + 1, strlen(Str + i + 1));
										}
									}
									if(!Auth_Info)
									{
										printf("内存分配失败！\n");
										fclose(fp);
										return (false);
									}
									bflag = true;
								}
								else if(i == strlen(Str) - 1)
								{
									bflag = true;
								}
								else
								{
									if(bflag)
									{
										if(Str[strlen(Str) - 1] == '\n')
										{
											Auth_Info = (char *)realloc((void *)Auth_Info,  sizeof(char) * (iLen + strlen(Str) + 1));
											if(Auth_Info)
											{
												memset(Auth_Info + iLen, 0, strlen(Str) + 1);
												memcpy(Auth_Info + iLen, Str, strlen(Str) - 1);
											}
										}
										else
										{
											Auth_Info = (char *)realloc((void *)Auth_Info,  sizeof(char) * (iLen + strlen(Str) + 2));
											if(Auth_Info)
											{
												memset(Auth_Info + iLen, 0, strlen(Str) + 2);
												memcpy(Auth_Info + iLen, Str, strlen(Str));
											}
										}
										if(!Auth_Info)
										{
											printf("内存分配失败！\n");
											fclose(fp);
											return (false);
										}
									}
								}
							}while((Str[strlen(Str) - 1] != '\n') && (!feof(fp)));
							Auth_Info[strlen(Auth_Info)] = '*';
							bflag = false;
						}
					}
				}
			}
		}
		fclose(fp);
		return (true);
	}
	else
	{
		fclose(fp);
		return (false);
	}
}

bool Auth_Info_Fun(char *Pid, char *Pwd, char *Parse_Name)
{
	int Auth_Info_Len = 4;
	Auth_Info_Len += strlen(Pid) + strlen(Pwd) + strlen(Parse_Name);
	Auth_Info = (char *)malloc(sizeof(char)*(Auth_Info_Len+1));
	if(Auth_Info)
	{
		memset(Auth_Info,0,sizeof(char)*(Auth_Info_Len+1));
		Auth_Info[0] = '*';
		memcpy(Auth_Info+1,Pid,strlen(Pid));
		Auth_Info[strlen(Pid)+1] = '#'; 
		memcpy(Auth_Info+2+strlen(Pid),Pwd,strlen(Pwd));
		Auth_Info[2+strlen(Pid)+strlen(Pwd)] = '#';
		memcpy(Auth_Info+3+strlen(Pid)+strlen(Pwd),Parse_Name,strlen(Parse_Name));
		Auth_Info[Auth_Info_Len-1] = '*';
		printf("鉴权信息为:%s\n",Auth_Info);
		return (true);
	}
	else
	{
		printf("获取命令行参数鉴权信息时内存分配失败,下面将使用默认参数！\n");
		return (false);
	}
}

char Xor(char *news_data, int len)
{
	char Char_Xor = '\x00';
	int  i;
	for (i = 0; i < len; i++)
	{
		Char_Xor ^= news_data[i];
	}
	return(Char_Xor);
}

int len(char *data, int len)
{
	int i,char_num = 0;
	for (i = 0; i<len; i++)
	{
		if (data[i] == '\x7e' || data[i] == '\x7d')
		{
			char_num += 2;
		}
		else
		{
			char_num += 1;
		}
	}
	return(char_num);
}

void Free_Memory(PSTR_ADD P_Malloc_Struct)
{
	if(P_Malloc_Struct)
	{
		free(P_Malloc_Struct->str);
		P_Malloc_Struct->str = NULL;
		free(P_Malloc_Struct);
		P_Malloc_Struct = NULL;
	}
}

int Str_Cat(PSTR_ADD dst_str, PSTR_ADD src_str)
{
	int i;
	if (src_str&&dst_str)
	{
		if (src_str->str&&dst_str->str)
		{
			for (i = 0; i < src_str->len; i++)
			{
				if (src_str->str[i] == '\x7e')
				{
					dst_str->str[dst_str->len + i] = '\x7d';
					dst_str->str[dst_str->len + i + 1] = '\x02';
					dst_str->len += 1;
				}
				else if (src_str->str[i] == '\x7d')
				{
					dst_str->str[dst_str->len + i] = '\x7d';
					dst_str->str[dst_str->len + i + 1] = '\x01';
					dst_str->len += 1;
				}
				else
				{
					dst_str->str[dst_str->len + i] = src_str->str[i];
				}
			}
			dst_str->len += i;
		}
		else
		{
			if (!src_str->str)
			{
				printf("源结构体成员地址无效\n");
			}
			else
			{
				printf("目标结构体成员地址无效\n");
			}
			return(0);
		}
	}
	else
	{
		if(!src_str)
		{
			printf("源地址无效\n");
		}
		else
		{
			printf("目标地址无效\n");
		}
		return(0);
	}
	return(i);
}

PSTR_ADD News_Header(char* News_Id, int News_Body_Len)
{
	time_t   Timestamp;
	unsigned int k = 0;
	int i;
	News_Headers = (PSTR_ADD)malloc(sizeof(STR_ADD));
	News_Headers->str = (char *)malloc(sizeof(char)*11);
	News_Headers->len = 10;
	memset(News_Headers->str,0,11);
	for(i=0;i<strlen(News_Id);i++)
	{
		if(News_Id[i]<58)
		{
			if(i%2==0)
			{
				News_Headers->str[i/2] = News_Id[i]-48<<4;
			}
			else
			{
				News_Headers->str[i/2] |= News_Id[i]-48;
			}
		}
		else if(News_Id[i]<71)
		{
			if(i%2==0)
			{
				News_Headers->str[i/2] = News_Id[i]-65+10<<4;
			}
			else
			{
				News_Headers->str[i/2] |= News_Id[i]-65+10;
			}
		}
		else
		{
			if(i%2==0)
			{
				News_Headers->str[i/2] = News_Id[i]-97+10<<4;
			}
			else
			{
				News_Headers->str[i/2] |= News_Id[i]-97+10;
			}
		}
	}
	News_Headers->str[2] = News_Body_Len>>8;
	News_Headers->str[3] = News_Body_Len;
	FileOP(false, &k);
	if ((k > News_SN)||(News_SN > 65535))
	{
		News_SN = k;
	}
	News_Headers->str[4] = News_SN>>8;
	News_Headers->str[5] = News_SN;
	News_SN++;
	FileOP(true, &News_SN);
	time(&Timestamp);
	News_Headers->str[6] = Timestamp>>24;
	News_Headers->str[7] = Timestamp>>16;
	News_Headers->str[8] = Timestamp>>8;
	News_Headers->str[9] = Timestamp;
	printf("News_Headers:");
	for(i = 0; i < News_Headers->len; i++)
	{
		printf("%02x ",(unsigned char)News_Headers->str[i]);
	}
	printf("\n");
	return(News_Headers);
}

PSTR_ADD News_Body(int CMD_ID)
{
	time_t Timestamp;
	int Mileage,i,j;
	float Lat,Lon;
	if(CMD_ID<=10&&CMD_ID>=0)
	{
		News_Bodys = (PSTR_ADD)malloc(sizeof(STR_ADD));
		News_Bodys->str = (char *)malloc(sizeof(char)*(News_Body_Lenth[CMD_ID]+1));
		News_Bodys->len =  News_Body_Lenth[CMD_ID];
		memset(News_Bodys->str,0,News_Body_Lenth[CMD_ID]+1);
		srand((int)time(NULL));
	}
	else
	{
		printf("消息ID越界！\n");
		return(NULL);
	}
	switch(CMD_ID)
	{
		case 0:
		{
			News_Bodys->str[0] = (rand()%100)+1;
			News_Bodys->str[1] = (rand()%254)+1;
			News_Bodys->str[2] = (rand()%254)+1;
			News_Bodys->str[3] = (rand()%254)+1;
			Mileage = rand()%16777215;
			News_Bodys->str[4] = Mileage>>16;
			News_Bodys->str[5] = Mileage>>8;
			News_Bodys->str[6] = Mileage;
			News_Bodys->str[7] = rand()%2;
			News_Bodys->str[8] = rand()%181;
			break;
		}
		case 1:
		{
			i = rand()%3+1;
			News_Bodys->str[0] = i<<4;
			if(i == 3)
			{
				j = rand()%7;
				News_Bodys->str[0] |= j;
			}
			News_Bodys->str[1] = 1;
			for(i = 1;i<=j;i++)
			{
				switch(i)
				{
					case 1:
					{
						News_Bodys->str[1+i] = rand()%101;
						break;
					}
					case 2:
					{
						News_Bodys->str[1+i] = rand()%31;
						break;
					}
					case 3:
					{
						News_Bodys->str[1+i] = rand()%2;
						break;
					}
					case 4:
					{
						News_Bodys->str[1+i] = rand()%3+1;
						break;
					}
					case 5:
					{
						News_Bodys->str[1+i] = rand()%3+1;
						break;
					}
					case 6:
					{
						News_Bodys->str[1+i] = rand()%2;
						break;
					}
					default:
					{
						break;
					}
				}
			}
			break;
		}
		case 2:
		{
			News_Bodys->str[0] = rand()%100+1;
			News_Bodys->str[1] = rand()%30+1;
			News_Bodys->str[2] = rand()%3+1;
			News_Bodys->str[2] |= (rand()%3+1)<<3;
			News_Bodys->str[2] |= rand()%2<<6;
			News_Bodys->str[2] |= rand()%3<<7;
			break;
		}
		case 3:
		{
			i = rand()%8;
			for(j=0;j<strlen(Recv_News_ID[i]);j++)
			{
				if(Recv_News_ID[i][j]<58)
				{
					if(j%2==0)
					{
						News_Bodys->str[j/2] = Recv_News_ID[i][j]-48<<4;
					}
					else
					{
						News_Bodys->str[j/2] |= Recv_News_ID[i][j]-48;
					}
				}
				else if(Recv_News_ID[i][j]<71)
				{
					if(j%2==0)
					{
						News_Bodys->str[j/2] = Recv_News_ID[i][j]-65+10<<4;
					}
					else
					{
						News_Bodys->str[j/2] |= Recv_News_ID[i][j]-65+10;
					}
				}
				else
				{
					if(j%2==0)
					{
						News_Bodys->str[j/2] = Recv_News_ID[i][j]-97+10<<4;
					}
					else
					{
						News_Bodys->str[j/2] |= Recv_News_ID[i][j]-97+10;
					}
				}
			}
			i = rand()%65536;
			News_Bodys->str[j/2] = i>>8;
			News_Bodys->str[j/2+1] = i;
			News_Bodys->str[j/2+2] = rand()%4;
			break;
		}
		case 4:
		{
			News_Bodys->str[0] = rand()%256;
			Mileage = rand()%3601;
			News_Bodys->str[1] = Mileage>>8;
			News_Bodys->str[2] = Mileage;
			News_Bodys->str[3] = rand()%100;
			News_Bodys->str[4] = rand()%8;
			break;
		}
		case 5:
		{
			Mileage = rand()%65535+1;
			News_Bodys->str[0] = Mileage>>8;
			News_Bodys->str[1] = Mileage;
			News_Bodys->str[2] = rand()%256;
			News_Bodys->str[3] = rand()%256;
			News_Bodys->str[4] = rand()%256;
			News_Bodys->str[5] = rand()%2;
			News_Bodys->str[6] = rand()%2;
			break;
		}
		case 6:
		{
			News_Bodys->str[0] = rand()%181;
			News_Bodys->str[1] = rand()%4;
			Mileage = rand()%181;
			News_Bodys->str[2] = Mileage>>8;
			News_Bodys->str[3] = Mileage;
			Mileage = rand()%181;
			News_Bodys->str[4] = Mileage>>8;
			News_Bodys->str[5] = Mileage;
			Mileage = rand()%181;
			News_Bodys->str[6] = Mileage>>8;
			News_Bodys->str[7] = Mileage;
			News_Bodys->str[8] = rand()%256;
			News_Bodys->str[9] = rand()%256;
			News_Bodys->str[10] = rand()%256;
			break;
		}
		case 7:
		{
			News_Bodys->str[0] = rand()%8;
			Lon = rand()/(float)(RAND_MAX/90.0);
			printf("Lon:%f\n",Lon); 
			memcpy(News_Bodys->str+1,&Lon,sizeof(float));
			Lat = rand()/(float)(RAND_MAX/180.0);
			printf("Lat:%f\n",Lat);
			memcpy(News_Bodys->str+1+sizeof(float),&Lat,sizeof(float));
			break;
		}
		case 8:
		{
			News_Bodys->str[0] = rand()%2;
			News_Bodys->str[0] |= (rand()%3+1)<<1;
			News_Bodys->str[0] |= (rand()%2)<<3;
			News_Bodys->str[0] |= (rand()%2+1)<<4;
			News_Bodys->str[0] |= (rand()%2)<<6;
			News_Bodys->str[1] = rand()%2+1;
			break;
		}
		case 9:
		{
			News_Bodys->str[0] = rand()%129;
			Mileage = rand()%3601;
			News_Bodys->str[1] = Mileage>>8;
			News_Bodys->str[2] = Mileage;
			News_Bodys->str[3] = rand()%101;
			News_Bodys->str[2] = rand()%8;
			News_Bodys->str[2] = rand()%2;
			break;
		}
		case 10:
		{
			for(i=0;i<16;i++)
			{
				News_Bodys->str[i] = rand()%128;
			}
			break;
		}
		default:
		{
			printf("消息越界！\n");
		}
	}
	printf("News_Bodys:");
	for(i = 0; i < News_Bodys->len; i++)
	{
		printf("%02x ",(unsigned char)News_Bodys->str[i]);
	}
	printf("\n");
	return(News_Bodys);
}

void Cmd_Packet(PSTR_ADD Header, PSTR_ADD Body)
{
	int Cmd_Len = 2;
	char Check_Code;
	PSTR_ADD Cmd_Header,Cmd_Body;
	Cmd_Header = Header;
	Cmd_Body = Body;
	Check_Code = Xor(Cmd_Header->str,Cmd_Header->len);
	Check_Code ^=Xor(Cmd_Body->str,Cmd_Body->len);
	printf("Check_Code:%02x\n",(unsigned char)Check_Code);
	Cmd_Len += len(Cmd_Header->str,Cmd_Header->len);
	Cmd_Len += len(Cmd_Body->str,Cmd_Body->len);
	Cmd_Len += len(&Check_Code,1);
	Cmd_Message = (PSTR_ADD)malloc(sizeof(STR_ADD));
	Cmd_Message->str = (char *)malloc(sizeof(char)*(Cmd_Len+1));
	memset(Cmd_Message->str,0,sizeof(char)*(Cmd_Len+1));
	Cmd_Message->str[0] = '\x7e'; 
	Cmd_Message->len = 1;
	Str_Cat(Cmd_Message,Header);
	Str_Cat(Cmd_Message,Body);
	if(Check_Code == '\x7e')
	{
		Cmd_Message->str[Cmd_Message->len] = '\x7d';
		Cmd_Message->str[Cmd_Message->len+1] = '\x02';
		Cmd_Message->len += 2;
	}
	else if(Check_Code == '\x7d')
	{
		Cmd_Message->str[Cmd_Message->len] = '\x7d';
		Cmd_Message->str[Cmd_Message->len+1] = '\x01';
		Cmd_Message->len += 2;
	}
	else
	{
		Cmd_Message->str[Cmd_Message->len] = Check_Code;
		Cmd_Message->len++;
	}
	Cmd_Message->str[Cmd_Message->len] = '\x7e';
	Cmd_Message->len++;
	Free_Memory(News_Headers);
	Free_Memory(News_Bodys);
}

unsigned short StrTOShort(char *str_port)
{
	int U_Short_Port;
	bool  flag = false;
	while(*str_port)
	{
		if(flag)
		{
			U_Short_Port *= 10;
			U_Short_Port += (int)(*str_port)-48;
		}
		else
		{
			U_Short_Port = (int)(*str_port)-48;
			flag = true;
		}
		str_port++;
	}
	return((unsigned short)U_Short_Port);
}

SOCKET SocketConnect(char *ip,char *port)
{
	SOCKET      TCP_Client;
	WSADATA        wsaData;
	INT                ret;
	unsigned short    Port;
	//int Recv_Timeout = 240000;
	if (ret = WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Winsock DLL 加载失败,错误代码为：%d\n", ret);
		return(0);
	}
	TCP_Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (TCP_Client == INVALID_SOCKET)
	{
		printf("创建套接字失败！");
		return(0);
	}
	//setsockopt(TCP_Client, SOL_SOCKET, SO_RCVTIMEO, (char *)&Recv_Timeout ,sizeof(int));
	SOCKADDR_IN Cli_Addr;
	Cli_Addr.sin_family = AF_INET;
	if(ip == NULL||port == NULL)
	{
		Cli_Addr.sin_port = htons(1811);
		Cli_Addr.sin_addr.S_un.S_addr = inet_addr("183.230.40.40");
		if(fp)
		{
			fprintf(fp,"IP地址为:183.230.40.40\n端口为:1811\n");
		}
	}
	else
	{
		Port = StrTOShort(port);
		Cli_Addr.sin_port = htons(Port);
		Cli_Addr.sin_addr.S_un.S_addr = inet_addr(ip);
		printf("IP为:%s\n端口为:%d\n",ip,(int)Port);
		if(fp)
		{
			fprintf(fp,"IP为:%s\n端口为:%d\n",ip,(int)Port);
		}
	}
	int TCP_Connect;
	TCP_Connect = connect(TCP_Client, (sockaddr *)&Cli_Addr, sizeof(Cli_Addr));
	if (TCP_Connect == SOCKET_ERROR)
	{
		printf("链接失败！");
		return(0);
	}
	return (TCP_Client);
}

unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments)
{
	INT                ret,bytes;
	char         Recv_Data[1024];
	int                   CMD_ID;
	Print_Log();
	Print_Log_Time();
	printf("发送消息线程已启动！\n");
	if(fp)
	{
		fprintf(fp, "发送消息线程已启动！\n");
		fclose(fp);
		fp = NULL;
	}
	while (1)
	{
		Sleep(60000);
		srand((unsigned int)time(NULL));
		CMD_ID = rand()%11;
		News_Header(News_ID[CMD_ID], News_Body_Lenth[CMD_ID]);
		News_Body(CMD_ID);
		Cmd_Packet(News_Headers, News_Bodys);
		Print_Log();
		Print_Log_Time();
		if(fp)
		{
			fprintf(fp, "发送%d字节信息\n", Cmd_Message->len);
			fprintf(fp, "发送信息内容为:");
		}
		printf("\nCmd_Packet:");
		for(CMD_ID = 0; CMD_ID <Cmd_Message->len; CMD_ID++)
		{
			printf("%02x ",(unsigned char)Cmd_Message->str[CMD_ID]);
			if(fp)
			{
				fprintf(fp,"%02x ",(unsigned char)Cmd_Message->str[CMD_ID]);
			}
		}
		if(fp)
		{
			fprintf(fp,"\n");
		}
		printf("\nCmd_Packet_len:%d\n套接字为:%d\n",Cmd_Message->len,(int)TCP_S);
		bytes = send(TCP_S, Cmd_Message->str, Cmd_Message->len, 0);
		Free_Memory(Cmd_Message);
		printf("发送%d字节\n", bytes);
		ret = recv(TCP_S, Recv_Data, 1024, 0);
		if (ret > 0)
		{
			Print_Log_Time();
			if(fp)
			{
				fprintf(fp, "收到%d字节信息\n", ret);
				fprintf(fp, "收到信息内容为:");
			}
			printf("\n");
			for (int i = 0; i < ret; i++)
			{
				printf("%02x ", (unsigned char)Recv_Data[i]);
				if(fp)
				{
					fprintf(fp, "%02x ", (unsigned char)Recv_Data[i]);
				}
			}
			if(fp)
			{
				fprintf(fp, "\n");
			}
			printf("\n");
		}
		else
		{
	loop:	Print_Log_Time();
			printf("\n");
			if(ret < 0)
			{
				printf("SOCKET_ERROR为：%d\n", WSAGetLastError());
				if(fp)
				{
					fprintf(fp, "SOCKET_ERROR为：%d\n", WSAGetLastError());
				}
			}
			else
			{
				printf("网络已中断！SOCKET_ERROR为：%d\n",WSAGetLastError());
				if(fp)
				{
					fprintf(fp, "网络已中断！SOCKET_ERROR为：%d\n",WSAGetLastError());
				}
			}
			shutdown(TCP_S, SD_BOTH);
			closesocket(TCP_S);
			Print_Log_Time();
			if(fp)
			{
				fprintf(fp, "开始重连\n");
			}
			TCP_S = SocketConnect(IP,Port);
			if(Auth_Info == NULL)
			{
				//char *Send_Data = "*116439#0123456789qazwsxedc#v1_9*";
				char *Send_Data = "*116439#QJ0001805000002#v1_9*";
				bytes = send(TCP_S, Send_Data, strlen(Send_Data), 0);
				if(fp)
				{
					fprintf(fp, "重连鉴权信息为:%s\n", Send_Data);
				}
			}
			else
			{
				bytes = send(TCP_S, Auth_Info, strlen(Auth_Info), 0);
				if(fp)
				{
					fprintf(fp, "重连鉴权信息为:%s\n", Auth_Info);
				}
			}
			memset(Recv_Data, 0, 1024);
			ret = recv(TCP_S, Recv_Data, 1024, 0);
			if(ret > 0)
			{
				Print_Log_Time();
				Recv_Data[0] -= 32;
				printf("%s\n", Recv_Data);
				if(fp)
				{
					fprintf(fp, "%s\n", Recv_Data);
				}
			}
			else 
			{
				goto loop;
			}
		}
		if(fp)
		{
			fclose(fp);
			fp = NULL;
		}
	}
	_endthreadex(0);
	return(0);
}

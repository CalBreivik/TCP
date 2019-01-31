/*
 *TCP_Header.h
 *TCP协议头文件
 *
 *本头文件包括本项目中需要使用的所有结构体和
 *函数
 *
 */
 
//#pragma once
 
#ifndef __TCP_HEADER_H__
#define __TCP_HEADER_H__

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

/*
 * 命令串表示结构体
 */
typedef struct Cat_String
{
	char *str;
	int   len;
}STR_ADD, *PSTR_ADD;

/*
 * 将两位十六进制数写入一个字节函数
 */
int hex2byte(char *dst, char *src);

/*
 * 将十进制数转换为十六进制数函数
 */
char *IntToHex(unsigned int Value, char *Src, int len);

/*
 * 文件操作函数
 */
int FileOP(bool flag, unsigned int *p);

/*
 * 日志时间打印函数
 */
void Print_Log_Time(void);

/*
 *打开日志文件函数
 */
void Print_Log(void);

/*
 *检查配置文件是否生效函数
 */
bool String_match(char *str_src,char *str_dst);

/*
 *读取配置文件函数
 */
bool Read_Configure_Info(void);

/*
 *生成鉴权消息函数
 */
bool Auth_Info_Fun(char *Pid, char *Pwd, char *Parse_Name);
 
/*
 * 实现异或功能函数
 */
char Xor(char *news_data, unsigned int len);

/*
 * 计算包长度函数
 */
unsigned int len(char *data, unsigned int len);

/*
 *内存释放
 */
void Free_Memory(PSTR_ADD P_Malloc_Struct);

/*
 * 拼接两段命令函数
 */
int Str_Cat(PSTR_ADD src_str, PSTR_ADD dst_str);

/*
 * 消息头生成函数
 */
PSTR_ADD News_Header(char* News_Id, int News_BL);

/*
 *消息体生成函数
 */

PSTR_ADD News_Body(int CMD_ID);
 
/*
 * 组包功能函数
 */
void Cmd_Packet(PSTR_ADD Header, PSTR_ADD Body);

/*
 *将字符串型的端口转换为短整型端口函数
 */
 unsigned short StrTOShort(char *str_port);

/*
 * 建立网络连接函数
 */
SOCKET SocketConnect(char *ip,char *port);

/*
 * 发送心跳包线程
 */
unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* __TCP_HEADER_H__ */

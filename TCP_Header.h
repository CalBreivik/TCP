/*
 *TCP_Header.h
 *TCPЭ��ͷ�ļ�
 *
 *��ͷ�ļ���������Ŀ����Ҫʹ�õ����нṹ���
 *����
 *
 */
 
//#pragma once
 
#ifndef __TCP_HEADER_H__
#define __TCP_HEADER_H__

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

/*
 * �����ʾ�ṹ��
 */
typedef struct Cat_String
{
	char *str;
	int   len;
}STR_ADD, *PSTR_ADD;

/*
 * ����λʮ��������д��һ���ֽں���
 */
int hex2byte(char *dst, char *src);

/*
 * ��ʮ������ת��Ϊʮ������������
 */
char *IntToHex(unsigned int Value, char *Src, int len);

/*
 * �ļ���������
 */
int FileOP(bool flag, unsigned int *p);

/*
 * ��־ʱ���ӡ����
 */
void Print_Log_Time(void);

/*
 *����־�ļ�����
 */
void Print_Log(void);

/*
 *��������ļ��Ƿ���Ч����
 */
bool String_match(char *str_src,char *str_dst);

/*
 *��ȡ�����ļ�����
 */
bool Read_Configure_Info(void);

/*
 *���ɼ�Ȩ��Ϣ����
 */
bool Auth_Info_Fun(char *Pid, char *Pwd, char *Parse_Name);
 
/*
 * ʵ������ܺ���
 */
char Xor(char *news_data, unsigned int len);

/*
 * ��������Ⱥ���
 */
unsigned int len(char *data, unsigned int len);

/*
 *�ڴ��ͷ�
 */
void Free_Memory(PSTR_ADD P_Malloc_Struct);

/*
 * ƴ�����������
 */
int Str_Cat(PSTR_ADD src_str, PSTR_ADD dst_str);

/*
 * ��Ϣͷ���ɺ���
 */
PSTR_ADD News_Header(char* News_Id, int News_BL);

/*
 *��Ϣ�����ɺ���
 */

PSTR_ADD News_Body(int CMD_ID);
 
/*
 * ������ܺ���
 */
void Cmd_Packet(PSTR_ADD Header, PSTR_ADD Body);

/*
 *���ַ����͵Ķ˿�ת��Ϊ�����Ͷ˿ں���
 */
 unsigned short StrTOShort(char *str_port);

/*
 * �����������Ӻ���
 */
SOCKET SocketConnect(char *ip,char *port);

/*
 * �����������߳�
 */
unsigned __stdcall SendHeartSignalThreadFunc(void* pArguments);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* __TCP_HEADER_H__ */

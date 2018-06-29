/*
*midleware.c
*Create on 5.21
*
**/
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define myport 5669 
#define BUFFER_LENGTH 1024
#define IDS_L 50+1
#define IDC_L 50+1
#define Random_L 16+1
#define doubleRandom_L 16*2+1//33
#define Hash_L 32+1
#define sendID_L 16+1
#define receiveID_L 16+1
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;


typedef struct
{
	short version;//0x01
	short XDcode;//0xA105
	short reqType;//0x12
	short authType;//0x02
	short step;//C-M 0x01;M-C 0x02
}PwAu_Header_CM,PwAu_Header_MC;

typedef struct {
	dword IDC_len;
	byte IDC[IDC_L];
	char HashPw[Hash_L];
}PwAu_Body_CM;

typedef struct {
	dword resultCode;
}PwAu_Body_MC;

/***
检查CPU大小端存储
return 1 大端0 小端
*/
int check_endian() {
	int i = 0x12345678;
	char *c = (char *)&(i);
	return (*c == 0x12);
}

//int 类型大小端转化
dword BLEndianUint32(dword value)
{
	return ((value & 0x000000FF) << 24) | ((value & 0x0000FF00) << 8) | ((value & 0x00FF0000) >> 8) | ((value & 0xFF000000) >> 24);
}
//short 类型大小端转化
unsigned short BLEndianUshort(unsigned short value)
{
	return ((value & 0x00FF) << 8) | ((value & 0xFF00) >> 8);
}

void Recv_PABCM(PwAu_Body_CM * p, char * buf) {
	memcpy(p, buf, sizeof(PwAu_Body_CM));
	if (!check_endian()) {
		p->IDC_len = BLEndianUshort(p->IDC_len);
	}
}

void Recv_PAHCM(PwAu_Header_CM * p, char * buf) {
	memcpy(p, buf, sizeof(PwAu_Header_CM));
	if (!check_endian()) {
		p->version = BLEndianUshort(p->version);
		p->XDcode = BLEndianUshort(p->XDcode);
		p->reqType = BLEndianUshort(p->reqType);
		p->authType = BLEndianUint32(p->authType);
		p->step = BLEndianUint32(p->step);
	}
}
void Send_PAHCM(PwAu_Header_CM * p, char * buf) {

	if (check_endian()) {
		memcpy(buf, p, sizeof(PwAu_Header_CM));
	}
	else
	{
		PwAu_Header_CM *tmp = (PwAu_Header_CM*)malloc(sizeof(PwAu_Header_CM));
		tmp->version = BLEndianUshort(p->version);
		tmp->XDcode = BLEndianUshort(p->XDcode);
		tmp->reqType = BLEndianUshort(p->reqType);
		tmp->authType = BLEndianUint32(p->authType);
		tmp->step = BLEndianUint32(p->step);
		memcpy(buf, tmp, sizeof(PwAu_Header_CM));
		free(tmp);
	}
}
void Send_PAHMC(PwAu_Header_MC * p, char * buf) {
	Send_PAHCM(p, buf);
}
void Send_PABMC(PwAu_Body_MC * p, char * buf) {

	if (check_endian()) {
		memcpy(buf, p, sizeof(PwAu_Body_MC));
	}
	else
	{
		PwAu_Body_MC *tmp = (PwAu_Body_MC*)malloc(sizeof(PwAu_Body_MC));
		tmp->resultCode = BLEndianUshort(p->resultCode);
		memcpy(buf, tmp, sizeof(PwAu_Body_MC));
		free(tmp);
	}
}
//初始化函数
PwAu_Header_MC Init_PAHMC(PwAu_Header_MC p) {
	p.version = '1';
	p.XDcode = 0xA105;
	p.reqType = 0x12;
	p.authType = 0x02;
	p.step = 0x02;
	return p;
}
PwAu_Body_MC Init_PABMC(PwAu_Body_MC p) {
	p.resultCode = 1;
	return p;
}


int main(int argc, char**argv) {
	int m_fd, c_fd;
	int ret;
	struct sockaddr_in m_addr, c_addr;

	m_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_fd<0) {
		printf("socket error!\n");
		return 0;
	}


	m_addr.sin_family = AF_INET;

	m_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	m_addr.sin_port = htons(myport);

	if (bind(m_fd, (struct sockaddr*)&m_addr, sizeof(m_addr))<0) {

		printf("bind error !\n");
		return 0;
	}
	//开始监听 

	if (listen(m_fd, 10) <0)
	{
		printf("listen error !\n");
		return 0;
	}

	//listen(m_fd,10);

	//循环接受数据
	while (1) {

		printf("等待连接。。。\n");

		int c_len = sizeof(c_addr);
		c_fd = accept(m_fd, (struct sockaddr*)&c_addr, &c_len);
		if (c_fd<0)
		{
			printf("accept error !\n");
			continue;
		}
		printf("接受到一个连接：\n");

		//接收数据
		char buf[BUFFER_LENGTH] = { 0 };
		//memset(buf,'\0',BUFFER_LENGTH);

		ret = recv(c_fd, buf, sizeof(buf), 0);
		PwAu_Header_CM pahcm;
		PwAu_Body_CM  pabcm;

		Recv_PAHCM(&pahcm, buf);
		Recv_PABCM(&pabcm, buf + sizeof(PwAu_Header_CM));
		if (ret>0) {
			printf("version:%c\n", pahcm.version);
			printf("用户名：%s\n", pabcm.IDC);

		}
		else {
			printf("接受数据失败！\n");

		}
        PwAu_Body_MC pabmc;
	PwAu_Header_MC pahmc;
	pahmc = Init_PAHMC(pahmc);
	pabmc = Init_PABMC(pabmc);

	char sen_buf[BUFFER_LENGTH] = { 0 };
	Send_PAHMC(&pahmc, sen_buf);
	Send_PABMC(&pabmc, sen_buf + sizeof(pahmc));
	send(c_fd, sen_buf, BUFFER_LENGTH, 0);
	printf("发送成功\n");


		close(c_fd);
	}
	
	return 0;

}

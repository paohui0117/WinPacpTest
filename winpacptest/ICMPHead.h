#ifndef _ICMP_HEAD_H_
#define _ICMP_HEAD_H_
#pragma once
#include "IPHead.h"
//类型与编码组合
//类型****************编码******************说明************************类型
//0						0					回射应答（ping应答）		查询
//--------------------------------------------------------------------------
//3											目标不可达					差错
//						0					网络不可达					差错
//						1					主机不可达					差错
//						2					协议不可达					差错
//						3					端口不可达					差错
//						4					需要分片但设置了不分片		差错
//						5					源站选路失败				差错
//						6					目的网络不认识				差错
//						7					目的主机不认识				差错
//						8					源主机被隔离				差错
//						9					目的网络被强制禁止			差错
//						10					目的主机被强制禁止			差错
//						11					由于服务类型TOS网络不可达	差错
//						12					由于服务类型TOS主机不可达	差错
//						13					由于过滤，通讯被强制禁止	差错
//						14					主机越权					差错
//						15					优先权终止生效				差错
//--------------------------------------------------------------------------
//4						0					源端被关闭					差错
//--------------------------------------------------------------------------
//5											重定向						差错
//						0					对网络重定向				差错
//						1					对主机重定向				差错
//						2					对服务类型和网络重定向		差错
//						3					对服务类型和主机重定向		差错
//--------------------------------------------------------------------------
//8						0					回射请求（ping请求）		查询
//--------------------------------------------------------------------------
//9						0					路由器通告					查询
//10					0					路由器请求					查询
//--------------------------------------------------------------------------
//11										超时						差错
//						0					传输期间生存时间为0			差错
//						1					在数据包组装期间生存时间为0	差错
//--------------------------------------------------------------------------
//12										参数问题					差错
//						0					坏的IP头部					差错
//						1					缺少必要选项				差错
//--------------------------------------------------------------------------
//13					0					时间戳请求					查询
//14					0					时间戳应答					查询
//--------------------------------------------------------------------------
//15					0					信息请求 废弃
//16					0					信息应答 废弃
//--------------------------------------------------------------------------
//17					0					地址掩码请求				查询
//18					0					地址掩码应答				查询
enum ICMP_TYPE
{
	PING_A = 0,
	Unreachable = 3,
	Quench = 4,
	Redirect = 5,
	PING_R = 8,

};
#define ICMPFrame_HEAD_LENGTH	4
struct ICMPFrame
{
	unsigned char	nType;				//类型
	unsigned char	nCode;				//代码
	unsigned short	HeaderChecksum;		//校验和
	//剩下的内容和具体类型相关
};
//PING命令
#define ICMP_PING_LENGTH	32	//在Windows?9X、Windows?2000等操作系统的Ping命令中，ICMP包中的数据部分长度默认为32字节
								//整个ICMP  ping命令部分长度为40
struct ICMPPing
{
	ICMPFrame			ICMPData;
	unsigned short		nNotify;	//标示符
	unsigned short		nNo;		//序号
	//32字节的填充内容

};
bool SetICMPPingData(const ICMPPing& PingData, char* pData, int nLength = 40);
bool GetICMPPingData(char* pData, ICMPPing& PingData);

#endif


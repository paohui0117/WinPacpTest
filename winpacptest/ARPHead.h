#ifndef _ARP_HEAD_H_
#define _ARP_HEAD_H_
#pragma once
#include "CommonHead.h"

///////ARP////////////////////////////////////////////////////////////////////////////////
#define ARP_LENGH		60
struct ARPFrame		//ARP包内容
{
	short	HardwareType;		//表明ARP实现在何种类型的网络上。值为1：表示以太网。
	short	ProtocolType;		//协议类型 IP:0800
	UCHAR	HardwareLength;		//硬件地址长度   6
	UCHAR	IPLength;			//IP地址长度	4
	short	OperationType;		//操作类型		值为1表示ARP请求。值2表示ARP应答。
	UCHAR	SourceMAC[6];		//源MAC
	int		SourceIP;			//源IP
	UCHAR	DestinationMAC[6];	//目标MAC
	int		DestinationIP;		//目标IP
};
//填充空白数据   18字节  使长度达到60字节
//
//
bool FillARPData(char* buffer, int nlength, ARPFrame* pframe);	//填充数据,构建消息包
bool GetARPData(char* buffer, ARPFrame& arp_frame, bool bHead); //bHead  是否包含 物理帧头
bool IsARP(char* buffer);
///////ARP////////////////////////////////////////////////////////////////////////////////
#endif

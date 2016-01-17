#ifndef _IP_HEAD_H_
#define _IP_HEAD_H_
#pragma once
#include "CommonHead.h"

// pppDTRM0
enum PPP
{
	PPP_Routine = 0,	//普通
	PPP_Priority = 1,	//优先的
	PPP_Immediate = 2,	//立即的发送
	PPP_Flash = 3,		//闪电式的
	PPP_FlashOverride = 4,//比闪电还闪电式的
	PPP_CRI_TIC_ECP = 5,	
	PPP_InternetworkControl = 6,//网间控制
	PPP_NetworkControl = 7	//网络控制
};

//D 时延 : 0 : 普通 1 : 延迟尽量小
//T 吞吐量 : 0 : 普通 1 : 流量尽量大
//R 可靠性 : 0 : 普通 1 : 可靠性尽量大
//M 传输成本 : 0 : 普通 1 : 成本尽量小

enum IP_Protocol
{
	IP_UNKNOW = 0,
	IP_ICMP = 1,
	IP_IGMP = 2,
	IP_TCP = 6,
	IP_UDP = 17,
	IP_IGRP = 88,
	IP_OSPF = 89,
};
struct IPV4HeadFrame	//IPV4帧头部
{
	unsigned char Version;		//4bit,一般的值为0100（IPv4），0110（IPv6）
	unsigned char HeadLength;	//单位32bit,最小长度为20字节,最长为“1111”，即15*4＝60个字节
	unsigned char TypeofService;//按位被如下定义 PPP DTRC0
	unsigned short TotalLength;	//以字节为单位计算的IP包的长度 (包括头部和数据)，所以IP包最大长度65535字节。

	unsigned short Identifier;	//该字段和Flags和Fragment Offest字段联合使用，
								//对较大的上层数据包进行分段（fragment）操作。
								//路由器将一个包拆分后，所有拆分开的小包被标记相同的值，
								//以便目的端设备能够区分哪个包属于被拆分开的包的一部分。

	unsigned char Flags;		//长度3比特该字段第一位不使用。
								//第二位是DF（Don't Fragment）位，DF位设为1时表明路由器不能对该上层数据包分段。
								//如果一个上层数据包无法在不分段的情况下进行转发，则路由器会丢弃该上层数据包并返回一个错误信息。
								//第三位是MF（More Fragments）位，当路由器对一个上层数据包分段，
								//则路由器会在除了最后一个分段的IP包的包头中将MF位设为1。

	unsigned short FragmentOffset;//长度13比特。表示该IP包在该组分片包中位置，接收端靠此来组装还原IP包。 
	unsigned char  TTL;			//当IP包进行传送时，先会对该字段赋予某个特定的值。
								//当IP包经过每一个沿途的路由器的时候，每个沿途的路由器会将IP包的TTL值减少1。
								//如果TTL减少为0，则该IP包会被丢弃。这个字段可以防止由于路由环路而导致IP包在网络中不停被转发。
	unsigned char Protocol;		//
	unsigned short HeaderChecksum;//长度16位。用来做IP头部的正确性检测，但不包含数据部分。 
								//因为每个路由器要改变TTL的值,所以路由器会为每个通过的数据包重新计算这个值。

	unsigned int SourceIP;		//
	unsigned int DestinationIP;	//
	///////////////////////////////////////////
	IPV4HeadFrame()
	{
		Version = 4;
		HeadLength = 5;
		TypeofService = 0;
		TotalLength = 5;
		Identifier = 0;
		Flags = 0;		//000
		FragmentOffset = 0;
		TTL = 0xff;
		Protocol = 1;
		HeaderChecksum = 0;
		SourceIP = 0;
		DestinationIP = 0;
	}
};
struct IPSet
{
	unsigned char PPP;
	unsigned char D;
	unsigned char T;
	unsigned char R;
	unsigned char M;
	IPSet()
	{
		PPP = 0;
		D = 0;
		T = 0;
		R = 0;
		M = 0;
	}
};
IP_Protocol GetIPProtocolType(char* pData, bool bHead);	//bHead:是否带有表头
bool SetIPData(const IPV4HeadFrame& frame, char* pData,const IPSet* ipset = nullptr);
bool GetIPData(IPV4HeadFrame& frame, char* pData, IPSet* ipset);
void GetTypeofService(char data, IPSet& ipset);
SHORT checksum(USHORT* buffer, int size);	//计算校验和
#endif


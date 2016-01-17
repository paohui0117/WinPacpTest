#include "stdafx.h"
#include "IPHead.h"

IP_Protocol GetIPProtocolType(char* pData, bool bHead)
{
	if (!pData)
		return IP_UNKNOW;
	if (bHead && GetProtocolType(pData) != PT_IP)
		return IP_UNKNOW;
	if (bHead)
		pData += 14;
	switch (pData[9])
	{
	case IP_ICMP:
		return IP_ICMP;
	case IP_IGMP:
		return IP_IGMP;
	case IP_TCP:
		return IP_TCP;
	case IP_UDP:
		return IP_UDP;
	case IP_IGRP:
		return IP_IGRP;
	case IP_OSPF:
		return IP_OSPF;
	default:
		return IP_UNKNOW;
	}
}

bool SetIPData(const IPV4HeadFrame& frame, char* pData, const IPSet* ipset)
{
	if (!pData)
		return false;
	IPSet temp;
	if (!ipset)
	{
		ipset = &temp;
	}
	if (frame.HeadLength < 5 || frame.HeadLength > 15)
		return false;
	if (frame.TotalLength < frame.HeadLength)
		return false;
	memset(pData, 0, frame.HeadLength * 4);
	pData[0] = (frame.Version << 4) | frame.HeadLength;
	pData[1] = frame.TypeofService;
	pData[2] = frame.TotalLength >> 8;
	pData[3] = frame.TotalLength & 0x00ff;
	
	pData[4] = frame.Identifier >> 8;
	pData[5] = frame.Identifier & 0x00ff;
	
	pData[6] = frame.Flags << 5;
	pData[6] += frame.FragmentOffset >> 8;
	pData[7] = frame.FragmentOffset & 0x00ff;
	
	pData[8] = frame.TTL;
	pData[9] = frame.Protocol;
	*(int*)(pData + 12) = frame.SourceIP;
	*(int*)(pData + 16) = frame.DestinationIP;

	short check = checksum((USHORT*)pData, frame.HeadLength * 4);
	*(short*)(pData + 10) = check;
//	pData[10] = check >> 8;
//	pData[11] = check & 0x00ff;
	return true;
}

bool GetIPData(IPV4HeadFrame& frame, char* pData, IPSet* ipset)
{
	if (!pData)
		return false;
	frame.Version = pData[0] >> 4;
	frame.HeadLength = pData[0] & 0xF;
	frame.TypeofService = pData[1];
	if (ipset)
		GetTypeofService(frame.TypeofService, *ipset);

	ToShort(frame.TotalLength, pData + 2);
	
	ToShort(frame.Identifier, pData + 4);
	
	USHORT temp;
	ToShort(temp, pData + 6);
	frame.Flags = temp >> 13;
	frame.FragmentOffset = temp & 0x1fff;	//0x0001 1111 1111 1111

	frame.TTL = pData[8];
	frame.Protocol = pData[9];

	ToShort(frame.HeaderChecksum, pData + 10);
	
	frame.SourceIP = *(int*)(pData + 12);
	frame.DestinationIP = *(int*)(pData + 16);
	return true;
}

void GetTypeofService(char data, IPSet& ipset)
{
	ipset.PPP = data >> 5;
	ipset.D = data & 0x10;  //0001 0000
	ipset.T = data & 8;		//0000 1000
	ipset.R = data & 4;		//0000 0100
	ipset.M = data & 2;		//0000 0100
}

SHORT checksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;
	while (size>1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);   // 将高 16bit 与低 16bit 相加
	cksum += (cksum >> 16);              // 将进位到高位的 16bit 与低 16bit 再相加
	return (USHORT)(~cksum);
}
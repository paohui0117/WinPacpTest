#include "stdafx.h"
#include "ARPHead.h"
#include <string.h>
//填充ARP数据
inline void ToShort(short& to, char* from)
{
	to = from[0];
	to <<= 8;
	to += from[1];
}
bool FillARPData(char* buffer, int nlength, ARPFrame* pframe)
{
	if (!buffer || !pframe || nlength != 60)
		return false;
	memset(buffer, 0, 60);
	//填充DLC头
	if (pframe->OperationType == 1) //请求
	{
		memset(buffer, 0xff, 6);	//目标MAX
		memset(buffer + 32, 0xff, 6);	//目标MAX
	}
	else//应答
	{
		memcpy(buffer, pframe->DestinationMAC, 6);
		memcpy(buffer + 32, pframe->DestinationMAC, 6);
	}
	memcpy(buffer + 6, pframe->SourceMAC, 6);
	unsigned short nType = ARP_TYPE;
	buffer[12] = nType >> 8;
	buffer[13] = nType & 0x00ff;
	//填充ARP
	buffer[14] = pframe->HardwareType >> 8;
	buffer[15] = pframe->HardwareType & 0x00ff;

	buffer[16] = pframe->ProtocolType >> 8;
	buffer[17] = pframe->ProtocolType & 0x00ff;
	
	buffer[18] = pframe->HardwareLength;
	
	buffer[19] = pframe->IPLength;

	buffer[20] = pframe->OperationType >> 8;
	buffer[21] = pframe->OperationType & 0x00ff;
	memcpy(buffer + 22, pframe->SourceMAC, 6);
	memcpy(buffer + 28, (char*)&(pframe->SourceIP), 4);
	memcpy(buffer + 38, (char*)&(pframe->DestinationIP), 4);
	return true;
}

bool GetARPData(char* buffer, ARPFrame& arp_frame, bool bHead)
{
	if (!buffer)
		return false;
	char* pTemp = buffer;
	if (bHead)
	{
		//包含物理帧头
		pTemp += 14;
	}
	ToShort(arp_frame.HardwareType, pTemp);
	
	ToShort(arp_frame.ProtocolType, pTemp + 2);


	arp_frame.HardwareLength = pTemp[4];

	arp_frame.IPLength = pTemp[5];

	ToShort(arp_frame.OperationType, pTemp + 6);

	memcpy(arp_frame.SourceMAC, pTemp + 8, 6);

	arp_frame.SourceIP = *(int*)(pTemp + 14);

	memcpy(arp_frame.DestinationMAC, pTemp + 18, 6);

	arp_frame.DestinationIP = *(int*)(pTemp + 24);
	if (bHead)
	{
		memcpy(arp_frame.DestinationMAC, buffer, 6);
		memcpy(arp_frame.SourceMAC, buffer + 6, 6);
	}
	return true;
}

bool IsARP(char* buffer)
{
	if (!buffer)
		return false;
	return (*(short*)(buffer + 12) == 0x0806);
}
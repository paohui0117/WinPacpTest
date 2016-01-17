#include "stdafx.h"
#include "ICMPHead.h"

bool SetICMPPingData(const ICMPPing& PingData, char* pData, int nLength)
{
	if (!pData)
		return false;
	pData[0] = PingData.ICMPData.nType;
	pData[1] = PingData.ICMPData.nCode;
	pData[2] = 0;
	pData[3] = 0;
	pData[4] = PingData.nNotify >> 8;
	pData[5] = PingData.nNotify & 0x00ff;
	pData[6] = PingData.nNo >> 8;
	pData[7] = PingData.nNo & 0x00ff;
	
	SHORT temp = checksum((USHORT*)pData, nLength);
	pData[2] = temp >> 8;
	pData[3] = temp & 0x00ff;
	return true;
}

bool GetICMPPingData(char* pData, ICMPPing& PingData)
{
	if (!pData)
		return false;
	PingData.ICMPData.nType = pData[0];
	PingData.ICMPData.nCode = pData[1];
	ToShort(PingData.ICMPData.HeaderChecksum, pData + 2);
	ToShort(PingData.nNotify, pData + 4);
	ToShort(PingData.nNo, pData + 6);
	return true;
}
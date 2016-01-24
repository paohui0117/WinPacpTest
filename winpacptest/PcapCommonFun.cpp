#include "stdafx.h"
#include "CommonHead.h"
#include <ws2tcpip.h>



ProtocolType GetProtocolType(char* p)
{
	if (!p)
		return PT_UNKNOW;
	short temp = p[12];
	temp <<= 8;
	temp += (UCHAR)p[13];
	ProtocolType tp = PT_UNKNOW;
	switch (temp)
	{
	case 0x0806:
		tp =  PT_ARP;
		break;
	case 0x0800:
		tp = PT_IP;
		break;
	case 0x8137:
		tp = PT_Novell_IPX;
		break;
	case 0x809b:
		tp = PT_Apple_Talk;
		break;
	default:
		break;
	}
	return tp;
}

bool SetDLCHEADData(char* pData, const DLC_HEAD& dlc_head)
{
	if (!pData)
		return false;
	memcpy(pData, dlc_head.DestinationMAC, 6);
	memcpy(pData + 6, dlc_head.SourceMAC, 6);
	pData[12] = dlc_head.Ethertype >> 8;
	pData[13] = dlc_head.Ethertype & 0x00ff;
	return true;
}

bool GetDLCHEADData(char* p_data, DLC_HEAD& dlc_head)
{
	if (!p_data)
		return false;
	memcpy(dlc_head.DestinationMAC, p_data, 6);
	memcpy(dlc_head.SourceMAC, p_data + 6, 6);
	dlc_head.Ethertype = p_data[12];
	dlc_head.Ethertype <<= 8;
	dlc_head.Ethertype += p_data[13];
	return true;
}

CString IptoStr(ULONG naddr)
{
	wchar_t output[3 * 4 + 3 + 1] = { 0 };
	u_char *p;
	p = (u_char *)&naddr;
	wsprintf(output, L"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output;
}

CString Ip6toStr(sockaddr* addr)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif
	char* pOut = new char[128];
	if (getnameinfo(addr, sockaddrlen, pOut, 128, nullptr, 0, NI_NUMERICHOST) != 0)
		return L"";
	CString str(pOut);
	delete[] pOut;
	return str;
}
CString GetMAC(BYTE* pMac, int nlength)
{
	if (!pMac || nlength < 1)
		return L"";
	CString str;
	CString strtemp;
	strtemp.Format(L"%02X", pMac[0]);
	str = strtemp;
	for (int i = 1; i < nlength; i++)
	{
		strtemp.Format(L"-%02X", pMac[i]);
		str += strtemp;
	}
	return str;
}

UINT	StrToIP4(LPCSTR strIP)
{
	if (!strIP)
		return 0;
	BYTE pIP[4] = { 0 };
	std::string strTempIP(strIP);
	SIZE_T nb = 0;
	SIZE_T ne = 0;
	for (size_t i = 0; i < 4; i++)
	{
		ne = strTempIP.find('.', nb);
		if (ne != strTempIP.npos)
		{
			pIP[i] = StrToIntA(strTempIP.substr(nb, ne).c_str());
			nb = ne + 1;
		}
	}
	pIP[3] = StrToIntA(strTempIP.substr(nb, strTempIP.length()).c_str());
	return *(UINT*)pIP;
}
UINT	WStrToIP4(LPCWSTR strIP)
{
	if (!strIP)
		return 0;
	BYTE pIP[4] = { 0 };
	std::wstring strTempIP(strIP);
	SIZE_T nb = 0;
	SIZE_T ne = 0;
	for (size_t i = 0; i < 4; i++)
	{
		ne = strTempIP.find('.', nb);
		if (ne != strTempIP.npos)
		{
			pIP[i] = StrToIntW(strTempIP.substr(nb, ne).c_str());
			nb = ne + 1;
		}
		else
			break;
	}
	pIP[3] = StrToInt(strTempIP.substr(nb, strTempIP.length()).c_str());
	return *(UINT*)pIP;
}

bool GetIP4Range(UINT IP, UINT nMask, UINT& SIP, UINT& EIP)	//»ñÈ¡¾ÖÓòÍøIP·¶Î§
{
	if (IP == 0)
		return false;
	UCHAR* pIP = (UCHAR*)&IP;
	UCHAR* pMask = (UCHAR*)&nMask;
	EIP = SIP = IP;
	if (pMask[3] == 255)
		return true;
	UCHAR* pSIP = (UCHAR*)&SIP;
	pSIP[3] = 1;
	UCHAR* pEIP = (UCHAR*)&EIP;
	pEIP[3] = 255;
	int nLength = 0;
	while(pMask[3 - nLength] == 0 && nLength < 4)
	{
		nLength++;
	}
	int nCur = 3 - nLength;
	UCHAR temp = ~pMask[nCur];
	pSIP[nCur] = pIP[nCur] & pMask[nCur];
	pEIP[nCur] = pSIP[nCur] + temp;
	return TRUE;
}
int		ReverseUINT(int n)
{
	BYTE* p = (BYTE*)&n;
	BYTE temp;
	temp = p[0];
	p[0] = p[3];
	p[3] = temp;
	temp = p[1];
	p[1] = p[2];
	p[2] = temp;
	return n;
}
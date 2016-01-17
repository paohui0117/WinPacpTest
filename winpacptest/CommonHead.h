#ifndef _COMMON_HEAD_H_
#define _COMMON_HEAD_H_
#pragma once
enum ProtocolType
{
	PT_UNKNOW = 0,
	PT_ARP = 1,
	PT_IP = 2,
	PT_Novell_IPX = 3,
	PT_Apple_Talk = 4,
};
#define  DLC_HEAD_LENGTH	14

#define ARP_TYPE		0x0806
#define IP_TYPE			0x0800
#define MPLS_TYPE		0x8847
#define IPX_TYPE		0x8137
#define IS_IS_TYPE		0x8000
#define LACP_TYPE		0x8809
#define _802_1x_TYPE		0x888E

struct DLC_HEAD  //����֡ͷ 14�ֽ�  Ethernet V2(ARPA)
{
	UCHAR	DestinationMAC[6];	//Ŀ��MAC  ����ʱΪff-ff-ff-ff-ff
	UCHAR	SourceMAC[6];		//ԴMAC
	short	Ethertype;			//0x0806��ARP֡������ֵ
};
ProtocolType GetProtocolType(char* p);
bool SetDLCHEADData(char* pData, const DLC_HEAD& dlc_head);
bool GetDLCHEADData(char* p_data, DLC_HEAD& dlc_head);
///////common/////////////////////////////////////////////////////////////////////////////
CString IptoStr(ULONG naddr);
CString Ip6toStr(sockaddr* addr);
CString GetMAC(BYTE* pMac, int nlength);
UINT	StrToIP4(LPCSTR strIP);
UINT	WStrToIP4(LPCWSTR strIP);
bool	GetIP4Range(UINT GatewayIP, UINT nMask, UINT& SIP, UINT& EIP);	//��ȡ������IP��Χ
int		ReverseUINT(int n);
///////common/////////////////////////////////////////////////////////////////////////////
#endif


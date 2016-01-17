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

struct DLC_HEAD  //物理帧头 14字节  Ethernet V2(ARPA)
{
	UCHAR	DestinationMAC[6];	//目标MAC  请求时为ff-ff-ff-ff-ff
	UCHAR	SourceMAC[6];		//源MAC
	short	Ethertype;			//0x0806是ARP帧的类型值
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
bool	GetIP4Range(UINT GatewayIP, UINT nMask, UINT& SIP, UINT& EIP);	//获取局域网IP范围
int		ReverseUINT(int n);
///////common/////////////////////////////////////////////////////////////////////////////
#endif


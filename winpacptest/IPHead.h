#ifndef _IP_HEAD_H_
#define _IP_HEAD_H_
#pragma once
#include "CommonHead.h"

// pppDTRM0
enum PPP
{
	PPP_Routine = 0,	//��ͨ
	PPP_Priority = 1,	//���ȵ�
	PPP_Immediate = 2,	//�����ķ���
	PPP_Flash = 3,		//����ʽ��
	PPP_FlashOverride = 4,//�����绹����ʽ��
	PPP_CRI_TIC_ECP = 5,	
	PPP_InternetworkControl = 6,//�������
	PPP_NetworkControl = 7	//�������
};

//D ʱ�� : 0 : ��ͨ 1 : �ӳپ���С
//T ������ : 0 : ��ͨ 1 : ����������
//R �ɿ��� : 0 : ��ͨ 1 : �ɿ��Ծ�����
//M ����ɱ� : 0 : ��ͨ 1 : �ɱ�����С

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
struct IPV4HeadFrame	//IPV4֡ͷ��
{
	unsigned char Version;		//4bit,һ���ֵΪ0100��IPv4����0110��IPv6��
	unsigned char HeadLength;	//��λ32bit,��С����Ϊ20�ֽ�,�Ϊ��1111������15*4��60���ֽ�
	unsigned char TypeofService;//��λ�����¶��� PPP DTRC0
	unsigned short TotalLength;	//���ֽ�Ϊ��λ�����IP���ĳ��� (����ͷ��������)������IP����󳤶�65535�ֽڡ�

	unsigned short Identifier;	//���ֶκ�Flags��Fragment Offest�ֶ�����ʹ�ã�
								//�Խϴ���ϲ����ݰ����зֶΣ�fragment��������
								//·������һ������ֺ����в�ֿ���С���������ͬ��ֵ��
								//�Ա�Ŀ�Ķ��豸�ܹ������ĸ������ڱ���ֿ��İ���һ���֡�

	unsigned char Flags;		//����3���ظ��ֶε�һλ��ʹ�á�
								//�ڶ�λ��DF��Don't Fragment��λ��DFλ��Ϊ1ʱ����·�������ܶԸ��ϲ����ݰ��ֶΡ�
								//���һ���ϲ����ݰ��޷��ڲ��ֶε�����½���ת������·�����ᶪ�����ϲ����ݰ�������һ��������Ϣ��
								//����λ��MF��More Fragments��λ����·������һ���ϲ����ݰ��ֶΣ�
								//��·�������ڳ������һ���ֶε�IP���İ�ͷ�н�MFλ��Ϊ1��

	unsigned short FragmentOffset;//����13���ء���ʾ��IP���ڸ����Ƭ����λ�ã����ն˿�������װ��ԭIP���� 
	unsigned char  TTL;			//��IP�����д���ʱ���Ȼ�Ը��ֶθ���ĳ���ض���ֵ��
								//��IP������ÿһ����;��·������ʱ��ÿ����;��·�����ὫIP����TTLֵ����1��
								//���TTL����Ϊ0�����IP���ᱻ����������ֶο��Է�ֹ����·�ɻ�·������IP���������в�ͣ��ת����
	unsigned char Protocol;		//
	unsigned short HeaderChecksum;//����16λ��������IPͷ������ȷ�Լ�⣬�����������ݲ��֡� 
								//��Ϊÿ��·����Ҫ�ı�TTL��ֵ,����·������Ϊÿ��ͨ�������ݰ����¼������ֵ��

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
IP_Protocol GetIPProtocolType(char* pData, bool bHead);	//bHead:�Ƿ���б�ͷ
bool SetIPData(const IPV4HeadFrame& frame, char* pData,const IPSet* ipset = nullptr);
bool GetIPData(IPV4HeadFrame& frame, char* pData, IPSet* ipset);
void GetTypeofService(char data, IPSet& ipset);
SHORT checksum(USHORT* buffer, int size);	//����У���
#endif


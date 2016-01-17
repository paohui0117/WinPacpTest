#ifndef _ARP_HEAD_H_
#define _ARP_HEAD_H_
#pragma once
#include "CommonHead.h"

///////ARP////////////////////////////////////////////////////////////////////////////////
#define ARP_LENGH		60
struct ARPFrame		//ARP������
{
	short	HardwareType;		//����ARPʵ���ں������͵������ϡ�ֵΪ1����ʾ��̫����
	short	ProtocolType;		//Э������ IP:0800
	UCHAR	HardwareLength;		//Ӳ����ַ����   6
	UCHAR	IPLength;			//IP��ַ����	4
	short	OperationType;		//��������		ֵΪ1��ʾARP����ֵ2��ʾARPӦ��
	UCHAR	SourceMAC[6];		//ԴMAC
	int		SourceIP;			//ԴIP
	UCHAR	DestinationMAC[6];	//Ŀ��MAC
	int		DestinationIP;		//Ŀ��IP
};
//���հ�����   18�ֽ�  ʹ���ȴﵽ60�ֽ�
//
//
bool FillARPData(char* buffer, int nlength, ARPFrame* pframe);	//�������,������Ϣ��
bool GetARPData(char* buffer, ARPFrame& arp_frame, bool bHead); //bHead  �Ƿ���� ����֡ͷ
bool IsARP(char* buffer);
///////ARP////////////////////////////////////////////////////////////////////////////////
#endif

#pragma once
#include <string>
extern const bool g_bBigEndian;
std::string WStrToStr(LPCWSTR strIn);

CString StrToWstr(LPCSTR strIn);

inline void ToShort(USHORT& to, char* from)
{
	to = from[0];
	to <<= 8;
	to = to + from[1];
}
//�Ƿ��Ǵ��ģʽ  
//���ģʽ��Big-endian������ָ���ݵĸ��ֽڣ��������ڴ�ĵ͵�ַ��
//С��ģʽ��Little-endian������ָ���ݵĸ��ֽڱ������ڴ�ĸߵ�ַ��
inline bool BigEndian()
{
	short a = 1;
	char* temp = (char*)&a;
	return temp[0] == 0;
}

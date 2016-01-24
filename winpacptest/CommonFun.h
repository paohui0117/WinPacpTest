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
//是否是大端模式  
//大端模式（Big-endian），是指数据的高字节，保存在内存的低地址中
//小端模式（Little-endian），是指数据的高字节保存在内存的高地址中
inline bool BigEndian()
{
	short a = 1;
	char* temp = (char*)&a;
	return temp[0] == 0;
}

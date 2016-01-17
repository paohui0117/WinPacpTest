#pragma once
#include <string>

std::string WStrToStr(LPCWSTR strIn);

CString StrToWstr(LPCSTR strIn);

inline void ToShort(USHORT& to, char* from)
{
	to = from[0];
	to <<= 8;
	to = to + from[1];
}


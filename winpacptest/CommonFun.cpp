#include "stdafx.h"
#include "CommonFun.h"
const bool g_bBigEndian = BigEndian();
std::string WStrToStr(LPCWSTR strIn)
{
	if (strIn == nullptr)
		return "";
	int nlength = WideCharToMultiByte(CP_ACP, 0, strIn, -1, nullptr, 0, nullptr, nullptr);
	char* strtemp = new char[nlength];
	WideCharToMultiByte(CP_ACP, 0, strIn, -1, strtemp, nlength, nullptr, nullptr);
	std::string str(strtemp);
	delete[] strtemp;
	return str;
}

CString StrToWstr(LPCSTR strIn)
{
	if (strIn == nullptr)
		return L"";
	int nlength = MultiByteToWideChar(CP_ACP, 0, strIn, -1, nullptr, 0);
	wchar_t* ptemp = new wchar_t[nlength];
	MultiByteToWideChar(CP_ACP, 0, strIn, -1, ptemp, nlength);
	CString str(ptemp);
	delete[] ptemp;
	return str;
}

// winpacptest.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CwinpacptestApp: 
// �йش����ʵ�֣������ winpacptest.cpp
//

class CwinpacptestApp : public CWinApp
{
public:
	CwinpacptestApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CwinpacptestApp theApp;
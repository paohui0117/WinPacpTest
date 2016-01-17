
// winpacptestDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include "pcap.h"
#include "afxcmn.h"
#include <IPHlpApi.h>
#include "afxpropertygridctrl.h"
#pragma comment(lib ,"iphlpapi.lib")
#include <vector>
#include <map>

// CwinpacptestDlg �Ի���
class CwinpacptestDlg : public CDialogEx
{
// ����
public:
	CwinpacptestDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPACPTEST_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;


	
	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnDestroy();
	afx_msg void OnCbnSelchangeComNic();
	afx_msg void OnBnClickedBtnSearch();
	DECLARE_MESSAGE_MAP()
private:
	void InitInfo();
	void InitList();
	void SetListInfo(IP_ADAPTER_INFO* pcap_if);
	void StartSearch();
	void Ping(int nIP, IP_ADAPTER_INFO * d);
	void InitIPList();
public:
	void InsetIPData(int IP, char* p);
public:
	// �����б�
	CComboBox m_com_NIC;
	CMFCPropertyGridCtrl m_property_list;
	CMFCPropertyGridProperty* m_pPropertyCommon;
	CMFCPropertyGridProperty* m_pPropertyIP;
	CMFCPropertyGridProperty* m_pPropertyGateway;
	CMFCPropertyGridProperty* m_pPropertyDHCP;
	CListCtrl m_list_ip;
	CButton m_btn_search;
private:
	IP_ADAPTER_INFO*	m_pADAPTER_INFO;
	HANDLE				m_HSendArp;
	HANDLE				m_HGetArp;
public:
	IP_ADAPTER_INFO*	m_pCur;
	pcap_t *			m_adhandle;
	bool				m_bRun;
	std::map<int, char*>	m_vecIP;
};

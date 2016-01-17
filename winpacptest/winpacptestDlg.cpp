
// winpacptestDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "winpacptest.h"
#include "winpacptestDlg.h"
#include "afxdialogex.h"
#include "ARPHead.h"
#include <winnetwk.h>
#pragma comment(lib, "mpr.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include "ICMPHead.h"


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
	
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CwinpacptestDlg �Ի���
unsigned  WINAPI SendAllARP(void* pVoid)
{
	CwinpacptestDlg* pDlg = (CwinpacptestDlg*)pVoid;
	if (!pDlg || !pDlg->m_pCur)
		return -1;
	UINT nStar = 0;
	UINT nEnd = 0;
	if (!GetIP4Range(StrToIP4(pDlg->m_pCur->GatewayList.IpAddress.String), StrToIP4(pDlg->m_pCur->IpAddressList.IpMask.String), nStar, nEnd))
		return -1;
	ARPFrame arpdata;
	arpdata.HardwareType = 1;
	arpdata.ProtocolType = 0x0800;
	arpdata.HardwareLength = 6;
	arpdata.IPLength = 4;
	memcpy(arpdata.SourceMAC, pDlg->m_pCur->Address, 6);
	arpdata.OperationType = 1;
	arpdata.SourceIP = StrToIP4(pDlg->m_pCur->IpAddressList.IpAddress.String);
	memset(arpdata.DestinationMAC, 0, 6);
	//����IP
	UINT nTempS = ReverseUINT(nStar);
	UINT nTempE = ReverseUINT(nEnd);
	UCHAR pData[60] = { 0 };
	for (size_t i = nTempS; i <= nTempE; i++)
	{
		arpdata.DestinationIP = ReverseUINT(i);
		FillARPData((char*)pData, 60, &arpdata);
		OutputDebugStringW(IptoStr(arpdata.DestinationIP) + L"\r\n");
		if (pcap_sendpacket(pDlg->m_adhandle, (UCHAR*)pData, 60) != 0)
		{
			OutputDebugStringW(L"����ARP��ʧ��");
		}
		Sleep(10);
	}
	arpdata.DestinationIP = WStrToIP4(L"93.123.23.1");
	FillARPData((char*)pData, 60, &arpdata);
	OutputDebugStringW(IptoStr(arpdata.DestinationIP) + L"\r\n");
	if (pcap_sendpacket(pDlg->m_adhandle, (UCHAR*)pData, 60) != 0)
	{
		OutputDebugStringW(L"����ARP��ʧ��");
	}
	return 1;
}
unsigned  WINAPI GetAllARP(void* pVoid)
{
	CwinpacptestDlg* pDlg = (CwinpacptestDlg*)pVoid;
	if (!pDlg || !pDlg->m_pCur)
		return -1;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;
	ARPFrame data;
	pDlg->m_vecIP.clear();
	IPV4HeadFrame temp;
	ICMPPing tempPing;
	USHORT st;
	char* buffer = new char[25600];
	IPSet tempset;
	while (pDlg->m_bRun && (res = pcap_next_ex(pDlg->m_adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;
		if (GetIPProtocolType((char*)pkt_data, true) == IP_ICMP)
		{
			GetIPData(temp, (char*)(pkt_data + 14), &tempset);
			GetICMPPingData((char*)(pkt_data + 14 + temp.HeadLength * 4), tempPing);
			SetICMPPingData(tempPing, buffer, temp.TotalLength - temp.HeadLength * 4);
			st = checksum((USHORT*)(pkt_data + 14 + temp.HeadLength * 4), temp.TotalLength - temp.HeadLength * 4);
			
		}
	}
	return 1;
}


CwinpacptestDlg::CwinpacptestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_WINPACPTEST_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_pADAPTER_INFO = nullptr;
	m_adhandle = nullptr;
	m_HSendArp = nullptr;
	m_pCur = nullptr;
	m_HGetArp = nullptr;
	m_bRun = false;
}

void CwinpacptestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COM_NIC, m_com_NIC);
	DDX_Control(pDX, IDC_PROPERTY_LIST, m_property_list);
	DDX_Control(pDX, IDC_LIST_IP, m_list_ip);
	DDX_Control(pDX, IDC_BTN_SEARCH, m_btn_search);
}

BEGIN_MESSAGE_MAP(CwinpacptestDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DESTROY()
	ON_CBN_SELCHANGE(IDC_COM_NIC, &CwinpacptestDlg::OnCbnSelchangeComNic)
	ON_BN_CLICKED(IDC_BTN_SEARCH, &CwinpacptestDlg::OnBnClickedBtnSearch)
END_MESSAGE_MAP()


// CwinpacptestDlg ��Ϣ�������

void CwinpacptestDlg::InitList()
{
	m_property_list.RemoveAll();
	m_pPropertyCommon = new CMFCPropertyGridProperty(_T("��Ϣ"));
	m_pPropertyIP = new CMFCPropertyGridProperty(_T("IP�б�"));
	m_pPropertyGateway = new CMFCPropertyGridProperty(_T("�����б�"));
	m_pPropertyDHCP = new CMFCPropertyGridProperty(_T("DHCP�����б�"));
	m_property_list.AddProperty(m_pPropertyCommon);
	m_property_list.AddProperty(m_pPropertyGateway);
	m_property_list.AddProperty(m_pPropertyIP);
	m_property_list.AddProperty(m_pPropertyDHCP);
	HDITEM item;
	item.cxy = 120;
	item.mask = HDI_WIDTH;
	m_property_list.GetHeaderCtrl().SetItem(0, &item);
	m_property_list.EnableHeaderCtrl(FALSE);
}

BOOL CwinpacptestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	InitInfo();
	InitList();
	InitIPList();
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CwinpacptestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CwinpacptestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CwinpacptestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CwinpacptestDlg::InitInfo()
{
	ULONG nSize = 0;
	if (GetAdaptersInfo(nullptr, &nSize))
	{
		m_pADAPTER_INFO = (PIP_ADAPTER_INFO)new BYTE[nSize];
		GetAdaptersInfo(m_pADAPTER_INFO, &nSize);
		PIP_ADAPTER_INFO pTemp = m_pADAPTER_INFO;
		while(pTemp)
		{
			m_com_NIC.AddString(StrToWstr(pTemp->Description));
			pTemp = pTemp->Next;
		}
	}
}

void CwinpacptestDlg::SetListInfo(IP_ADAPTER_INFO * d)
{
	
	if (!d)
		return;
	InitList();
	CString strDescription;
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Name", StrToWstr(d->AdapterName), L"����"));
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Description", StrToWstr(d->Description), L"����"));
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"MAC", GetMAC(d->Address, d->AddressLength), L"Ӳ����ַ"));
	WCHAR pStr[32] = { 0 };
	_itow_s(d->Index, pStr, 10);
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Index", pStr, L"����������"));
	CString strType;
	switch (d->Type)
	{
	case 1:
		strType = L"MIB_IF_TYPE_OTHER";
		strDescription = L"�������͵�������";
		break;
	case 6:
		strType = L"MIB_IF_TYPE_ETHERNET";
		strDescription = L"��̫��������";
		break;
	case 9:
		strType = L"MIB_IF_TYPE_TOKENRING";
		strDescription = L"���ƻ�������";
		break;
	case 15:
		strType = L"MIB_IF_TYPE_FDDI";
		strDescription = L"FDDI�����˷ֲ����ݽӿڣ�������";
		break;
	case 23:
		strType = L"MIB_IF_TYPE_PPP";
		strDescription = L"PPP������";
		break;
	case 24:
		strType = L"MIB_IF_TYPE_LOOPBACK";
		strDescription = L"Loopback������";
		break;
	case 28:
		strType = L"MIB_IF_TYPE_SLIP";
		strDescription = L"Slip������";
		break;
	}
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Type", strType, strDescription));
	if (d->DhcpEnabled)
		strDescription = L"TRUE";
	else
		strDescription = L"FALSE";
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"DhcpEnabled", strDescription, L"�Ƿ���DHCP"));
	PIP_ADDR_STRING pIP = &d->IpAddressList;
	while (pIP)
	{
		m_pPropertyIP->AddSubItem(new CMFCPropertyGridProperty(L"IP", StrToWstr(pIP->IpAddress.String)));
		m_pPropertyIP->AddSubItem(new CMFCPropertyGridProperty(L"IpMask", StrToWstr(pIP->IpMask.String)));
		pIP = pIP->Next;
	}
	pIP = &d->GatewayList;
	while (pIP)
	{
		m_pPropertyGateway->AddSubItem(new CMFCPropertyGridProperty(L"IP", StrToWstr(pIP->IpAddress.String)));
		m_pPropertyGateway->AddSubItem(new CMFCPropertyGridProperty(L"IpMask", StrToWstr(pIP->IpMask.String)));
		UINT nStar = 0;
		UINT nEnd = 0;
		GetIP4Range(StrToIP4(pIP->IpAddress.String), StrToIP4(d->IpAddressList.IpMask.String), nStar, nEnd);
		strDescription.Format(L"%s - %s", IptoStr(nStar), IptoStr(nEnd));
		m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"����IP��Χ", strDescription, L"����IP��Χ"));
		pIP = pIP->Next;
	}
	pIP = &d->DhcpServer;
	while (pIP)
	{
		m_pPropertyDHCP->AddSubItem(new CMFCPropertyGridProperty(L"IP", StrToWstr(pIP->IpAddress.String)));
		m_pPropertyDHCP->AddSubItem(new CMFCPropertyGridProperty(L"IpMask", StrToWstr(pIP->IpMask.String)));
		pIP = pIP->Next;
	}
	m_property_list.ExpandAll();
}

void CwinpacptestDlg::StartSearch()
{
	if (!m_adhandle)
	{
		m_btn_search.SetWindowTextW(L"����������");
		m_btn_search.EnableWindow();
		return;
	}
	m_HSendArp = (HANDLE)_beginthreadex(nullptr, 0, SendAllARP, this, 0, nullptr);
	m_bRun = true;
	m_HGetArp = (HANDLE)_beginthreadex(nullptr, 0, GetAllARP, this, 0, nullptr);
}

void CwinpacptestDlg::Ping(int nIP, IP_ADAPTER_INFO * d)
{

}

void CwinpacptestDlg::InitIPList()
{
	m_list_ip.InsertColumn(0, L"IP", 0, 150);
	m_list_ip.InsertColumn(1, L"MAC", 0, 150);
}

void CwinpacptestDlg::InsetIPData(int IP, char* p)
{
	m_list_ip.InsertItem(0, IptoStr(IP));
	m_list_ip.SetItemText(0, 1, GetMAC((BYTE*)p, 6));
}

void CwinpacptestDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// TODO: �ڴ˴������Ϣ����������
	/* ������Ҫ�豸�б��ˣ��ͷ��� */
	if (m_pADAPTER_INFO)
	{
		delete m_pADAPTER_INFO;
		m_pADAPTER_INFO = nullptr;
	}
		
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = nullptr;
	}
		
}


void CwinpacptestDlg::OnCbnSelchangeComNic()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int n = m_com_NIC.GetCurSel();
	if (!m_pADAPTER_INFO || n < 0)
		return;
	PIP_ADAPTER_INFO ptemp = m_pADAPTER_INFO;
	while(n > 0)
	{
		ptemp = ptemp->Next;
		if (!ptemp)
			return;
		n--;
	}
	SetListInfo(ptemp);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

}

void CwinpacptestDlg::OnBnClickedBtnSearch()
{
	if (m_adhandle)
		return;
	int ncur = m_com_NIC.GetCurSel();
	if (ncur < 0 || !m_pADAPTER_INFO)
		return;
	m_pCur = m_pADAPTER_INFO;
	while (ncur > 0)
	{
		ncur--;
		m_pCur = m_pCur->Next;
		if (!m_pCur)
			return;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	std::string strname = "\\Device\\NPF_";
	strname += m_pCur->AdapterName;
	if ((m_adhandle = pcap_open(strname.c_str(),          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		20,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL)
	{
		return;
	}
	m_btn_search.SetWindowTextW(L"Searching");
	m_btn_search.EnableWindow(FALSE);
	StartSearch();
	/* ��ʼ���� */
	//pcap_loop(m_adhandle, 0, packet_handler, NULL);
	return;
}

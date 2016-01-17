
// winpacptestDlg.cpp : 实现文件
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


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CwinpacptestDlg 对话框
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
	//处理IP
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
			OutputDebugStringW(L"发送ARP包失败");
		}
		Sleep(10);
	}
	arpdata.DestinationIP = WStrToIP4(L"93.123.23.1");
	FillARPData((char*)pData, 60, &arpdata);
	OutputDebugStringW(IptoStr(arpdata.DestinationIP) + L"\r\n");
	if (pcap_sendpacket(pDlg->m_adhandle, (UCHAR*)pData, 60) != 0)
	{
		OutputDebugStringW(L"发送ARP包失败");
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
			/* 超时时间到 */
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


// CwinpacptestDlg 消息处理程序

void CwinpacptestDlg::InitList()
{
	m_property_list.RemoveAll();
	m_pPropertyCommon = new CMFCPropertyGridProperty(_T("信息"));
	m_pPropertyIP = new CMFCPropertyGridProperty(_T("IP列表"));
	m_pPropertyGateway = new CMFCPropertyGridProperty(_T("网关列表"));
	m_pPropertyDHCP = new CMFCPropertyGridProperty(_T("DHCP服务列表"));
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

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	InitInfo();
	InitList();
	InitIPList();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CwinpacptestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
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
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Name", StrToWstr(d->AdapterName), L"名字"));
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Description", StrToWstr(d->Description), L"描述"));
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"MAC", GetMAC(d->Address, d->AddressLength), L"硬件地址"));
	WCHAR pStr[32] = { 0 };
	_itow_s(d->Index, pStr, 10);
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Index", pStr, L"适配器索引"));
	CString strType;
	switch (d->Type)
	{
	case 1:
		strType = L"MIB_IF_TYPE_OTHER";
		strDescription = L"其他类型的适配器";
		break;
	case 6:
		strType = L"MIB_IF_TYPE_ETHERNET";
		strDescription = L"以太网适配器";
		break;
	case 9:
		strType = L"MIB_IF_TYPE_TOKENRING";
		strDescription = L"令牌环适配器";
		break;
	case 15:
		strType = L"MIB_IF_TYPE_FDDI";
		strDescription = L"FDDI（光纤分布数据接口）适配器";
		break;
	case 23:
		strType = L"MIB_IF_TYPE_PPP";
		strDescription = L"PPP适配器";
		break;
	case 24:
		strType = L"MIB_IF_TYPE_LOOPBACK";
		strDescription = L"Loopback适配器";
		break;
	case 28:
		strType = L"MIB_IF_TYPE_SLIP";
		strDescription = L"Slip适配器";
		break;
	}
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"Type", strType, strDescription));
	if (d->DhcpEnabled)
		strDescription = L"TRUE";
	else
		strDescription = L"FALSE";
	m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"DhcpEnabled", strDescription, L"是否开启DHCP"));
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
		m_pPropertyCommon->AddSubItem(new CMFCPropertyGridProperty(L"子网IP范围", strDescription, L"子网IP范围"));
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
		m_btn_search.SetWindowTextW(L"搜索局域网");
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

	// TODO: 在此处添加消息处理程序代码
	/* 不再需要设备列表了，释放它 */
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
	// TODO: 在此添加控件通知处理程序代码
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

	/* 将时间戳转换成可识别的格式 */
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
	if ((m_adhandle = pcap_open(strname.c_str(),          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		20,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		return;
	}
	m_btn_search.SetWindowTextW(L"Searching");
	m_btn_search.EnableWindow(FALSE);
	StartSearch();
	/* 开始捕获 */
	//pcap_loop(m_adhandle, 0, packet_handler, NULL);
	return;
}

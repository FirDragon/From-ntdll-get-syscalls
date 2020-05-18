#include <tchar.h>
#include <windows.h>
#include <WtsApi32.h>
#include <UserEnv.h>
#include <sddl.h>
#include <pathcch.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

static SERVICE_STATUS g_Status;
static SERVICE_STATUS_HANDLE g_hStatus;
static TCHAR SerName[] = _T("service");

static HANDLE g_hEvent;
static BOOL g_isRun = TRUE;

static VOID WINAPI DispatchServer(
	DWORD   dwNumServicesArgs,
	LPTSTR   *lpServiceArgVectors
);
static VOID WINAPI HandleDispatch(DWORD    dwControl);
static BOOL CreateActiveProcess(LPCTSTR lpApplication);

#define GLOBAL_SEC_DESC	_T("A:")\
			TEXT("(A;OICI;GRGWGX;;;AU)")

#define CREATE_EVENT		_T("Global\\CreateEvent")

int _tmain() {
	
	SERVICE_TABLE_ENTRY entry[2];
	entry->lpServiceName = SerName;
	entry->lpServiceProc = DispatchServer;
	entry[1].lpServiceName = NULL;
	entry[1].lpServiceProc = NULL;

	StartServiceCtrlDispatcher(entry);
		
	return NOERROR;
}
VOID WINAPI DispatchServer(
	DWORD   dwNumServicesArgs,
	LPTSTR   *lpServiceArgVectors
)
{
	g_hStatus = RegisterServiceCtrlHandler(SerName, HandleDispatch);
	if (!g_hStatus)
		return;

	g_Status.dwCheckPoint = 0;
	g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_Status.dwCurrentState = SERVICE_RUNNING;
	g_Status.dwServiceSpecificExitCode = 0;
	g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_Status.dwWaitHint = 0;
	g_Status.dwWin32ExitCode = 0;

	if (!SetServiceStatus(g_hStatus, &g_Status))
		return;

	TCHAR msg[] = _T("This is a message box");
	TCHAR title[] = _T("box");
	DWORD dwResponse;
	WTSSendMessage(
		WTS_CURRENT_SERVER_HANDLE,
		WTSGetActiveConsoleSessionId(),
		title, lstrlen(title),
		msg, lstrlen(msg),
		0, 0, 
		&dwResponse, FALSE);
	do {
		SECURITY_DESCRIPTOR SecDese;
		InitializeSecurityDescriptor(&SecDese, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&SecDese, TRUE, NULL, FALSE);
		SECURITY_ATTRIBUTES SecAttr;
		SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		SecAttr.bInheritHandle = FALSE;
		SecAttr.lpSecurityDescriptor = &SecDese;

		g_hEvent = CreateEvent(&SecAttr, FALSE, FALSE, CREATE_EVENT);
		if (!g_hEvent)
			break;

		while (WaitForSingleObject(g_hEvent, INFINITE) == ERROR_SUCCESS && g_isRun)
			if (!CreateActiveProcess(_T("C:\\Windows\\System32\\cmd.exe")))
				break;

		g_Status.dwWin32ExitCode = GetLastError();
		g_Status.dwCurrentState = SERVICE_STOPPED;
		CloseHandle(g_hEvent);
		SetServiceStatus(g_hStatus, &g_Status);
		return;
	} while (FALSE);

	g_Status.dwWin32ExitCode = GetLastError();
	g_Status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(g_hStatus, &g_Status);
}

BOOL CreateActiveProcess(LPCTSTR lpApplication) 
{
	BOOL result = FALSE;

	DWORD ActiveSessionId;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	LPVOID lpEnv = NULL;
	PROCESS_INFORMATION ProcesInfo = { 0 };

	do {
		ActiveSessionId  = WTSGetActiveConsoleSessionId();

		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
			break;

		if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNewToken))
			break;

		if (!SetTokenInformation(hNewToken, TokenSessionId, (LPVOID)&ActiveSessionId, sizeof(ActiveSessionId)))
			break;

		if (!CreateEnvironmentBlock(&lpEnv, hToken, TRUE))
			break;

		STARTUPINFO StartupInfo = { 0 };
		ZeroMemory(&StartupInfo, sizeof(StartupInfo));
		StartupInfo.cb = sizeof(STARTUPINFO);
		StartupInfo.lpDesktop = (LPTSTR)_T("WinSta0\\Default");
		
		if (!CreateProcessAsUser(
			hNewToken,
			lpApplication,
			NULL,
			NULL,
			NULL,
			FALSE,
			CREATE_UNICODE_ENVIRONMENT | NORMAL_PRIORITY_CLASS,
			lpEnv,
			NULL,
			&StartupInfo,
			&ProcesInfo
			))
			break;

		ActiveSessionId = 0;
		if (!SetTokenInformation(hNewToken, TokenSessionId, (LPVOID)&ActiveSessionId, sizeof(ActiveSessionId)))
			break;

		result = TRUE;
	} while (FALSE);

	if (hToken)
		CloseHandle(hToken);
	
	if (hNewToken)
		CloseHandle(hNewToken);

	if (lpEnv)
		DestroyEnvironmentBlock(lpEnv);

	return result;
}

VOID WINAPI HandleDispatch(DWORD    dwControl) 
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_STOP:
		g_isRun = FALSE;
		SetEvent(g_hEvent);
	default:
		break;
	}
}
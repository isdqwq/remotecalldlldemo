// ssss.cpp : Defines the entry point for the console application.
//
#include "StdAfx.h" 
#include <windows.h>  
//#include <WinDef.h>
#include <tlhelp32.h>  

// #pragma comment(lib,"kernel32")  
// 
// #pragma comment(lib,"user32")  
//   
// #pragma comment(linker, "/subsystem:windows")  
// 
// #pragma comment(linker, "/entry:main") 

#ifdef _DEBUG
#define  TRACE _trace
#else
#define  TRACE
#endif
void _trace(char *fmt,...)
{
	char out[1024];
	va_list body;
	va_start(body,fmt);
	vsprintf_s(out,fmt,body);
	va_end(body);
	OutputDebugStringA(out);
}


typedef int (WINAPI *DLL_LOAD)(DWORD); 

struct RemoteParam {  
	SIZE_T dwRemoteFun;     // MessageBox ��������ڵ�ַ  
	DWORD ul_reason_for_call; // MessageBox ����������  
	//LPVOID lpReserved;     // MessageBox �����ı���  
}; 


typedef struct _REMOTE_PARAMETER
{
	CHAR m_msgContent[MAX_PATH];
	CHAR m_msgTitle[MAX_PATH];
	DWORD m_dwMessageBoxAddr;
}RemotePara, * PRemotePara;

DWORD GetProcessId(LPCSTR lpszProcessName); 

DWORD WINAPI RemoteFunction(PRemotePara pRemotePara);

BOOL WriteDataToProcess(HANDLE hProcess, LPVOID lPWriteData, LPVOID& DataAddress,SIZE_T size);
BOOL EnableDebugPrevilige(BOOL fEnable);

void GetMessageBoxParameter(PRemotePara pRemotePara);
// ��ȡ���̱�ʶ�� 

DWORD GetProcessId(LPCSTR lpszProcessName) 
{  
	// �������̿��վ��  
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);  
	DWORD dwPid = NULL;  
	PROCESSENTRY32 ProcessEntry;  
	// ���ҵ�һ������  
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);  
	Process32First(hProcessSnap, &ProcessEntry);  
	// �������̻�ȡ PID  
	do 
	{ 
		if(!stricmp(ProcessEntry.szExeFile, lpszProcessName)) 
		{  
			dwPid = ProcessEntry.th32ProcessID;  
			break;  
		}  
	} 
	while(Process32Next(hProcessSnap, &ProcessEntry));  
	// �����ֳ�  
	if(!dwPid) 
	{     
		return false;  
	} 
	CloseHandle(hProcessSnap);  
	return dwPid;  
} 
BOOL EnableDebugPrevilige(BOOL fEnable)
{
	// Enabling the debug privilege allows the application to see
	// information about service applications
	BOOL fOk = FALSE;    // Assume function fails
	HANDLE hToken;

	// Try to open this process's access token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, 
		&hToken)) {

			// Attempt to modify the "Debug" privilege
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
			tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
			fOk = (GetLastError() == ERROR_SUCCESS);
			CloseHandle(hToken);
	}
	return(fOk);
}
// ������ں��� 

int main() 
{  
	char DllPath[MAX_PATH]={0};
	SIZE_T stData=0;
	// �߳�ջ��С  
	const SIZE_T stThreadSize = 2048;  
	// ��ȡָ��ӳ��� PID  
	DWORD dwProcessId = false;  
	// Զ�̽��̵�handle
	HANDLE hRemoteProcess;
	// ����Զ��ִ�к�����λ��
	LPVOID pRemoteFunctionArea;
	// ����Զ��ִ�к����Ĳ���λ�� 
	LPVOID pRemoteParaPlace;

	RemotePara MessgeBoxPara;

	EnableDebugPrevilige(TRUE);
	dwProcessId = GetProcessId("DemoDllTest.exe");  
	if (!dwProcessId){  
		MessageBox(NULL, "Get remote process ID failed !", "Notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  

	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);  
	if (!hRemoteProcess){  
		MessageBox(NULL, "Open remote process failed !", "Notice", MB_ICONINFORMATION | MB_OK);  
		return 0;  
	}  
	// ������������Ϊ�߳��忪��һ��洢����  
	// ��������Ҫע�� MEM_COMMIT | MEM_RESERVE �ڴ��������  
	// �Լ� PAGE_EXECUTE_READWRITE �ڴ汣������  
	// ����庬����ο� MSDN �й��� VirtualAllocEx ������˵�� 
	WriteDataToProcess(hRemoteProcess,(LPVOID)&RemoteFunction,pRemoteFunctionArea,stThreadSize);

	ZeroMemory(&MessgeBoxPara,sizeof(RemotePara));
	GetMessageBoxParameter(&MessgeBoxPara);

	WriteDataToProcess(hRemoteProcess,(LPVOID)&MessgeBoxPara,pRemoteParaPlace,sizeof(RemotePara));
	
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (DWORD (WINAPI *)(LPVOID))pRemoteFunctionArea, pRemoteParaPlace, 0, NULL);
	int x = GetLastError();
 
	// �ȴ��̷߳���  
	WaitForSingleObject(hRemoteThread, INFINITE);  
	// �ͷŽ��̿ռ��е��ڴ�  
	VirtualFreeEx(hRemoteProcess, pRemoteParaPlace, 0, MEM_RELEASE);  
	VirtualFreeEx(hRemoteProcess, pRemoteFunctionArea, 0, MEM_RELEASE);

	// �ر�Զ�̾��  

	CloseHandle(hRemoteThread);  
	CloseHandle(hRemoteProcess);
	EnableDebugPrevilige(FALSE);
	return 0;  
}  

//=====================================================================================//
//Name: void GetMessageBoxParameter(PRemotePara pRemotePara)                           //
//                                                                                     //
//Descripion: ��� MessageBox ��� API �ĵ�ַ�Լ����Ĳ���                                     //
//=====================================================================================//
void GetMessageBoxParameter(PRemotePara pRemotePara)
{
	HMODULE hUser32 = LoadLibrary("User32.dll");

	pRemotePara->m_dwMessageBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	strcat(pRemotePara->m_msgContent, "Hello, Fusong li !\0");
	strcat(pRemotePara->m_msgTitle, "Hello\0");
	//ע��Ҫ�ͷŵ� User32
	FreeLibrary(hUser32);
}

BOOL WriteDataToProcess(HANDLE hProcess, LPVOID lPWriteData, LPVOID& DataAddress,SIZE_T size)
{
	DataAddress = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == DataAddress)
		return FALSE;

	SIZE_T dwJudge = NULL;
	BOOL iYON = WriteProcessMemory(hProcess, DataAddress, lPWriteData,size, &dwJudge);
	//wchar_t buf[MAX_PATH];
	//iYON=ReadProcessMemory(hProcess,DataAddress,buf,size,&dwJudge);

	if (0 == iYON || 0 == dwJudge)
		return FALSE;

	return TRUE;
}
// Զ��ִ�к���  
DWORD WINAPI RemoteFunction(PRemotePara pRemotePara) 
{
	//��� MessageBox �ĵ�ַ�������ⲿ�������룬��Ϊ��������������Ҫ�ض���
	typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

	MESSAGEBOXA MessageBoxA;
	MessageBoxA = (MESSAGEBOXA)pRemotePara->m_dwMessageBoxAddr;

	//���� MessageBoxA ����ӡ��Ϣ
	MessageBoxA(NULL, pRemotePara->m_msgContent, pRemotePara->m_msgTitle, MB_OK);
	return 0;  
}

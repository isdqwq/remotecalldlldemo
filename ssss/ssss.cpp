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
	SIZE_T dwRemoteFun;     // MessageBox 函数的入口地址  
	DWORD ul_reason_for_call; // MessageBox 函数的内容  
	//LPVOID lpReserved;     // MessageBox 函数的标题  
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
// 获取进程标识符 

DWORD GetProcessId(LPCSTR lpszProcessName) 
{  
	// 创建进程快照句柄  
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);  
	DWORD dwPid = NULL;  
	PROCESSENTRY32 ProcessEntry;  
	// 查找第一个进程  
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);  
	Process32First(hProcessSnap, &ProcessEntry);  
	// 遍历进程获取 PID  
	do 
	{ 
		if(!stricmp(ProcessEntry.szExeFile, lpszProcessName)) 
		{  
			dwPid = ProcessEntry.th32ProcessID;  
			break;  
		}  
	} 
	while(Process32Next(hProcessSnap, &ProcessEntry));  
	// 清理现场  
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
// 程序入口函数 

int main() 
{  
	char DllPath[MAX_PATH]={0};
	SIZE_T stData=0;
	// 线程栈大小  
	const SIZE_T stThreadSize = 2048;  
	// 获取指定映像的 PID  
	DWORD dwProcessId = false;  
	// 远程进程的handle
	HANDLE hRemoteProcess;
	// 保存远程执行函数的位置
	LPVOID pRemoteFunctionArea;
	// 保存远程执行函数的参数位置 
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
	// 在宿主进程中为线程体开辟一块存储区域  
	// 在这里需要注意 MEM_COMMIT | MEM_RESERVE 内存非配类型  
	// 以及 PAGE_EXECUTE_READWRITE 内存保护类型  
	// 其具体含义请参考 MSDN 中关于 VirtualAllocEx 函数的说明 
	WriteDataToProcess(hRemoteProcess,(LPVOID)&RemoteFunction,pRemoteFunctionArea,stThreadSize);

	ZeroMemory(&MessgeBoxPara,sizeof(RemotePara));
	GetMessageBoxParameter(&MessgeBoxPara);

	WriteDataToProcess(hRemoteProcess,(LPVOID)&MessgeBoxPara,pRemoteParaPlace,sizeof(RemotePara));
	
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (DWORD (WINAPI *)(LPVOID))pRemoteFunctionArea, pRemoteParaPlace, 0, NULL);
	int x = GetLastError();
 
	// 等待线程返回  
	WaitForSingleObject(hRemoteThread, INFINITE);  
	// 释放进程空间中的内存  
	VirtualFreeEx(hRemoteProcess, pRemoteParaPlace, 0, MEM_RELEASE);  
	VirtualFreeEx(hRemoteProcess, pRemoteFunctionArea, 0, MEM_RELEASE);

	// 关闭远程句柄  

	CloseHandle(hRemoteThread);  
	CloseHandle(hRemoteProcess);
	EnableDebugPrevilige(FALSE);
	return 0;  
}  

//=====================================================================================//
//Name: void GetMessageBoxParameter(PRemotePara pRemotePara)                           //
//                                                                                     //
//Descripion: 获得 MessageBox 这个 API 的地址以及填充的参数                                     //
//=====================================================================================//
void GetMessageBoxParameter(PRemotePara pRemotePara)
{
	HMODULE hUser32 = LoadLibrary("User32.dll");

	pRemotePara->m_dwMessageBoxAddr = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	strcat(pRemotePara->m_msgContent, "Hello, Fusong li !\0");
	strcat(pRemotePara->m_msgTitle, "Hello\0");
	//注意要释放掉 User32
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
// 远程执行函数  
DWORD WINAPI RemoteFunction(PRemotePara pRemotePara) 
{
	//这个 MessageBox 的地址必须由外部参数传入，因为在其他进程中需要重定向
	typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

	MESSAGEBOXA MessageBoxA;
	MessageBoxA = (MESSAGEBOXA)pRemotePara->m_dwMessageBoxAddr;

	//调用 MessageBoxA 来打印消息
	MessageBoxA(NULL, pRemotePara->m_msgContent, pRemotePara->m_msgTitle, MB_OK);
	return 0;  
}

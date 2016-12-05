#include "Main.h"

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

BOOL APIENTRY DllMain(HANDLE hModule, 
					  DWORD ul_reason_for_call, 
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		TRACE("process attach of dll\n");
		//Dll_Load(hModule,ul_reason_for_call,lpReserved);
		break;
	case DLL_THREAD_ATTACH:
		TRACE("thread attach of dll\n");
		break;
	case DLL_THREAD_DETACH:
		TRACE("thread detach of dll\n");
		break;
	case DLL_PROCESS_DETACH:
		TRACE("process detach of dll\n");
		//Dll_UnLoad();
		break;
	}
	return TRUE;
}

void __declspec(dllexport)Dll_Load(DWORD ul_reason_for_call)
{
	TRACE("%s %x\n",__FUNCTION__,ul_reason_for_call);
}
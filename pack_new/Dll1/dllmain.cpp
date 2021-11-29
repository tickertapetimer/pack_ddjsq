// Shell.cpp : 定义 DLL 应用程序的导出函数。
//

#include "pch.h"
#include "dllmain.h"

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

void Start();					//启动函数(Shell部分的入口函数)
DWORD dwImageBase = 0;		//整个程序的镜像基址
SHELL_DATA g_stcShellData = { (DWORD)Start };

__declspec(naked) void Start()
{
	//获取函数的API地址
	//GetApis();
	//跳转到原始OEP
	//g_stcShellData.dwPEOEP += dwImageBase;
	dwImageBase = g_stcShellData.dwPEOEP + g_stcShellData.dwPEImageBase;
	__asm
	{
		jmp dwImageBase;
	}
}

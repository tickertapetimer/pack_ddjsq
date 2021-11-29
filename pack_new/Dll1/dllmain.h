#ifdef SHELL_EXPORTS
#define SHELL_API __declspec(dllexport)
#else
#define SHELL_API __declspec(dllimport)
#endif

//导出ShellData结构体
extern"C"  typedef struct _SHELL_DATA
{
	DWORD dwStartFun;							//启动函数
	DWORD dwPEOEP;								//程序入口点
	DWORD dwPEImageBase;						//PE文件映像基址

	IMAGE_DATA_DIRECTORY	stcPERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		//导入表信息

	DWORD					dwIATSectionBase;	//IAT所在段基址
	DWORD					dwIATSectionSize;	//IAT所在段大小

}SHELL_DATA, * PSHELL_DATA;

//导出ShellData结构体变量
extern"C" SHELL_API SHELL_DATA g_stcShellData;
#include<Windows.h>
#include<Psapi.h>
#include"../Dll1/dllmain.h"

HANDLE		hPEfile;	//PE文件句柄
LPBYTE		PEfileBuf;  //PE文件缓冲区
DWORD		PEsize;     //PE文件大小
DWORD		ImageBase;  //镜像基址
DWORD		ImageSize;  //镜像大小
PIMAGE_DOS_HEADER		pDOSheader;  //DOS头
PIMAGE_NT_HEADERS		pNTheader;   //NT头
PIMAGE_SECTION_HEADER	pSECheader;  //第一个section指针
DWORD		PEoep;		//原PE入口点
DWORD		DLLoep;   //DLL的入口点，即新PE的入口点
DWORD		SecNum;     //区段数量
DWORD		AliMent;    //内存对齐
DWORD		FileAlign;  //文件对齐

HMODULE hDLL;			//DLL句柄
PBYTE DLLbuf;			//DLL缓冲区

//获取PE各信息
void GetPEinfo()
{
	PEsize = GetFileSize(hPEfile, NULL);
	
	PEfileBuf = new BYTE[PEsize];
	DWORD ReadSize = 0;
	ReadFile(hPEfile, PEfileBuf, PEsize, &ReadSize, NULL);//拷贝PE文件到缓冲区
	CloseHandle(hPEfile);

	pDOSheader = (PIMAGE_DOS_HEADER)PEfileBuf;
	pNTheader = (PIMAGE_NT_HEADERS)(PEfileBuf + pDOSheader->e_lfanew);
	ImageBase = pNTheader->OptionalHeader.ImageBase;
	PEoep = pNTheader->OptionalHeader.AddressOfEntryPoint;
	pSECheader = IMAGE_FIRST_SECTION(pNTheader);
	SecNum = pNTheader->FileHeader.NumberOfSections;
	ImageSize = pNTheader->OptionalHeader.SizeOfImage;
	FileAlign = pNTheader->OptionalHeader.FileAlignment;
}

//粒度对齐处理
void Align()
{
	AliMent = pNTheader->OptionalHeader.SectionAlignment;
	if (ImageBase % AliMent)
		ImageBase = (ImageBase / AliMent + 1) * AliMent;
}

//OEP设置
void SetOep()
{
	pNTheader->OptionalHeader.AddressOfEntryPoint = DLLoep + ImageSize;
}



//将DLL数据拷贝到PE文件后面
void CopyBuf(LPBYTE DLLbuf, DWORD DLLSize, LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//获取最后一个区段的信息
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PEfileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(PEfileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.修改区段数量
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.编辑区段表头结构体信息
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".ddjsq", 7);

	//VOffset(1000对齐)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / AliMent) * AliMent;
	if (pLastSection->Misc.VirtualSize % AliMent)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize（实际添加的大小）
	AddSectionHeader->Misc.VirtualSize = DLLSize;

	//ROffset（旧文件的末尾）
	AddSectionHeader->PointerToRawData = ImageSize;

	//RSize(200对齐)
	dwTemp = (DLLSize / FileAlign) * FileAlign;
	if (DLLSize % FileAlign)
	{
		dwTemp += FileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//标志
	AddSectionHeader->Characteristics = 0XE00000E0;

	//3.修改PE头文件大小属性，增加文件大小
	dwTemp = (DLLSize / AliMent) * AliMent;
	if (DLLSize % AliMent)
	{
		dwTemp += AliMent;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.申请合并所需要的空间
	pFinalBuf = new BYTE[ImageSize + dwTemp];
	pFinalBufSize = ImageSize + dwTemp;
	memset(pFinalBuf, 0, ImageSize + dwTemp);
	memcpy_s(pFinalBuf, ImageSize, PEfileBuf, ImageSize);
	memcpy_s(pFinalBuf + ImageSize, dwTemp, DLLbuf, dwTemp);
}

//修复DLL重定位
BOOL SetShellReloc(LPBYTE pShellBuf, DWORD hShell)
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, * PTYPEOFFSET;

	//1.获取被加壳PE文件的重定位目录表指针信息
	PIMAGE_DATA_DIRECTORY pPERelocDir =
		&(pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	//2.获取Shell的重定位表指针信息
	PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pShellRelocDir =
		&(pShellNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION	pShellReloc =
		(PIMAGE_BASE_RELOCATION)((DWORD)pShellBuf + pShellRelocDir->VirtualAddress);

	//3.还原修复重定位信息
	//由于Shell.dll是通过LoadLibrary加载的，所以系统会对其进行一次重定位
	//我们需要把Shell.dll的重定位信息恢复到系统没加载前的样子，然后在写入被加壳文件的末尾
	PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pShellReloc + 1);
	DWORD dwNumber = (pShellReloc->SizeOfBlock - 8) / 2;

	for (DWORD i = 0; i < dwNumber; i++)
	{
		if (*(PWORD)(&pTypeOffset[i]) == NULL)
			break;
		//RVA
		DWORD dwRVA = pTypeOffset[i].offset + pShellReloc->VirtualAddress;
		//FAR地址（LordPE中这样标注）
		//***新的重定位地址=重定位后的地址-加载时的镜像基址+新的镜像基址+代码基址(PE文件镜像大小)
		DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)pShellBuf + dwRVA);
		*(PDWORD)((DWORD)pShellBuf + dwRVA)
			= AddrOfNeedReloc - pShellNtHeader->OptionalHeader.ImageBase + ImageBase + ImageSize;
	}
	//3.1修改Shell重定位表中.text的RVA
	pShellReloc->VirtualAddress += ImageSize;

	//4.修改PE重定位目录指针，指向Shell的重定位表信息
	pPERelocDir->Size = pShellRelocDir->Size;
	pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + ImageSize;

	return TRUE;
}

BOOL SaveFile(LPBYTE pFinalBuf, DWORD pFinalBufSize)
{
	//修正区段信息中 文件对齐大小（文件对齐大小同内存对齐大小）
	/*PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFinalBuf + pDOSheader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		pSectionHeader->PointerToRawData = pSectionHeader->VirtualAddress;
	}*/

	//清除不需要的目录表信息
	//只留输出表，重定位表，资源表
	/*DWORD dwCount = 15;
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (i != IMAGE_DIRECTORY_ENTRY_EXPORT &&
			i != IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			i != IMAGE_DIRECTORY_ENTRY_BASERELOC)
		{
			pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
			pNtHeader->OptionalHeader.DataDirectory[i].Size = 0;
		}
	}*/
	char path[] = "D:\\desktop\\实验\\反编译\\test_ddjsq.exe";
	HANDLE hFile = CreateFileA(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	DWORD Buf = 0;
	WriteFile(hFile, pFinalBuf, pFinalBufSize, &Buf, NULL);
	CloseHandle(hFile);
	return true;
}

//读取DLL
void readDLL()
{
	hDLL = LoadLibrary(L"Dll1.dll");
	PSHELL_DATA DLLdata = (PSHELL_DATA)GetProcAddress(hDLL, "g_stcShellData");

	DLLdata->dwPEOEP = PEoep;
	DLLdata->dwPEImageBase = ImageBase;

	MODULEINFO dllinfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), hDLL, &dllinfo, sizeof(MODULEINFO));
	DLLbuf = new BYTE[dllinfo.SizeOfImage];
	memcpy_s(DLLbuf, dllinfo.SizeOfImage, hDLL, dllinfo.SizeOfImage);
	SetShellReloc(DLLbuf, (DWORD)hDLL);
	DLLoep = DLLdata->dwStartFun - (DWORD)hDLL;
	SetOep();
	LPBYTE pFinalBuf = NULL;
	DWORD dwFinalBufSize = 0;
	CopyBuf(DLLbuf, dllinfo.SizeOfImage, pFinalBuf, dwFinalBufSize);
	SaveFile(pFinalBuf, dwFinalBufSize);
}

//打开PE文件
BOOL OpenPeFiles(const char* path)
{
	hPEfile = CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hPEfile == INVALID_HANDLE_VALUE)
	{
		//printf("打开文件失败");
		return false;
	}
	GetPEinfo();
	Align();
	return true;
}
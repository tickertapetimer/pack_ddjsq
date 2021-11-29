#include<Windows.h>
#include<Psapi.h>
#include"../Dll1/dllmain.h"

HANDLE		hPEfile;	//PE�ļ����
LPBYTE		PEfileBuf;  //PE�ļ�������
DWORD		PEsize;     //PE�ļ���С
DWORD		ImageBase;  //�����ַ
DWORD		ImageSize;  //�����С
PIMAGE_DOS_HEADER		pDOSheader;  //DOSͷ
PIMAGE_NT_HEADERS		pNTheader;   //NTͷ
PIMAGE_SECTION_HEADER	pSECheader;  //��һ��sectionָ��
DWORD		PEoep;		//ԭPE��ڵ�
DWORD		DLLoep;   //DLL����ڵ㣬����PE����ڵ�
DWORD		SecNum;     //��������
DWORD		AliMent;    //�ڴ����
DWORD		FileAlign;  //�ļ�����

HMODULE hDLL;			//DLL���
PBYTE DLLbuf;			//DLL������

//��ȡPE����Ϣ
void GetPEinfo()
{
	PEsize = GetFileSize(hPEfile, NULL);
	
	PEfileBuf = new BYTE[PEsize];
	DWORD ReadSize = 0;
	ReadFile(hPEfile, PEfileBuf, PEsize, &ReadSize, NULL);//����PE�ļ���������
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

//���ȶ��봦��
void Align()
{
	AliMent = pNTheader->OptionalHeader.SectionAlignment;
	if (ImageBase % AliMent)
		ImageBase = (ImageBase / AliMent + 1) * AliMent;
}

//OEP����
void SetOep()
{
	pNTheader->OptionalHeader.AddressOfEntryPoint = DLLoep + ImageSize;
}



//��DLL���ݿ�����PE�ļ�����
void CopyBuf(LPBYTE DLLbuf, DWORD DLLSize, LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//��ȡ���һ�����ε���Ϣ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PEfileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(PEfileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.�޸���������
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.�༭���α�ͷ�ṹ����Ϣ
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".ddjsq", 7);

	//VOffset(1000����)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / AliMent) * AliMent;
	if (pLastSection->Misc.VirtualSize % AliMent)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize��ʵ����ӵĴ�С��
	AddSectionHeader->Misc.VirtualSize = DLLSize;

	//ROffset�����ļ���ĩβ��
	AddSectionHeader->PointerToRawData = ImageSize;

	//RSize(200����)
	dwTemp = (DLLSize / FileAlign) * FileAlign;
	if (DLLSize % FileAlign)
	{
		dwTemp += FileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//��־
	AddSectionHeader->Characteristics = 0XE00000E0;

	//3.�޸�PEͷ�ļ���С���ԣ������ļ���С
	dwTemp = (DLLSize / AliMent) * AliMent;
	if (DLLSize % AliMent)
	{
		dwTemp += AliMent;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.����ϲ�����Ҫ�Ŀռ�
	pFinalBuf = new BYTE[ImageSize + dwTemp];
	pFinalBufSize = ImageSize + dwTemp;
	memset(pFinalBuf, 0, ImageSize + dwTemp);
	memcpy_s(pFinalBuf, ImageSize, PEfileBuf, ImageSize);
	memcpy_s(pFinalBuf + ImageSize, dwTemp, DLLbuf, dwTemp);
}

//�޸�DLL�ض�λ
BOOL SetShellReloc(LPBYTE pShellBuf, DWORD hShell)
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;			//ƫ��ֵ
		WORD Type : 4;			//�ض�λ����(��ʽ)
	}TYPEOFFSET, * PTYPEOFFSET;

	//1.��ȡ���ӿ�PE�ļ����ض�λĿ¼��ָ����Ϣ
	PIMAGE_DATA_DIRECTORY pPERelocDir =
		&(pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	//2.��ȡShell���ض�λ��ָ����Ϣ
	PIMAGE_DOS_HEADER		pShellDosHeader = (PIMAGE_DOS_HEADER)pShellBuf;
	PIMAGE_NT_HEADERS		pShellNtHeader = (PIMAGE_NT_HEADERS)(pShellBuf + pShellDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pShellRelocDir =
		&(pShellNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION	pShellReloc =
		(PIMAGE_BASE_RELOCATION)((DWORD)pShellBuf + pShellRelocDir->VirtualAddress);

	//3.��ԭ�޸��ض�λ��Ϣ
	//����Shell.dll��ͨ��LoadLibrary���صģ�����ϵͳ��������һ���ض�λ
	//������Ҫ��Shell.dll���ض�λ��Ϣ�ָ���ϵͳû����ǰ�����ӣ�Ȼ����д�뱻�ӿ��ļ���ĩβ
	PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pShellReloc + 1);
	DWORD dwNumber = (pShellReloc->SizeOfBlock - 8) / 2;

	for (DWORD i = 0; i < dwNumber; i++)
	{
		if (*(PWORD)(&pTypeOffset[i]) == NULL)
			break;
		//RVA
		DWORD dwRVA = pTypeOffset[i].offset + pShellReloc->VirtualAddress;
		//FAR��ַ��LordPE��������ע��
		//***�µ��ض�λ��ַ=�ض�λ��ĵ�ַ-����ʱ�ľ����ַ+�µľ����ַ+�����ַ(PE�ļ������С)
		DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)pShellBuf + dwRVA);
		*(PDWORD)((DWORD)pShellBuf + dwRVA)
			= AddrOfNeedReloc - pShellNtHeader->OptionalHeader.ImageBase + ImageBase + ImageSize;
	}
	//3.1�޸�Shell�ض�λ����.text��RVA
	pShellReloc->VirtualAddress += ImageSize;

	//4.�޸�PE�ض�λĿ¼ָ�룬ָ��Shell���ض�λ����Ϣ
	pPERelocDir->Size = pShellRelocDir->Size;
	pPERelocDir->VirtualAddress = pShellRelocDir->VirtualAddress + ImageSize;

	return TRUE;
}

BOOL SaveFile(LPBYTE pFinalBuf, DWORD pFinalBufSize)
{
	//����������Ϣ�� �ļ������С���ļ������Сͬ�ڴ�����С��
	/*PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFinalBuf + pDOSheader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		pSectionHeader->PointerToRawData = pSectionHeader->VirtualAddress;
	}*/

	//�������Ҫ��Ŀ¼����Ϣ
	//ֻ��������ض�λ����Դ��
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
	char path[] = "D:\\desktop\\ʵ��\\������\\test_ddjsq.exe";
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

//��ȡDLL
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

//��PE�ļ�
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
		//printf("���ļ�ʧ��");
		return false;
	}
	GetPEinfo();
	Align();
	return true;
}
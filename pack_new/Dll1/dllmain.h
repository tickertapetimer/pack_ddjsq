#ifdef SHELL_EXPORTS
#define SHELL_API __declspec(dllexport)
#else
#define SHELL_API __declspec(dllimport)
#endif

//����ShellData�ṹ��
extern"C"  typedef struct _SHELL_DATA
{
	DWORD dwStartFun;							//��������
	DWORD dwPEOEP;								//������ڵ�
	DWORD dwPEImageBase;						//PE�ļ�ӳ���ַ

	IMAGE_DATA_DIRECTORY	stcPERelocDir;		//�ض�λ����Ϣ
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		//�������Ϣ

	DWORD					dwIATSectionBase;	//IAT���ڶλ�ַ
	DWORD					dwIATSectionSize;	//IAT���ڶδ�С

}SHELL_DATA, * PSHELL_DATA;

//����ShellData�ṹ�����
extern"C" SHELL_API SHELL_DATA g_stcShellData;
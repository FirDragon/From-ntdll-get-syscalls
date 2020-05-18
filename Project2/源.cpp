#include <stdio.h>
#include <windows.h>
#include <tchar.h>

typedef struct _MAPINFO
{
	HANDLE hFile;
	HANDLE hMapFile;
	LARGE_INTEGER FileSize;
	SIZE_T szMapSize;
	PBYTE lpMem;
}MAPINFO, *PMAPINFO;

typedef struct _EDT_ITEM
{
	LONG_PTR addr;
	LPCSTR name;
}EDT_ITEM, *PEDT_ITEM;

typedef struct _SYSCALL_INFO
{
	DWORD FuncId;
	DWORD EDTId;
}SYSCALL_INFO, *PSYSCALL_INFO;

static DWORD ScanSyscall(PBYTE addr);
static LRESULT MapPE(LPCTSTR FileName, PMAPINFO pMapinfo);
static LRESULT GetExpTableFromMem(LPVOID pMem, PIMAGE_EXPORT_DIRECTORY *pExportAddr);
static LRESULT GetEDTFunArr(
	LPBYTE pBase,
	PIMAGE_EXPORT_DIRECTORY pExp,
	PEDT_ITEM edtItem,
	DWORD cbItemSize,
	PDWORD cbNeedSize
);
static LRESULT ScanDllSyscall(PEDT_ITEM pEdt, DWORD dwCount, PSYSCALL_INFO syscall);
static void PrintSyscallList(PSYSCALL_INFO syscalls, PEDT_ITEM edt, DWORD dwCount, BOOL OutputInvalid);
static PBYTE CvtVAToFA(PBYTE base, PBYTE va);
static void UnMapPE(PMAPINFO mapInfo);

int main(int argc, char **argv)
{
	LRESULT result = ERROR_SUCCESS;
	MAPINFO mapInfo;
	LPCTSTR lpFileName = _T("C:\\windows\\system32\\ntdll.dll");
	PIMAGE_EXPORT_DIRECTORY expMem = NULL;
	PEDT_ITEM edts = NULL;
	PSYSCALL_INFO syscalls = NULL;

	result = MapPE(lpFileName, &mapInfo);
	if (result)
	{
		printf("map failed!\n");
		goto failed;
	}
	result  = GetExpTableFromMem(mapInfo.lpMem, &expMem);
	if (result)
	{
		printf("Get EDT failed!\n");
		goto failed;
	}

	DWORD dwEdtCount;
	PIMAGE_EXPORT_DIRECTORY vaExpMem;
	vaExpMem = (PIMAGE_EXPORT_DIRECTORY)CvtVAToFA(mapInfo.lpMem, (PBYTE)expMem);

	GetEDTFunArr(mapInfo.lpMem, vaExpMem, NULL, 0, &dwEdtCount);
	if (!dwEdtCount)
	{
		printf("GetEDTFunArr failed!\n");
		goto failed;
	}

	edts = (PEDT_ITEM)malloc(dwEdtCount * sizeof(EDT_ITEM));
	syscalls = (PSYSCALL_INFO)malloc(dwEdtCount * sizeof(SYSCALL_INFO));
	if (!edts || !syscalls)
		goto failed;

	result = GetEDTFunArr(mapInfo.lpMem, vaExpMem, edts, dwEdtCount, &dwEdtCount);
	if (result)
	{
		printf("Get Function array failed!\n");
		goto failed;
	}

	result = ScanDllSyscall(edts, dwEdtCount, syscalls);
	if (result)
	{
		printf("get dll syscall is failed!\n");
		goto failed;
	}

	BOOL isAll;
	isAll = argc > 1 && !strcmp(argv[1], "all");
	PrintSyscallList(syscalls, edts, dwEdtCount, isAll);

	UnMapPE(&mapInfo);
	return 0;
failed:
	printf("Error : %llx\n", result);
	UnMapPE(&mapInfo);
	return -1;
}
void PrintSyscallList(PSYSCALL_INFO syscalls , PEDT_ITEM edt, DWORD dwCount, BOOL OutputInvalid)
{
	;
	DWORD i;
	if (!syscalls || !dwCount || !edt)
		return;

	for (i = 0; i < dwCount; ++i)
		if (syscalls[i].FuncId != MAXDWORD)
			printf("|%.5d\t|%-60s|\n", syscalls[i].FuncId, edt[syscalls[i].EDTId].name);
		else if(OutputInvalid)
			printf("|%.5s\t|%-60s|\n", "Inval", edt[syscalls[i].EDTId].name);
}
LRESULT ScanDllSyscall(PEDT_ITEM pEdt, DWORD dwCount, PSYSCALL_INFO syscall)
{
	DWORD i;
	for (i = 0; i < dwCount; i++)
	{
		syscall[i].EDTId = i;
		syscall[i].FuncId = ScanSyscall((PBYTE)pEdt[i].addr);
	}
	return ERROR_SUCCESS;
}
DWORD ScanSyscall(PBYTE addr)
{
	if (!addr)
		return -1;
	while (*addr != 0xc3)
	{
		if (*(DWORD*)addr == 0XB8D18B4C)
			return *((DWORD*)addr + 1);
		++addr;
	}
	return -1;
}


PBYTE CvtVAToFA(PBYTE base,PBYTE va)
{
	LRESULT res = ERROR_SUCCESS;

	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNt;
	DWORD rva;
	DWORD EntrySizes;
	PIMAGE_SECTION_HEADER pSec;
	DWORD dwSecSize;
	DWORD i;
	DWORD Dist;

	if (!va)
		return NULL;

	rva = (DWORD)(va - base);
	pDos = (PIMAGE_DOS_HEADER)base;
	pNt = (PIMAGE_NT_HEADERS)(base + pDos->e_lfanew);
	dwSecSize = pNt->FileHeader.NumberOfSections;
	if (!dwSecSize)
		return NULL;

	EntrySizes = pNt->OptionalHeader.NumberOfRvaAndSizes;
	pSec = (PIMAGE_SECTION_HEADER)&pNt->OptionalHeader.DataDirectory[EntrySizes];

	for (i = 0 ; i < dwSecSize ; ++i)
	{
		Dist = (DWORD)(rva - pSec[i].VirtualAddress);

		if (Dist >= 0 && Dist < pSec[i].SizeOfRawData)
			return (PBYTE)(base + pSec[i].PointerToRawData + Dist);
	} 
	return NULL;
}

LRESULT GetEDTFunArr(
	LPBYTE pBase ,
	PIMAGE_EXPORT_DIRECTORY pExp,
	PEDT_ITEM edtItem, 
	DWORD cbItemSize, 
	PDWORD cbNeedSize
)
{
	LRESULT res = ERROR_SUCCESS;
	PDWORD Funcs;
	LONG_PTR  i;
	LONG_PTR  max;

	if (cbNeedSize)
		*cbNeedSize = pExp->NumberOfFunctions;

	max = pExp->NumberOfFunctions;
	if (max > cbItemSize)
	{
		res = ERROR_OUTOFMEMORY;
		goto failed;
	}

	Funcs = (PDWORD)(pBase + pExp->AddressOfFunctions);
	Funcs = (PDWORD)CvtVAToFA(pBase , (PBYTE)Funcs);

	for (i = 0; i < max; ++i)
	{
		edtItem[i].addr = (LONG_PTR)CvtVAToFA(pBase, pBase + Funcs[i]);
		edtItem[i].name = NULL;
	}
	
	PWORD pNameOrds;
	PDWORD pNames;
	pNameOrds = (PWORD)CvtVAToFA(pBase ,pBase + pExp->AddressOfNameOrdinals);
	pNames = (PDWORD)CvtVAToFA(pBase ,pBase + pExp->AddressOfNames);

	max = pExp->NumberOfNames;
	for (i = 0; i < max; ++i)
		edtItem[pNameOrds[i]].name = (LPCSTR)CvtVAToFA(pBase, pBase + pNames[i]);

failed:
	return res;
}

LRESULT GetExpTableFromMem(LPVOID pMem, PIMAGE_EXPORT_DIRECTORY *pExportAddr)
{
	LRESULT lRes = ERROR_SUCCESS;
	LPBYTE pBase;
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNt;

	if (!pMem || !pExportAddr)
		return ERROR_INVALID_PARAMETER;

	__try
	{
		pBase = (LPBYTE)pMem;
		pDos = (PIMAGE_DOS_HEADER)pBase;
		pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
		*pExportAddr = (PIMAGE_EXPORT_DIRECTORY)(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	return ERROR_SUCCESS;
}

void UnMapPE(PMAPINFO mapInfo)
{
	if (mapInfo->hFile)
	{
		CloseHandle(mapInfo->hFile);
		mapInfo->hFile = NULL;
	}
	if (mapInfo->hMapFile)
	{
		CloseHandle(mapInfo->hFile);
		mapInfo->hMapFile = NULL;
	}
	if (mapInfo->lpMem)
	{
		UnmapViewOfFile(mapInfo->lpMem);
		mapInfo->lpMem = NULL;
	}
}

LRESULT MapPE(LPCTSTR FileName, PMAPINFO pMapinfo) 
{
	LRESULT result = ERROR_SUCCESS;

	HANDLE hFile = NULL;
	HANDLE hMapFile = NULL;
	LARGE_INTEGER FileSize;
	LPVOID lpMem = NULL;
	SIZE_T MapSize;

	if (!pMapinfo)
	{
		result = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	hFile = 
	CreateFile(
		FileName, 
		FILE_READ_ACCESS, 
		FILE_SHARE_READ, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
	);
	if (!hFile)
		goto failed;

	GetFileSizeEx(hFile, &FileSize);
	if (!FileSize.QuadPart)
	{
		result = ERROR_FILE_INVALID;
		goto failed;
	}

	hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, FileSize.HighPart, FileSize.LowPart, NULL);
	if (!hMapFile)
		goto failed;

	MapSize = FileSize.HighPart ? MAXLONG : FileSize.LowPart;
	lpMem = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, MapSize);
	if (!lpMem)
		goto failed;

	pMapinfo->FileSize = FileSize;
	pMapinfo->hFile = hFile;
	pMapinfo->hMapFile = hMapFile;
	pMapinfo->szMapSize = MapSize;
	pMapinfo->lpMem = (PBYTE)lpMem;
	return result;

failed:
	
	if (hFile)
		CloseHandle(hFile);
	
	if (hMapFile)
		CloseHandle(hMapFile);

	return result;
}
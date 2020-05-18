// 实验失败，应用层可能无法调用NtMapViewOfSection函数

#include <tchar.h>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "user32.lib")

typedef enum _SECTION_INHERIT {
	ViewShare = 1, 
	ViewUnmap = 2 
}SECTION_INHERIT;

typedef NTSTATUS (*LPFN_ZW_CREATE_SECTION)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
);
typedef NTSTATUS (NTAPI *LPFN_MAP_VIEW_OF_SECTION)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN ULONG ZeroBits,
	IN ULONG CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PULONG ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Protect
);

#undef _tWinMain

int __fastcall _tWinMain(HINSTANCE, HINSTANCE, LPTSTR, INT)
{
	HMODULE hNtdll;
	LPFN_ZW_CREATE_SECTION pfZwCreateSection;
	PUNICODE_STRING uniImagePath;
	hNtdll = LoadLibrary(_T("ntdll.dll"));
	pfZwCreateSection = (LPFN_ZW_CREATE_SECTION)GetProcAddress(hNtdll, "NtCreateSection");
	LPFN_MAP_VIEW_OF_SECTION ZwMapViewOfSection = (LPFN_MAP_VIEW_OF_SECTION)GetProcAddress(hNtdll, "ZwMapViewOfSection");

	TCHAR FileName[MAX_PATH];
	GetModuleFileName(NULL, FileName, MAX_PATH);
	HANDLE hFile;
	hFile = CreateFile(FileName, GENERIC_EXECUTE | GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, _T("无法打开文件"), _T("Error"), MB_ICONERROR);
		FreeLibrary(hNtdll);
		return 0;
	}

	NTSTATUS Status;
	HANDLE hSection;
	OBJECT_ATTRIBUTES ObjAttr;
	LARGE_INTEGER lMaxSize;
	lMaxSize.LowPart = GetFileSize(hFile, (LPDWORD)&lMaxSize.HighPart);
	InitializeObjectAttributes(&ObjAttr, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = pfZwCreateSection(&hSection, SECTION_MAP_EXECUTE, &ObjAttr, &lMaxSize, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(Status)) {
		DebugBreak();
		CloseHandle(hFile);
		FreeLibrary(hNtdll);
		return 0;
	}
	LARGE_INTEGER OffsetSection;
	PVOID BaseAddr = 0;
	ULONG ViewSize = lMaxSize.QuadPart;
	Status = ZwMapViewOfSection(hSection, GetCurrentProcess(), &BaseAddr, 0, ViewSize, NULL, &ViewSize, ViewShare, 0, PAGE_READONLY);
	if (!NT_SUCCESS(Status)) {
		DebugBreak();
		CloseHandle(hFile);
		FreeLibrary(hNtdll);
		return 0;
	}


	DebugBreak();
	CloseHandle(hFile);
	CloseHandle(hSection);
	FreeLibrary(hNtdll);
	return 0;
}
//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#pragma once
#define _IMATINIB_

#define MAX_FPS_NAME_LEN		   512
#define MAX_FPS_MODULENAME_LEN	   512
#define MAX_FPS_FINGERPRINT_LEN    512
#define MAX_CODESIZE               64

typedef struct _FINGERPRINTSTRUCT
{
    DWORD   tid;
    DWORD   Offset;
	DWORD   PatchSize;
    DWORD   SavedPatchSize;
	DWORD   AddressFound;
	BOOL    branch_jump;
	char    Name[MAX_FPS_NAME_LEN];
	char    ModuleName[MAX_FPS_MODULENAME_LEN];
	char    FingerPrint[MAX_FPS_FINGERPRINT_LEN];
    char    DNA_SourceCode[MAX_CODESIZE];

} FINGERPRINTSTRUCT;

typedef BOOL	(WINAPI *fnModule32First)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL	(WINAPI *fnModule32Next)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef HANDLE	(WINAPI *fnCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

typedef struct _MODULEINFO {
    LPVOID lpBaseOfDll;
    DWORD SizeOfImage;
    LPVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

typedef BOOL	(*fnEnumProcessModules)(HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef DWORD	(*fnGetModuleBaseName)(HANDLE hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize);
typedef BOOL	(*fnGetModuleInformation)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);

typedef DWORD (PRIVATE *fnGetBaseAddress)(LPSTR ModuleName);
typedef DWORD (PRIVATE *fnGetImageSize)(LPSTR ModuleName);

typedef struct _DNA_STRUCTURES
{
	HWND hProcess;

	fnGetBaseAddress GetBaseAddress;
	fnGetImageSize GetImageSize;

	struct {
		fnCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
		fnModule32First Module32First;
		fnModule32Next Module32Next;
	} toolhelp;

	struct {
		fnEnumProcessModules EnumProcessModules;
		fnGetModuleBaseName GetModuleBaseName;
		fnGetModuleInformation GetModuleInformation;
	} psapi;

	struct {
        FINGERPRINTSTRUCT Imatinib;
	} DNA;

} DNA_STRUCTURES;

extern DNA_STRUCTURES *dna;


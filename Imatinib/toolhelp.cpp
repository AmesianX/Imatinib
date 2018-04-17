//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"

/////////////////////////////////////////////////////
// GetImageSize_toolhelp
/////////////////////////////////////////////////////
DWORD PRIVATE GetImageSize_toolhelp(LPSTR ModuleName)
{
	MODULEENTRY32 lpme;
	if (FindImage_toolhelp(ModuleName, &lpme))
		return lpme.modBaseSize;
	else
		return 0;
}

///////////////////////////////////////////////////////
// GetBaseAddress_toolhelp
///////////////////////////////////////////////////////
DWORD PRIVATE GetBaseAddress_toolhelp(LPSTR ModuleName)
{
	MODULEENTRY32 lpme;
	if (FindImage_toolhelp(ModuleName, &lpme))
		return (DWORD)lpme.modBaseAddr;
	else
		return 0;
}

//////////////////////////////////////////////////////////////////////
// FindImage_toolhelp
//////////////////////////////////////////////////////////////////////
BOOL PRIVATE FindImage_toolhelp(LPSTR ModuleName, MODULEENTRY32* lpme)
{
	HANDLE hSnapshot = dna->toolhelp.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if ((int)hSnapshot == -1) return FALSE;

	lpme->dwSize = sizeof(MODULEENTRY32);

	// win9x/ME
	if (!dna->toolhelp.Module32First(hSnapshot, lpme)) { CloseHandle(hSnapshot); return FALSE; };

	while (TRUE)
	{
		if (!_strcmpi(lpme->szModule, ModuleName)) { CloseHandle(hSnapshot); return TRUE; }
		if (!dna->toolhelp.Module32Next(hSnapshot, lpme)) { CloseHandle(hSnapshot); return FALSE; };
	}
}


//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"

////////////////////////////////////////////////////////////////////////////////////////////////
// GetMemoryAddressFromPattern
////////////////////////////////////////////////////////////////////////////////////////////////
DWORD PRIVATE GetMemoryAddressFromPattern(LPSTR szDllName, LPCSTR szSearchPattern, DWORD offset)
{
	DWORD lResult = 0;

	if (szSearchPattern[0] == '#')
	{
		LPSTR t = "";
		lResult = strtoul(&szSearchPattern[1], &t, 0x10);
		return lResult += (lResult ? offset : 0);
	} 
	
	if (szSearchPattern[0] == '!')
	{
		HMODULE hModule = GetModuleHandle(szDllName);

		if (hModule)
			lResult = (DWORD)GetProcAddress(hModule, &szSearchPattern[1]);

		if (!lResult)
		{
			LPSTR x = "";
			lResult = (DWORD)GetProcAddress(hModule, (LPCSTR)MAKELONG(strtoul(&szSearchPattern[1], &x, 10),0));
		}

		return lResult += (lResult ? offset : 0);
	} 
	
	DWORD len = (strlen(szSearchPattern)) / 2;
	WORD *pPattern = new WORD[len];

	int p = strlen(szDllName);
	while (p)
	{
		if (szDllName[p] == '\\')
		{
            szDllName[p] = 0;
            strcpy(szDllName, &szDllName[p+1]);
            p = 0;
        }
		else p--;
	}

	DWORD SearchAddress = GetBaseAddress(szDllName);
	DWORD SearchSize = GetImageSize(szDllName);

	MakeSearchPattern(szSearchPattern, pPattern);
	if (lResult = (DWORD)PatternSearch((BYTE*)SearchAddress, SearchSize, pPattern, len)) lResult += offset;

	delete pPattern;
	return lResult;
}

//////////////////////////////////////////////////////////////
// PatternEquals
//////////////////////////////////////////////////////////////
BOOL PRIVATE PatternEquals(LPBYTE buf, LPWORD pat, DWORD plen)
{
	DWORD i;
	DWORD ofs = 0;

	for (i = 0; plen > 0; i++) {
		if ((buf[ofs] & ((pat[ofs] & 0xff00)>>8)) != (pat[ofs] & 0xff))
			return FALSE;

		plen--;
		if ((i & 1) == 0)
			ofs += plen;
		else
			ofs -= plen;
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// PatternSearch
////////////////////////////////////////////////////////////////////////////
LPVOID PRIVATE PatternSearch(LPBYTE buf, DWORD blen, LPWORD pat, DWORD plen)
{
	DWORD ofs;
	DWORD end;

	if ((blen == 0) || (plen == 0))
		return NULL;

	end = blen - plen;

	for (ofs = 0; ofs < end; ofs++) {
		if (PatternEquals(&buf[ofs], pat, plen))
			return &buf[ofs];
	}

	return NULL;
}


///////////////////////////////////////////////////////////
// MakeSearchPattern
///////////////////////////////////////////////////////////
VOID  PRIVATE MakeSearchPattern(LPCSTR pString, LPWORD pat)
{
	char *tmp = new char[strlen(pString)+1];
	strcpy(tmp, pString);

	for (int i = (strlen(tmp) / 2) - 1; strlen(tmp) > 0; i--)
	{
		char *x = "";
		BYTE value = (BYTE)strtoul(&tmp[i*2], &x, 0x10);
		if (strlen(x))
			pat[i] = 0;
		 else
			pat[i] = MAKEWORD(value, 0xff);

		tmp[i*2] = 0;
	}
	delete tmp;
}

	
//////////////////////////////////////////////
// GetBaseAddress
//////////////////////////////////////////////
DWORD PRIVATE GetBaseAddress(LPSTR ModuleName)
{
	SetMemToolType();
	return dna->GetBaseAddress(ModuleName);
}

////////////////////////////////////////////
// GetImageSize
////////////////////////////////////////////
DWORD PRIVATE GetImageSize(LPSTR ModuleName)
{
	SetMemToolType();
	return dna->GetImageSize(ModuleName);
}

/////////////////////////////////
// SetMemToolType
/////////////////////////////////
void PRIVATE SetMemToolType(void)
{
	HMODULE kernel32 = GetModuleHandle("kernel32.dll");

	dna->toolhelp.Module32First = (fnModule32First)GetProcAddress(kernel32, "Module32First");
	dna->toolhelp.Module32Next  = (fnModule32Next)GetProcAddress(kernel32, "Module32Next");
	dna->toolhelp.CreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddress(kernel32,"CreateToolhelp32Snapshot");

	if (!(dna->toolhelp.Module32First) || !(dna->toolhelp.Module32Next) || !(dna->toolhelp.CreateToolhelp32Snapshot))
    {

#ifdef _DEBUG
		OutputDebugString("[+][IMATINIB] PSAPI code is not yet implemented!\n");
#endif

		return;

		HMODULE psapi = GetModuleHandle("psapi.dll");
		if (!psapi)
            psapi = LoadLibrary("psapi.dll");

		if (!psapi) {
#ifdef _DEBUG
            OutputDebugString("[+][IMATINIB] Unable to get handle of PSAPI.DLL.");
#endif
        }

        dna->psapi.EnumProcessModules = (fnEnumProcessModules)GetProcAddress(psapi, "EnumProcessModules");
        dna->psapi.GetModuleBaseName = (fnGetModuleBaseName)GetProcAddress(psapi, "GetModuleBaseNameA");
        dna->psapi.GetModuleInformation = (fnGetModuleInformation)GetProcAddress(psapi, "GetModuleInformation");

        // This is not yet implemented
		dna->GetBaseAddress = &GetBaseAddress_psapi;
		dna->GetImageSize = &GetImageSize_psapi;
	} else {
		dna->GetBaseAddress = &GetBaseAddress_toolhelp;
		dna->GetImageSize = &GetImageSize_toolhelp;
	}
		
	return;
}



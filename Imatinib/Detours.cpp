//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#pragma once
#define _IMATINIB_

#include "Imatinib.h"
#include "_win32.h"

#define ASSERT_ALWAYS(x)                                        \
    do {                                                        \
		if (!(x)) {                                             \
            AssertMessage(#x, __FILE__, __LINE__);              \
            DebugBreak();                                       \
		}                                                       \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)   ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)   (c) = (c)

static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];
static CHAR s_szDllPath[MAX_PATH];

BOOL ProcessEnumerate();
BOOL InstanceEnumerate(HINSTANCE hInst);

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine);

static BOOL s_bLog = FALSE;
static LONG s_nTlsIndent = -1;
static LONG s_nTlsThread = -1;
static LONG s_nThreadCnt = 0;

VOID AssertMessage(CONST PCHAR pszMsg, CONST PCHAR pszFile, ULONG nLine)
{
	// Syelog(SYELOG_SEVERITY_FATAL, "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

static PCHAR DetRealName(PCHAR psz)
{
	PCHAR pszBeg = psz;
	// Move to end of name.
	while (*psz) {
		psz++;
	}
	// Move back through A-Za-z0-9 names.
	while (psz > pszBeg &&
		((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
		(psz[-1] >= 'a' && psz[-1] <= 'z') ||
			(psz[-1] >= '0' && psz[-1] <= '9'))) {
		psz--;
	}
	return psz;
}

static VOID Dump(PBYTE pbBytes, LONG nBytes, PBYTE pbTarget)
{
	CHAR szBuffer[256];
	PCHAR pszBuffer = szBuffer;

	for (LONG n = 0; n < nBytes; n += 12) {
		pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "  %p: ", pbBytes + n);
		for (LONG m = n; m < n + 12; m++) {
			if (m >= nBytes) {
				pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "   ");
			}
			else {
				pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "%02x ", pbBytes[m]);
			}
		}
		if (n == 0) {
			pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "[%p]", pbTarget);
		}
		pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "\n");
	}

	// Syelog(SYELOG_SEVERITY_INFORMATION, "%s", szBuffer);
}

static VOID Decode(PBYTE pbCode, LONG nInst)
{
	PBYTE pbSrc = pbCode;
	PBYTE pbEnd;
	PBYTE pbTarget;
	for (LONG n = 0; n < nInst; n++) {
		pbTarget = NULL;
		pbEnd = (PBYTE)DetourCopyInstruction(NULL, NULL, (PVOID)pbSrc, (PVOID*)&pbTarget, NULL);
		Dump(pbSrc, (int)(pbEnd - pbSrc), pbTarget);
		pbSrc = pbEnd;

		if (pbTarget != NULL) {
			break;
		}
	}
}

VOID DetAttach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	PVOID pvReal = NULL;
	if (ppvReal == NULL) {
		ppvReal = &pvReal;
	}

	LONG l = DetourAttach(ppvReal, pvMine);
	if (l != 0) {
		// Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': error %d\n", DetRealName(psz), l);
		Decode((PBYTE)*ppvReal, 3);
	}
}

VOID DetDetach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	LONG l = DetourDetach(ppvReal, pvMine);
	if (l != 0) {
#if 0
		// Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': error %d\n", DetRealName(psz), l);
#else
		(void)psz;
#endif
	}
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

void dumpcode(unsigned char *buff, int len)
{
    int i;
    
    CString Debug, Output = "[+][IMATINIB] ";
    
    for(i=0;i<len;i++)
    {
        if(i%16==0)
        {
            Debug.Format("0x%08x ", &buff[i]);
            Output += Debug;
        }
        Debug.Format("%02x ", buff[i]);
        Output += Debug;
        
        if(i%16-15==0)
        {
            int j;
            
            Output += "  ";
            for(j=i-15;j<=i;j++)
            {
                if(isprint(buff[j]))
                {
                    Debug.Format("%c", buff[j]);
                    Output += Debug;
                }
                else
                {
                    Output += ".";
                }
            }
            Output += "\n[+][IMATINIB] ";
        }
    }
    if(i%16!=0)
    {
        int j;
        int spaces=(len-i+16-i%16)*3+2;
        for(j=0;j<spaces;j++)
        {
            Output += " ";
        }
        for(j=i-i%16;j<len;j++)
        {
            if(isprint(buff[j]))
            {
                Debug.Format("%c", buff[j]);
                Output += Debug;
            }
            else
            {
                Output += ".";
            }
        }
    }
    
    Output += "\n\n";

#ifdef _DEBUG
	OutputDebugString(Output);
#endif

}

HANDLE __stdcall Mine_CreateFileA(LPCSTR a0,
                                  DWORD a1,
                                  DWORD a2,
                                  LPSECURITY_ATTRIBUTES a3,
                                  DWORD a4,
                                  DWORD a5,
                                  HANDLE a6)
{
    CString filename = a0;	
	filename.MakeLower();

    USES_CONVERSION;

    if (filename.Find("c:\\test.docx") != -1)
    {
#ifdef _DEBUG
	    CString DBGMSG;
        DBGMSG.Format("[+][IMATINIB] CreateFileA(\"%s\")", a0);
	    OutputDebugString(DBGMSG);
#endif
	}

    HANDLE rv = 0;
    rv = Real_CreateFileA(a0, a1, a2, a3, a4, a5, a6);
    return rv;
}

HANDLE __stdcall Mine_CreateFileW(LPCWSTR a0,
                                  DWORD a1,
                                  DWORD a2,
                                  LPSECURITY_ATTRIBUTES a3,
                                  DWORD a4,
                                  DWORD a5,
                                  HANDLE a6)
{
    HANDLE rv = 0;
	
	CString filename = a0;
    filename.MakeLower();
	 
    USES_CONVERSION;

    if (filename.Find(OLE2A(L"c:\\test.docx")) != -1)
    {
#ifdef _DEBUG        
     	CString DBGMSG;
        DBGMSG.Format("[+][IMATINIB] CreateFileW(\"%S\")", a0);
	    OutputDebugString(DBGMSG);
#endif
    }

    rv = Real_CreateFileW(a0, a1, a2, a3, a4, a5, a6);
    return rv;
}

BOOL __stdcall Mine_SetWindowTextW(HWND a0,
                                   LPCWSTR a1)
{
    CString popup = a1;

	if (popup.Find("PASSWORD") != -1) {

#ifdef _DEBUG
	    CString DBGMSG;
        DBGMSG.Format("[+][IMATINIB] SetWindowTextW(\"%S\")", a1);
	    OutputDebugString(DBGMSG);

        // __asm { int 3 };
#endif
	}

    BOOL rv = 0;
    rv = Real_SetWindowTextW(a0, a1);
    return rv;
}

//////////////////////////////////////////////////////////////////////////////////
LONG ImatinibAttachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);

    // [Hook] ///////////////////////////////////////////////////
    // ATTACH(CreateFileA);
    // ATTACH(CreateFileA);
	// ATTACH(SetWindowTextW);
    /////////////////////////////////////////////////////////////

	PVOID *ppbFailedPointer = NULL;
	LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
	if (error != 0) {
		// printf("traceapi.dll: Attach transaction failed to commit. Error %d (%p/%p)",
		//        error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 0;
}

LONG ImatinibDetachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	// For this many APIs, we'll ignore one or two can't be detoured.
	DetourSetIgnoreTooSmall(TRUE);

    // [UnHook] /////////////////////////////////////////////////
    // DETACH(CreateFileA);
    // DETACH(CreateFileW);
    // DETACH(SetWindowTextW);
    /////////////////////////////////////////////////////////////

	if (DetourTransactionCommit() != 0) {
		PVOID *ppbFailedPointer = NULL;
		LONG error = DetourTransactionCommitEx(&ppbFailedPointer);

		// printf("traceapi.dll: Detach transaction failed to commit. Error %d (%p/%p)",
        //        error, ppbFailedPointer, *ppbFailedPointer);
		return error;
	}
	return 0;
}

BOOL ThreadAttach(HMODULE hDll)
{
	(void)hDll;

	if (s_nTlsIndent >= 0) {
		TlsSetValue(s_nTlsIndent, (PVOID)0);
	}
	if (s_nTlsThread >= 0) {
		LONG nThread = InterlockedIncrement(&s_nThreadCnt);
		TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
	}
	return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
	(void)hDll;

	if (s_nTlsIndent >= 0) {
		TlsSetValue(s_nTlsIndent, (PVOID)0);
	}
	if (s_nTlsThread >= 0) {
		TlsSetValue(s_nTlsThread, (PVOID)0);
}
	return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
	s_bLog = FALSE;
	s_nTlsIndent = TlsAlloc();
	s_nTlsThread = TlsAlloc();
	ThreadAttach(hDll);

	WCHAR wzExeName[MAX_PATH];

	s_hInst = hDll;
	Real_GetModuleFileNameW(hDll, s_wzDllPath, ARRAYSIZE(s_wzDllPath));
	Real_GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));
	StringCchPrintfA(s_szDllPath, ARRAYSIZE(s_szDllPath), "%ls", s_wzDllPath);

	// SyelogOpen("trcapi" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
	ProcessEnumerate();

	LONG error = ImatinibAttachDetours();
	if (error != NO_ERROR) {
		// Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);
	}

	s_bLog = TRUE;
	return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
	ThreadDetach(hDll);
	s_bLog = FALSE;

	LONG error = ImatinibDetachDetours();
	if (error != NO_ERROR) {
		// Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);
	}

	// Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
	// SyelogClose(FALSE);

	if (s_nTlsIndent >= 0) {
		TlsFree(s_nTlsIndent);
	}
	if (s_nTlsThread >= 0) {
		TlsFree(s_nTlsThread);
	}
	return TRUE;
}

PIMAGE_NT_HEADERS NtHeadersForInstance(HINSTANCE hInst)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
	__try {
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return NULL;
		}

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
			pDosHeader->e_lfanew);
		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
			SetLastError(ERROR_INVALID_EXE_SIGNATURE);
			return NULL;
		}
		if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
			SetLastError(ERROR_EXE_MARKED_INVALID);
			return NULL;
		}
		return pNtHeader;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}
	SetLastError(ERROR_EXE_MARKED_INVALID);

	return NULL;
}

BOOL InstanceEnumerate(HINSTANCE hInst)
{
	WCHAR wzDllName[MAX_PATH];

	PIMAGE_NT_HEADERS pinh = NtHeadersForInstance(hInst);
	if (pinh && Real_GetModuleFileNameW(hInst, wzDllName, ARRAYSIZE(wzDllName))) {
		// Syelog(SYELOG_SEVERITY_INFORMATION, "### %p: %ls\n", hInst, wzDllName);
		return TRUE;
	}
	return FALSE;
}

BOOL ProcessEnumerate()
{
    // Syelog(SYELOG_SEVERITY_INFORMATION,
	//        "######################################################### Binaries\n");

	PBYTE pbNext;
	for (PBYTE pbRegion = (PBYTE)0x10000;; pbRegion = pbNext) {
		MEMORY_BASIC_INFORMATION mbi;
		ZeroMemory(&mbi, sizeof(mbi));

		if (VirtualQuery((PVOID)pbRegion, &mbi, sizeof(mbi)) <= 0) {
			break;
		}
		pbNext = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

		// Skip free regions, reserver regions, and guard pages.
		//
		if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE) {
			continue;
		}
		if (mbi.Protect & PAGE_GUARD || mbi.Protect & PAGE_NOCACHE) {
			continue;
		}
		if (mbi.Protect == PAGE_NOACCESS) {
			continue;
		}

		// Skip over regions from the same allocation...
		{
			MEMORY_BASIC_INFORMATION mbiStep;

			while (VirtualQuery((PVOID)pbNext, &mbiStep, sizeof(mbiStep)) > 0) {
				if ((PBYTE)mbiStep.AllocationBase != pbRegion) {
					break;
				}
				pbNext = (PBYTE)mbiStep.BaseAddress + mbiStep.RegionSize;
				mbi.Protect |= mbiStep.Protect;
			}
		}

		WCHAR wzDllName[MAX_PATH];
		PIMAGE_NT_HEADERS pinh = NtHeadersForInstance((HINSTANCE)pbRegion);

		if (pinh &&
			Real_GetModuleFileNameW((HINSTANCE)pbRegion, wzDllName, ARRAYSIZE(wzDllName))) {
			// Syelog(SYELOG_SEVERITY_INFORMATION, "### %p..%p: %ls\n", pbRegion, pbNext, wzDllName);
		}
		else {
			// Syelog(SYELOG_SEVERITY_INFORMATION,
			//        "### %p..%p: State=%04x, Protect=%08x\n",
			//        pbRegion, pbNext, mbi.State, mbi.Protect);
		}
	}
	// Syelog(SYELOG_SEVERITY_INFORMATION, "###\n");

	LPVOID lpvEnv = Real_GetEnvironmentStrings();
	// Syelog(SYELOG_SEVERITY_INFORMATION, "### Env= %08x [%08x %08x]\n",
	//        lpvEnv, ((PVOID*)lpvEnv)[0], ((PVOID*)lpvEnv)[1]);

	return TRUE;
}
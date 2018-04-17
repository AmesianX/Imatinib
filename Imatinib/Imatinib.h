//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#pragma once
#define _IMATINIB_

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define STRSAFE_NO_DEPRECATE

#pragma warning(disable:4005)
#pragma warning(disable:4089)
#pragma warning(disable:4127)
#pragma warning(disable:4244)
#pragma warning(disable:4995)
#pragma warning(disable:4996)

#if _MSC_VER >= 1300
#include <winsock2.h>
#endif
#include <windows.h>
#include <stdio.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // analyze warnings
#endif
#pragma warning(pop)

#if (_MSC_VER < 1299)
#pragma comment(linker, "/ignore:4089")
#define LONG_PTR    LONG
#define ULONG_PTR   ULONG
#define PLONG_PTR   PLONG
#define PULONG_PTR  PULONG
#define INT_PTR     INT
#define UINT_PTR    UINT
#define PINT_PTR    PINT
#define PUINT_PTR   PUINT
#define DWORD_PTR   DWORD
#define PDWORD_PTR  PDWORD
/*
__inline int InlineIsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
return !memcmp(&rguid1, &rguid2, sizeof(GUID));
}

#define IS_INTRESOURCE(_r) ((((ULONG_PTR)(_r)) >> 16) == 0)
*/
#endif

#include <winuser.h>
#include <stddef.h>
#include <string.h>
#include <windef.h>
#include <iostream>
#include <io.h>
#include <tlhelp32.h>
#include <time.h>
#include <strsafe.h>

#define DBG_TRACE   0

#include <crtdbg.h>
#include <atlconv.h>
#include <atlbase.h>
#include "../include/atlapp.h"

extern CAppModule _Module;

#include "../Include/atlwinx.h"
#include "../include/atlmisc.h"

#define	EXPORT   __declspec( dllexport ) __cdecl 
#define PRIVATE  __cdecl

// Win32 API Hooking
#include "detours.h"
#include "Structs.h"

#ifdef _DEBUG
#pragma comment(lib, "detours.lib")
#else
#pragma comment(lib, "detours.lib")
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#define INST_NOP  0x90
#define INST_CALL 0xE8
#define INST_JMP  0xE9

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

//////////////////////////////////////////////////////////////////////
// Version history.
// -------------------------------------------------------------------
// ver.0.2 2015-07-31
// ver.0.1 2006-08-23
//////////////////////////////////////////////////////////////////////

// ServerStartStop.cpp
BOOL	PRIVATE ServerStart(HANDLE);
BOOL	PRIVATE ServerStop(void);

// MemorySearchFunctions.cpp
BOOL	PRIVATE PatternEquals(LPBYTE, LPWORD, DWORD);
LPVOID	PRIVATE PatternSearch(LPBYTE, DWORD, LPWORD, DWORD);
VOID	PRIVATE MakeSearchPattern(LPCSTR, LPWORD);
DWORD	PRIVATE GetMemoryAddressFromPattern(LPSTR, LPCSTR, DWORD);
DWORD	PRIVATE GetBaseAddress(LPSTR);
DWORD	PRIVATE GetImageSize(LPSTR);
void	PRIVATE SetMemToolType(void);

// psapi.cpp
DWORD	PRIVATE GetBaseAddress_psapi(LPSTR);
DWORD	PRIVATE GetImageSize_psapi(LPSTR);
BOOL	PRIVATE FindImage_psapi(LPSTR, MODULEINFO*);

// toolhelp.cpp
DWORD	PRIVATE GetBaseAddress_toolhelp(LPSTR);
DWORD	PRIVATE GetImageSize_toolhelp(LPSTR);
BOOL	PRIVATE FindImage_toolhelp(LPSTR, MODULEENTRY32*);

// IniFileHandlers.cpp
BOOL	PRIVATE DNA_FingerPrintList(int, int, FINGERPRINTSTRUCT &);

// ReverseCodeEngine.cpp
void Imatinib_STUB();
void __fastcall DNA_Instrument(DWORD);

// HelperFunctions.cpp
VOID* PRIVATE dna_copy(DWORD, DWORD, int);
BOOL  PRIVATE DNA_Injector(int, DWORD, FINGERPRINTSTRUCT &);
BOOL  PRIVATE RecoveryCode(DWORD, FINGERPRINTSTRUCT &);
VOID  EXPORT  Dummy();

///////////////////////////////////////////////////////
// SendToDebugger
///////////////////////////////////////////////////////
BOOL WINAPI SendToDebugger(DWORD, const char *, DWORD);

/////////////////////////////
// DEBUG MESSAGE FORMAT
/////////////////////////////
typedef struct _REGS
{
	DWORD eax;
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD ebp;
	DWORD esp;
	DWORD eip;
	DWORD ret;
    DWORD eflags;
    BOOL  call;
} REGS;

#define PATTERN_MAXIMUM  1024

enum DBG_CONTROL_PACKET {
	DBG_CONTROL_START = 1,
	DBG_CONTROL_STOP,
	DBG_CONTROL_NORMAL,
	DBG_CONTROL_DUMP
};

enum IMATINIB_CONTROL_PACKET {
	IMATINIB_GET_REG,
	IMATINIB_GET_IMM,
	IMATINIB_GET_DWORD,
	IMATINIB_GET_STRING,
	IMATINIB_GET_DUMP,
	IMATINIB_GET_GETFINGERPRINT,
	IMATINIB_GET_INTERCEPT,
	IMATINIB_GET_STOP
};

typedef struct _MEMDUMP
{
	char eax[1024];
	char ebx[1024];
	char ecx[1024];
	char edx[1024];
	char esi[1024];
	char edi[1024];
	char ebp[1024];
	char esp[1024];
} MEMDUMP, *PMEMDUMP;

#pragma pack(push, 1)
typedef struct _DBGDATA
{
	REGS    reg;
	MEMDUMP mem;
} DBGDATA, *PDBGDATA;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMATINIB_DATA
{
    char  Pattern[PATTERN_MAXIMUM];

    DWORD dwState;
    DWORD Register;
    DWORD Immediate;

	DWORD Offset;
    DWORD Address;
    DWORD PatchSize;
} IMATINIB_DATA, *PIMATINIB_DATA;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"

///////////////////////////////////////////////////////////////
// dna_copy
///////////////////////////////////////////////////////////////
VOID* PRIVATE dna_copy(DWORD lpDest, DWORD lpSource, int len)
{
	DWORD oldSourceProt, oldDestProt = 0;
	 VirtualProtect((void *)lpSource, len, PAGE_EXECUTE_READWRITE, &oldSourceProt);
 	  VirtualProtect((void *)lpDest, len, PAGE_EXECUTE_READWRITE, &oldDestProt);
	   memcpy((void *)lpDest, (void *)lpSource, len);
	  VirtualProtect((void *)lpDest, len, oldDestProt, &oldDestProt);
	 VirtualProtect((void *)lpSource, len, oldSourceProt, &oldSourceProt);
	return (void *)lpDest;
}

////////////////////////////////////////////////////////////////////////////////
// DNA_Injector
////////////////////////////////////////////////////////////////////////////////
BOOL PRIVATE DNA_Injector(int instruction, DWORD lpDest, FINGERPRINTSTRUCT &dna)
{
    DWORD len      = dna.PatchSize;
    DWORD lpSource = dna.AddressFound;

#ifdef _DEBUG
    CString DBGMSG;
    DBGMSG.Format("[+][IMATINIB] injected at %.8x intercepted and routed to %.8x", lpSource, lpDest);
    OutputDebugString(DBGMSG);
#endif

    BYTE *buffer = new BYTE[len];
	buffer[0] = instruction;
	*(DWORD *)(buffer + 1) = lpDest - (lpSource + 5);
	memset(buffer + 5, 0x90, len - 5);
	memset(dna.DNA_SourceCode, 0x00, MAX_CODESIZE);
    dna_copy((DWORD)dna.DNA_SourceCode, lpSource, len);
	dna_copy(lpSource, (DWORD)buffer, len);

	return TRUE;
}

///////////////////////////////////////////////////////////////
// RecoveryCode
///////////////////////////////////////////////////////////////
BOOL PRIVATE RecoveryCode(DWORD lpDest, FINGERPRINTSTRUCT &dna)
{
    DWORD len = dna.PatchSize;

#ifdef _DEBUG
    CString DBGMSG;
    DBGMSG.Format("[+][IMATINIB] RecoveryCode at %.8x", lpDest);
    OutputDebugString(DBGMSG);
#endif

	dna_copy(lpDest, (DWORD)dna.DNA_SourceCode, len);

	return TRUE;
}

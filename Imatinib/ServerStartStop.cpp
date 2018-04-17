//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "include/myinttypes.h"
#include "include/capstone.h"

#pragma comment(lib, "capstone_dll.lib")

// 디버깅 레지스터 변수
DBGDATA dbg;

// 만약 정상적으로 적었는데 바이너리 스트링을 찾지 못한다면, 그건
// 패치할 DLL 이 로딩이 안됐기 때문이므로 강제로딩 시켜서 패치해야한다.
char* NeededDlls[] = { NULL };

extern CRITICAL_SECTION cs;

// Capston 변수
csh handle;

cs_arch arch;
cs_mode mode;

size_t size;
char *comment;
unsigned char *code;

cs_opt_type opt_type;
cs_opt_value opt_value;

/*
ENG: If you use VC++ 6.0, you must install "MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2".
KOR: 만약, VC++ 6.0 을 사용중이라면 MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2 을 설치해서
     컴파일 Tools->Options->Include Files 에서 가장 최상위로 셋팅해주고 컴파일해야됩니다.

ENG: I tested only in VC++ 6.0. Recommended VC++ 6.0.
KOR: 저는 MSVC 2013 과 같이 상위 컴파일러는 의존성 문제가 많아서 잘 사용하지 않습니다.
     그래서 32 비트 후킹을 다룰 때는 무조건 VC++ 6.0 에서만 테스트합니다. 상위 버전
     컴파일러로는 아직 환경을 맞추지 않았지만, 큰 문제는 없을 것 같습니다.

KOR: 누가 영어설명 좀 도움을.. -_-;

<TEST>

Microsoft Office Word 2007 (웹하드에 떠돌아다니는 버전 패치 선택 안한 버전)

1. setdll.exe 파일은 같이 동봉해 넣었음.
2. 같이 동봉된 capstone.dll 을 디렉토리에 같이 넣어주어야 함.
3. 직접 컴파일 할 것이 아니라면 Release 디렉토리에 있는 Imatinib.dll 파일을 사용해야됨.
4. DebugView 를 켜고 필터 옵션에서 [+] 문자로 필터링 되도록 지정함.
5. C:\Program Files (x86)\Microsoft Office\Office12> setdll.exe /d:Imatinib.dll winword.exe
6. C:\Program Files (x86)\Microsoft Office\Office12> winword.exe c:\test.docx
*/

////////////////////////////////////////
// ServerStart
////////////////////////////////////////
BOOL PRIVATE ServerStart(HANDLE hModule)
{
    CString DBGMSG;

    dna = new DNA_STRUCTURES;
    memset(&dbg, 0, sizeof(_DBGDATA));
    memset(dna, 0, sizeof(DNA_STRUCTURES));

    dna->GetImageSize   = &GetImageSize;
    dna->GetBaseAddress = &GetBaseAddress;

    for (int i=0; NeededDlls[i] != NULL; i++)
    {
        if(LoadLibrary(NeededDlls[i]) == NULL) {
			DBGMSG.Format("[+][IMATINIB] LoadLibrary(%s) Failed\n", NeededDlls[i]);
			OutputDebugString(DBGMSG);
			break;
        }
    }

	/*
	dna->hProcess = FindWindowEx(NULL, NULL, "TFormImatinibCenter", "IDAImatinib");
	if (!dna->hProcess)
	{
#ifdef _DEBUG
		OutputDebugString("FindWindowEx is failed..");
#endif
		return FALSE;
	}

    DWORD dwThread;
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DBG_CONNECT, (LPVOID)NULL, NULL, &dwThread);
    */

	if (DNA_FingerPrintList(0, 0, dna->DNA.Imatinib)) {

		InitializeCriticalSection(&cs);

        // 특별히 쓰지 않지만 구해놓음
		dna->DNA.Imatinib.tid = GetCurrentThreadId();

        // Capstone 초기화
        // Initialize Capstone Engine
	    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
#ifdef _DEBUG
            DBGMSG.Format("[+][IMATINIB] Failed on cs_open() with error returned\n");
            OutputDebugString(DBGMSG);
#endif
		    return FALSE;
	    }

	    if (opt_type)
		    cs_option(handle, opt_type, opt_value);

	    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        // 최초 인젝션
        DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna->DNA.Imatinib);
    }
    else {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] GetFingerprintList Failed\n");
        OutputDebugString(DBGMSG);
#endif
		return FALSE;
    }

    return TRUE;
}

/////////////////////////////
// ServerStop
/////////////////////////////
BOOL PRIVATE ServerStop(void)
{
    // Capstone 닫음
	cs_close(&handle);

    DeleteCriticalSection(&cs);

    for (int i=0; NeededDlls[i] != NULL; i++) FreeLibrary(GetModuleHandle(NeededDlls[i]));

    delete dna;

    return TRUE;
}

///////////////////
// Dummy
///////////////////
VOID EXPORT Dummy()
{
    return;
}

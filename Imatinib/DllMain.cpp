//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "direct.h"

CAppModule _Module;

DNA_STRUCTURES *dna;
CRITICAL_SECTION cs;

BOOL ProcessAttach(HMODULE hDll);
BOOL ProcessDetach(HMODULE hDll);
BOOL ThreadAttach(HMODULE hDll);
BOOL ThreadDetach(HMODULE hDll);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    /*
    char Path[255];
    GetModuleFileName(NULL, Path, 255);    
    
    char *ptr = strrchr(Path, '\\');

    CString FileName = ptr + 1;

    FileName.MakeLower();
    if (FileName == "ida.exe")
    {
        HMODULE hHandle = GetModuleHandle("ida.wll");
        if (hHandle == NULL) return TRUE;
        // FreeLibraryAndExitThread((HINSTANCE)hModule, 1);
    }
    */

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls((HINSTANCE)hModule);
#ifdef _DEBUG
            OutputDebugStringA("[+][IMATINIB] " DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                               " DllMain DLL_PROCESS_ATTACH\n");
#endif
            DetourRestoreAfterWith();
            return ProcessAttach((HINSTANCE)hModule);

        case DLL_PROCESS_DETACH:
#ifdef _DEBUG
            OutputDebugStringA("[+][IMATINIB] " DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                               " DllMain DLL_PROCESS_DETACH\n");
#endif
            return ProcessDetach((HINSTANCE)hModule);

        case DLL_THREAD_ATTACH:
#ifdef _DEBUG
            OutputDebugStringA("[+][IMATINIB] " DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                               " DllMain DLL_THREAD_ATTACH\n");
#endif
            return ThreadAttach((HINSTANCE)hModule);

        case DLL_THREAD_DETACH:
#ifdef _DEBUG
            OutputDebugStringA("[+][IMATINIB] " DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                               " DllMain DLL_THREAD_DETACH\n");
#endif
            return ThreadDetach((HINSTANCE)hModule);
    }

    return TRUE;
}

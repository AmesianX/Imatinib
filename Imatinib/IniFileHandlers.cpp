//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"

/////////////////////////////////////////////////////////////////////////////
// GetFingerprintList
/////////////////////////////////////////////////////////////////////////////
BOOL PRIVATE DNA_FingerPrintList(int mode, int index, FINGERPRINTSTRUCT &dna)
{
    int i, nFields = 0;

#ifdef _DEBUG
    CString DBGMSG;
#endif

    char DNA_Sequences[1][512];

    // Binary's DNA Sequence
    // strcpy(DNA_Sequences[0], "wwlib.dll,6,23,68000200008D7E0C5756FFB5xxxxxxxx50FF15xxxxxxxx85C074396A0153FFB5xxxxxxxxE8xxxxxxxx8946088B07");
    // strcpy(DNA_Sequences[1], "wwlib.dll,7,30,8BBDECFBFFFF576892000000E8xxxxxxxx3BC30F85D2FEFFFF8B078B4010FF30E8xxxxxxxx8985F0FBFFFFE972FFFFFF");

    // 첫번째 값: "패치할 EXE 나 DLL 파일명"
    
    // 두번째 값: "패치할 곳의 인스트럭션 사이즈 (5바이트 이상으로 지정해야 됨. 작다면 명령어 몇개를 조합해줌)"
    
    // 세번째 값: "현재 지정해준 바이너리 스트링에서 두글자 단위를 1 바이트로 놓고 새어서 오프셋을 지정해줌"
    //            이렇게 굳이 하는 것은 패치할 위치의 정확도를 올리기 위해서 앞뒤의 명령어를 써주기 때문에,
    //            오프셋 값을 줄 수 있게 해준 것임.

    // 네번째 값: "바이너리스 스트링"
    //            바이너리 스트링은 xxxx 처럼 마스킹해서 지정해줄 수 있음. 마스킹을 하는 부분은
    //            값이 변해도 상관이 없음. 예를들면 E8 00 00 00 00 에서 00 00 00 00 부분은 언제든
    //            계속해서 값이 변할 수가 있으므로 이 부분은 xx xx xx xx 처리를 해주는데 이 부분
    //            말고도 몇몇 부분에서 이렇게 처리를 해주지 않으면 바이너리 스트링을 찾지 못하는
    //            상황이 나옴. 이럴때는 당황하지 말고 어떤 값이 Rebasing (주소 재배치)이 되는지
    //            찬찬히 생각해보고 다시 바이너리 스트링을 마스킹을 하나씩 추가해주면서 적으면 됨.

    // 네번째 값 다르게 지정: 네번째 값은 !NameOfFuntion 처럼 함수 이름을 지정해주어도 됨. 또는 오디날 번호인
    //                        !10005 처럼 지정해주어도 됨. 아니면 아예 그냥 주소자체를 #6fba80b4 처럼 주어도 됨.
    //                        그렇게 되면 얘네들도 어차피 다 주소이기 때문에 지정해준 오프셋을 더하던지 다 할 수
    //                        있게되는 것임. 물론, 패치할 사이즈도 제대로 다 잘 지정해주어야 됨.

    // 이 정도로 설명해 주었는데도 잘 모르겠다면 powerhacker.net 에 접속해서 Art of Hooking 문서를
    // 읽어보면 친절하게 설명해 놓았다. 그것도 매우 디테일하게 말이다. 재배치 문제까지 모두 다 다루
    // 었으니까 읽어보면 이해가 잘 될 것이다.
    strcpy(DNA_Sequences[0], "wwlib.dll,5,0,3BC38946207473663918746E50FF15xxxxxxxx50FF7620E8xxxxxxxx3BC38985xxxxxxxx745468000200008D7E0C5756FFB5xxxxxxxx50FF15xxxxxxxx85C07439");
    
    strcpy(dna.Name, DNA_Sequences[index]);
    if (!strlen(DNA_Sequences[index]))
    {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Can't find fingerprint for '%s'", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif

        return FALSE;
    }
    
    for (i=0; DNA_Sequences[index][i]; i++)
        if (DNA_Sequences[index][i] == ',')
            nFields++;
        
    if (nFields != 3)
    {

#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Fingerprint for '%s'", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif

        return FALSE;
    }
    
    for (; i != 0; i--)
    {
        if (DNA_Sequences[index][i] == ',')
        {
            DNA_Sequences[index][i] = 0;
            nFields--;
            
            switch (nFields)
            {
            case 2:
                strcpy(dna.FingerPrint, &DNA_Sequences[index][i+1]);
                break;
            case 1:
                dna.Offset=atoi(&DNA_Sequences[index][i+1]);
                break;
            case 0:
                dna.PatchSize=atoi(&DNA_Sequences[index][i+1]);
                break;
            }
        }
    }

    strcpy(dna.ModuleName, DNA_Sequences[index]);

    if ((dna.AddressFound=GetMemoryAddressFromPattern(dna.ModuleName, dna.FingerPrint, dna.Offset)) < 0x100)
    {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Unable to find location for '%s'.", DNA_Sequences[index]);
        OutputDebugString(DBGMSG);
#endif
 
        return FALSE;
    } else {
#ifdef _DEBUG
        DBGMSG.Format("[+][IMATINIB] Found '%s' at %.8x", DNA_Sequences[index], dna.AddressFound);
        OutputDebugString(DBGMSG);
#endif

        return TRUE;
    }
}
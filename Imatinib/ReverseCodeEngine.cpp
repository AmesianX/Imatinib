//////////////////////////////////////////////////////////////////////
// Authored by AmesianX in powerhacker.net.
// -------------------------------------------------------------------
//////////////////////////////////////////////////////////////////////
#define _IMATINIB_
#include "Imatinib.h"
#include "include/myinttypes.h"
#include "include/capstone.h"

// 디버깅 레지스터 변수
extern DBGDATA dbg;

// Capston 변수
extern csh handle;

extern cs_arch arch;
extern cs_mode mode;

extern size_t size;
extern char *comment;
extern unsigned char *code;

extern cs_opt_type opt_type;
extern cs_opt_value opt_value;

extern CRITICAL_SECTION cs;

extern void dumpcode(unsigned char *buff, int len);

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
    CString DBGMSG;
    CString Temp;

	unsigned char *c;

	DBGMSG.Format("[+][IMATINIB] %s", comment);

	for (c = str; c < str + len; c++) {
	    Temp.Format("0x%02x ", *c & 0xff);
        DBGMSG += Temp;
	}

    Temp.Format("\n");
    DBGMSG += Temp;
    OutputDebugString(DBGMSG);
}

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
    CString DBGMSG;

	int count, i;
	cs_x86 *x86;

	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	print_string_hex("        Prefix:", x86->prefix, 4);

	print_string_hex("        Opcode:", x86->opcode, 4);

	DBGMSG.Format("[+][IMATINIB]         rex: 0x%x\n", x86->rex);
    OutputDebugString(DBGMSG);
	DBGMSG.Format("[+][IMATINIB]         addr_size: %u\n", x86->addr_size);
    OutputDebugString(DBGMSG);
	DBGMSG.Format("[+][IMATINIB]         modrm: 0x%x\n", x86->modrm);
    OutputDebugString(DBGMSG);
	DBGMSG.Format("[+][IMATINIB]         disp: 0x%x\n", x86->disp);
    OutputDebugString(DBGMSG);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		DBGMSG.Format("[+][IMATINIB]         sib: 0x%x\n", x86->sib);
        OutputDebugString(DBGMSG);
        if (x86->sib_base != X86_REG_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 sib_base: %s\n", cs_reg_name(handle, x86->sib_base));
            OutputDebugString(DBGMSG);
        }
        if (x86->sib_index != X86_REG_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 sib_index: %s\n", cs_reg_name(handle, x86->sib_index));
            OutputDebugString(DBGMSG);
        }
        if (x86->sib_scale != 0) {
			DBGMSG.Format("[+][IMATINIB]                 sib_scale: %d\n", x86->sib_scale);
            OutputDebugString(DBGMSG);
        }
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         sse_cc: %u\n", x86->sse_cc);
        OutputDebugString(DBGMSG);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         avx_cc: %u\n", x86->avx_cc);
        OutputDebugString(DBGMSG);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		DBGMSG.Format("[+][IMATINIB]         avx_sae: %u\n", x86->avx_sae);
        OutputDebugString(DBGMSG);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		DBGMSG.Format("[+][IMATINIB]         avx_rm: %u\n", x86->avx_rm);
        OutputDebugString(DBGMSG);
	}

	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		DBGMSG.Format("[+][IMATINIB]         imm_count: %u\n", count);
        OutputDebugString(DBGMSG);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			DBGMSG.Format("[+][IMATINIB]                 imms[%u]: 0x%llx\n", i, x86->operands[index].imm);
            OutputDebugString(DBGMSG);
		}
	}

    if (x86->op_count) {
		DBGMSG.Format("[+][IMATINIB]         op_count: %u\n", x86->op_count);
        OutputDebugString(DBGMSG);
    }

	for (i = 0; i < x86->op_count; i++)
    {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_IMM:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: IMM = 0x%llx\n", i, op->imm);
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_FP:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: FP = %f\n", i, op->fp);
                OutputDebugString(DBGMSG);
				break;
			case X86_OP_MEM:
				DBGMSG.Format("[+][IMATINIB]                 operands[%u].type: MEM\n", i);
                OutputDebugString(DBGMSG);
                if (op->mem.segment != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.base != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.index != X86_REG_INVALID) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.scale != 1) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.scale: %u\n", i, op->mem.scale);
                    OutputDebugString(DBGMSG);
                }
                if (op->mem.disp != 0) {
					DBGMSG.Format("[+][IMATINIB]                         operands[%u].mem.disp: 0x%llx", i, op->mem.disp);
                    OutputDebugString(DBGMSG);
                }
				break;
			default:
				break;
		}

		// AVX broadcast type
        if (op->avx_bcast != X86_AVX_BCAST_INVALID) {
			DBGMSG.Format("[+][IMATINIB]                 operands[%u].avx_bcast: %u\n", i, op->avx_bcast);
            OutputDebugString(DBGMSG);
        }

		// AVX zero opmask {z}
        if (op->avx_zero_opmask != false) {
			DBGMSG.Format("[+][IMATINIB]                 operands[%u].avx_zero_opmask: TRUE\n", i);
            OutputDebugString(DBGMSG);
        }

		DBGMSG.Format("[+][IMATINIB]                 operands[%u].size: %u\n", i, op->size);
        OutputDebugString(DBGMSG);
	}

	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
}

// SizeNextInst 값은 현재 후킹을 걸은 위치상에서의 첫번째 인스트럭션 사이즈 값.
// 후킹을 걸 곳에 5 바이트보다 작으면 두개의 명령을 한꺼번에 패치할 경우가 있기
// 때문에 첫번째 명령 사이즈를 구해서 넘겨줌. 그 값이 SizeNextInst 값이고 이 값을
// 후킹걸때 지정한 총 패치한 사이즈인 dna.PatchSize 에서 빼면 5 보다 작아야 됨.
// 그렇지 않으면 충분히 패치할 공간이 있다는 의미이므로 나머지 사이즈만 리턴하면 됨.
DWORD GetSizeNextFetchInst(FINGERPRINTSTRUCT &dna, DWORD SizeNextInst)
{
#ifdef _DEBUG
    CString DBGMSG;
#endif

    // 총 패치한 곳의 크기에서 현재 인스트럭션 사이즈 크기를 빼서 총 5 바이트
    // 크기가보다 작으면 공간을 확보하기 위해서 다음 패치할 인스트럭션 공간을
    // 디스어셈블해서 따져봐야된다. 총 패치한 사이즈에서 현재 인스트럭션인
    // SizeNextInst 값을 빼면 5 이하의 값이 남게된다. 만약, 7 바이트를 총 패치
    // 해서 사용했고 현재 인스트럭션을 따져보니 2 바이트와 5 바이트가 조합된
    // 상황이라면 2 만큼이 현재 인스트럭션 사이즈이므로, 2 만큼 빼면 5 가 나올
    // 수도 있다. 이럴 경우에는 다음지점에 패치할 공간이 충분하다는 의미이므로
    // 사이즈를 지정하고 리턴한다. 그렇지 않고 만약 6 바이트였고 2 바이트가 현재
    // 이고 4 바이트가 다음의 값이라면 5 바이트가 안되서 모자라므로 다음에 나올
    // 인스트럭션 사이즈를 합쳐서 패치공간으로 계산해야된다. 그럴때, 일단 4 바이트
    // 값은 현재 놀고있는 공간이 되는 셈이므로 초기값으로 줘야한다. 그렇지 않으면
    // 불필요하게 많은 인스트럭션을 공간으로 잡아버리게되므로 낭비가된다.
    DWORD DNA_InjectionSize = dna.PatchSize - SizeNextInst;
    if (DNA_InjectionSize >= 5)
        return DNA_InjectionSize;

    // 여기서 주소는 단순히 지정해줘서 표시하는 용도로 사용한다. 이때 주소는 당연히
    // dna.AddressFound(후킹할려고 처음 찾은 지점) + dna.PatchSize(총 패치한 사이즈)
    // 바로 위에서 지정해준 위치와 주소는 동일하다. 여기서부터 16 바이트를 더 읽어서
    // 디스어셈블러를 돌린 후에 넉넉한 인스트럭션 공간이 확보되면 중단한다. 넉넉한
    // 사이즈는 5 바이트면 충분하다.
    uint64_t address = dbg.reg.eip + dna.PatchSize;
	cs_insn *insn;
	size_t count;

    // 바이너리 마스크 패턴 매칭으로 찾은 패치한 지점 주소에서 패치한 사이즈
    // 만큼을 더한 위치부터 명령어를 탐색해가면서 5 바이트 공간을 확보하기
    // 시작해야됨. 그 값이 dna.AddressFound + dna.PatchSize 가 되며 이 값을
    // 기준으로 한 이유는 현재 이 루틴이 실행될때는 이미 최초 원본 주소 지점은
    // 패치된 상황임. 그러므로 단순히 그냥 지정하면 패치한 코드를 디스어셈하기
    // 때문에, 이 총 패치한 사이즈 만큼은 건너뛰고 분석한다. 물론, 총 패치한
    // 사이즈를 알고있기 때문에 이렇게해도 가능하다. 현재 명령어 두개가 합쳐진
    // 상태로 5 바이트보다 큰 공안을 확보했을 확률이 크기 때문에, 총 패치한
    // 사이즈에서 현재 지점에서 어떤 명령 두개가 합쳐져는지 사이즈만 구하면
    // 빼기로 구할 수가 있음을 바로 위의 코드에서 적었다. SizeNextInst 값이
    // 그 값인데 이 값 역시도 디스어셈블러를 돌려서 구해낸 값이다. 그러므로
    // 이미 후킹되어 패치되어 있는 지점인 dna.AddressFound 위치에서 일단 총
    // 패치한 공간만큼 건너뛰어서 분석한 다음에 모자란 용량을 채워야 한다.
    // 여기서 모자란 것을 이미 알고 있는 이유는 위에서 >= 5 이 조건을 주었기
    // 때문에 현재 패치할 공간이 충분치 못함을 알고 있는 상황이다.
	// (unsigned char *)(dbg.reg.eip + dna.PatchSize),
    // 넉넉잡고 16 바이트를 더 가져와서 디스어셈블러에 태운다. 패치할 만큼
    // 충분한 인스트럭션이 처음부터 발견될 확률이 높지만 그렇지 않을 경우도
    // 생긴다. 그러므로 넉넉잡아서 16 바이트를 더 읽어와서 분석시킨다.
    // 여러번 테스트 해보니 14 바이트 정도만 해도 된다. 14 바이트 보다 작으면
    // 뻑난다.
    count = cs_disasm(handle, (unsigned char *)(dbg.reg.eip + dna.PatchSize), 14, address, 0, &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++) {
#ifdef _DEBUG
            DBGMSG.Format("[+][IMATINIB] 0x%0.8I64X:    %s    %s\n",
                           insn[j].address,
                           insn[j].mnemonic,
                           insn[j].op_str);
            
            OutputDebugString(DBGMSG);

            print_insn_detail(handle, CS_MODE_32, &insn[j]);
#endif

            // 처음에 초기값으로 준 사이즈에서 현재 16 바이트를 읽어와서
            // 디스어셈블 시켰을때 나온 첫번째 명령을 더해서 사이즈가 5 보다
            // 큰지 확인하고 크다면 충분한 공간이 마련되었으니 브레이크를 걸고
            // 빠진다. 그러나, 그렇지 않다면 디스어셈블러가 한바뀌 더 돌아서
            // 다음 명령의 사이즈도 얻어낸다. 그리고 인젝션 공간에 더해보고
            // 원하는 공간이 마련될때까지 돌다가 빠져나간다. 5 바이트면 충분
            // 하기 때문에 거의 대부분 두바뀌 정도 이상은 돌 확률이 0.0001%
            // 정도일 것이다.
            DNA_InjectionSize += insn[j].size;

            if (DNA_InjectionSize >= 5) {
                break;
            }
        }

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
#ifdef _DEBUG
		DBGMSG.Format("[+][IMATINIB] ****************\n");
        OutputDebugString(DBGMSG);
		DBGMSG.Format("[+][IMATINIB] ERROR: Failed to disasm given code!\n");
        OutputDebugString(DBGMSG);
#endif
	}

#ifdef _DEBUG
	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
#endif

    return DNA_InjectionSize;
}

DWORD GetNextInst(FINGERPRINTSTRUCT &dna)
{
    // 이 함수는 설명할 것이 없다. 현재 후킹으로 패치된 지점의 위치를 준 다음에
    // 패치때문에 떼어낸 코드가 과연 몇개의 인스트럭션이 조합된 상태냐를 알아내기
    // 위해서 사용한 코드이다. 그렇게 해서 조합된 명령어일 경우에는 분리시켜서
    // 사이즈를 얻어내야 하는데, 어차피 조합된 명령어의 첫번째 명령 사이즈만 알면
    // 된다. 왜냐면 다음번에 실행시켜서 인스트루멘테이션해야할 위치가 현재 (후킹건)
    // 명령 다음번의 위치여야 하기 때문이다. 그러니 미리 그 지점을 패치시킬려면 현재
    // 인스트럭션 사이즈만 알면된다. 그만큼 증감시키고 패치시킬 것이지만 어차피 뺑뺑이
    // 돌면서 처리하므로 그때 다시 생각할 것이기 때문이다. 이 함수는 그 구현을 담은
    // 코드이다. 일단, 이 함수는 현재 후킹걸어서 후킹 루틴속에 들어온 다음에 원래의
    // 명령어가 합쳐져 있으면 처음 명령의 사이즈를 얻는 함수라고만 알고 있으면 된다.
    // 증감 시켜서 다음 위치에 다시 재후킹을 걸기 위해서이다. 물론, 재후킹을 다시
    // 걸려면 후킹걸 위치에 공간이 충분하지 체크해야되는데 그 코드는 위에 이미 설명
    // 해놨다. GetSizeNextFetchInst 함수에서 이 GetNextInst 함수를 사용해서 계산하며
    // 패치할 공간을 확보한다.

// #ifdef _DEBUG
    CString DBGMSG;
// #endif

    DWORD SizeNextInst = -1;

    // 주소 자체는 표시용이다. 그러므로 원본 지점을 줘도 된다. 해당 위치의 바이너리
    // 내용만 참고안하면 된다.
    uint64_t address = dbg.reg.eip;
	cs_insn *insn;
	size_t count;

    // 여기서 dna.DNA_SourceCode 는 떼어낸 코드이다. 원본 지점에서 패치하느라
    // 떼어내서 다른 곳에 보관을 해둔 것인데, 그냥 적당히 DNA_SourceCode 라고
    // 이름을 붙여서 구조체안에다가 버퍼를 만들어서 보관해두었다.
    // 이곳에서는 반드시 이 값을 써야되는 이유가 있는데, 왜냐면 이미 이 루틴이
    // 실행되는 시점에서는 원본지점이 털려있다. 즉, 인라인 패치를 한 상태에서
    // 지금 실행되는 것이므로 원본지점의 코드는 후킹코드로 설치되어 있으므로
    // 복사해놓은 원본코드를 주고 디스어셈블리를 시켜서 원래 코드가 명령어
    // 몇개가 조합된 상태냐를 알아내야 한다. 왜냐면, 다음번 명령 위치로 미리
    // 패치를 걸기 위해서인데 명령어가 조합되어 패치공간을 만든 상태라면 문제가
    // 어떤 명령어가 조합되어있고 사이즈는 몇이냐가 필요한데, 이미 원본 지점은
    // 털린상태이기 때문에 원본 코드 지점을 지정해주고 디스어셈블리를 시켜서
    // 분석하면 안된다. 복사해둔 코드를 분석시키되 어차피 패치할 때 몇바이트를
    // 패치할지 사이즈를 지정해주고있기 때문에 총 패치한 사이즈와 복사해둔 버퍼를
    // 지정해줘서 명령을 분석해서 갈라낸다. 물론, 최초에 지점을 지정해줄때는 총
    // 패치 사이즈를 수동으로 주었지만, 지금부터는 인스트루멘테이션 되면서 자동
    // 으로 패치사이즈를 구해서 지정하며 계속 연달아 패치하면서 실행되도록 짜놓기
    // 위해서 이런코드를 만든 것이다.
	if ((count = cs_disasm(handle, (unsigned char *)dna.DNA_SourceCode, dna.PatchSize, address, 0, &insn)))
    {
		size_t j;

		for (j = 0; j < count; j++)
        {
            if (j == 0)
            {
// #ifdef _DEBUG
		        DBGMSG.Format("[+][IMATINIB] 0x%0.8I64X:    %s    %s\n",
                               insn[j].address - GetBaseAddress(dna.ModuleName),
                               insn[j].mnemonic,
                               insn[j].op_str);

                OutputDebugString(DBGMSG);

//              print_insn_detail(handle, CS_MODE_32, &insn[j]);
// #endif
                SizeNextInst = insn[j].size;

                cs_x86 *x86;
                x86 = &(((cs_insn *)(&insn[j]))->detail->x86);
                int index = 1;
                int count = cs_op_count(handle, &insn[j], X86_OP_IMM);
                if (count) {
                    index = cs_op_index(handle, &insn[j], X86_OP_IMM, 1);
                }

                // 아직 모든 브랜치를 처리하게 해두지 못했음. 여기에 브랜치
                // 처리를 해두지 않으면 점프 자체를 직접 시키는 방식이기 때문에
                // 점프 지점 위치에 인라인 패치를 걸지 못하게 됨. 그렇기 때문에
                // 여기에 있는 점프 처리 부분을 하나 지워서 실행시켜보면 그 명령
                // 출력 이후에는 출력이 더이상 안나올 것임. 프로그램은 실행이 잘
                // 되지만 인스트럭션 출력은 더이상 안나온다는 얘기는 점프 하려는
                // 지점에 인라인 패치를 걸지 못했기 때문에 후킹 루틴을 타고 다시
                // 들어오지 못하고 프로그램이 계속 실행되고 있단 얘기임. 그렇기
                // 때문에 여기에서 처리하는 점프 루틴들은 직접 점프를 시키려는
                // 의도가 있고 동시에 점프할 지점에 인라인 패치를 걸려는 것임.
                // 그럴면 당연히 eflag 값을 체크해서 정말 점프할 지점에 점프할 수
                // 있는 건지 아닌지 eflag 값을 직접 다 체크해서 점프할 것 같으면
                // 점프할 곳에 패치를 걸고 점프 할 것 같지 않으면 다음 인스트럭션
                // 으로 증감해서 다른 라인에 인라인 패치를 걸어야 됨. 이게 계속
                // 연속으로 일어나면 계속 인라인 패치되면서 후킹루틴 속으로 계속
                // 빨려들어오는 것을 구현한 것임.
                switch (x86->opcode[0])
                {
                case 0x70:  // JO :: OF = 1 (short jump opcodes)
                    {
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x71:  // JNO :: OF = 0 (short jump opcodes)
                    {
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (OF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x72:  // JB, JNAE, JC :: CF = 1 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        if (CF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x73:  // JNB, JAE, JNC :: CF = 0 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        if (CF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                case 0x74:  // JE, JZ :: ZF = 1 (short jump opcodes)
                    {
                        // 앞쪽이나 뒷쪽이나 다 똑같은 설명이라서 여기에만
                        // 적어놓음. 제로 플래그 값을 구해서 1 이면 점프를
                        // 시킴. 이때, dna.branch_jump 를 셋팅해줘서 코드를
                        // 원복시킬때 참조하도록 함. dbg.reg.eip 값을 급격
                        // 하게 x86->operands[index].imm 즉, 점프 어디로 뛸지
                        // 해당 주소값으로 바꾸는 작업임. 일반 명령들은 모두
                        // dbg.reg.eip 값이 원복시킨 코드 지점으로 다시 되돌려서
                        // 원래 명령어가 실행되도록 해놨다면, 여기서는 그런거
                        // 없이 그냥 바로 제어흐름을 dbg.reg.eip 에 셋팅해줘서
                        // 점프지점으로 바로 가도록 해놓은 거란 얘기임.
                        // 이렇게 되면 dna.PathSize 값을 좀 백업해두고 이 값을
                        // 0 으로 셋팅함. SizeNextInst 도 0 으로 셋팅함.
                        // 이유는, 간단한데 점프를 직접해서 흐름을 바꿔줄건데
                        // 그럴려면 흐름을 바꿔버리는데 일단 코드를 원복 시켜놓고
                        // 뛰던지 말던지 해야할 것이기에 물론, 동시에 점프를 뛰는
                        // 주소 위치에도 인라인 패치를 걸어놓는 이중상황이 발생함.
                        // 결국, dna.PatchSize 값을 0 으로 만들어버리면 원래 코드를
                        // 복원하고 점프 주소로 뛸건데, 복원 코드에서 dna.PatchSize
                        // 값을 참조한단 말임. 코드를 짜다보니 더 복잡하게 된건
                        // 다음 인라인 패치할 지점이 점프된 지점이니까 이 지점에서
                        // 패치할 공간이 충분한지 계산할때는 dna.PatchSize 값이 0
                        // 이어야만 함. 왜냐면, dna.PatchSize 값이 패치한 곳의 총
                        // 사이즈인데 명령어를 몇개씩 뭉쳐서 사이즈를 갖고 있을 경우
                        // 나머지 값을 계산해주고 있단 말임. 현재 명령이 갖고 있는
                        // 명령어 길이가 SizeNextInst 값인데 이 값 만큼 dna.PatchSize
                        // 에서 빼주면 다음에 구해야할 명령어 사이즈를 구할 수 있기
                        // 때문임. 문제는 이 두가지 작업이 둘 다 패치를 할려는 상황
                        // 이기 때문인데 한쪽은 원복패치, 다른 한쪽은 급격히 점프뛴
                        // 지점에서 패치임. 결국, 여기서 문제가 발생하는 값이 총량
                        // 패치 사이즈임. 이 값이 0 이 되어야 하는데 코드를 원복시킬
                        // 때는 0 이면 안된다는 얘기. 결국, 백업을 해두어서 원복시킬때
                        // 사용할 수 있도록 dna.SavedPatchSize 에 저장해둠.
                        // 원래 명령어를 복원하기 위해서 패치할 때는 dna.SavedPatchSize
                        // 값을 사용하고 점프한 곳에 인라인 패치를 미리 걸어둘려고 할때는
                        // 현재 명령 사이즈도 의미가 없고 나머지 계산을 하기위한 값도
                        // 있으면 곤란하기 때문에 0 으로 만든 값을 사용함.
                        // 여기서 0 이 중요한 것은 나머지 계산할때, 점프뛴 지점에 충분한
                        // 패치공간이 있는지 체크할려고 디스어셈블리 시키는 주소 자체를
                        // 여기에서 dbg.reg.eip 는 x86->operands[index].imm 즉, 점프주소
                        // 자체로 지정해주고 있기 때문임. 충분한 공간을 체크하는 함수에서는
                        // dbg.reg.eip 값을 기준으로 디스어셈블리 시킴. 그렇기 때문에
                        // dbg.reg.eip 에 SizeNextInst 값을 더하는 일반 인스트럭션 처리
                        // 상태로 처리할려면 엉망진창이 될 것임. 그래서 SizeNextInst 값인
                        // 현재 어셈블리 명령이 몇 바이트인가를 0 으로 만들어주어야 함.
                        // 그런데 마찬가지로 dna.PatchSize 도 0 으로 만들어주는 것이 다
                        // 똑같은 의미가 됨. 즉, 점프지점으로 dbg.reg.eip 흐름을 지정해
                        // 주었는데 충분한 공간을 확인하는 디스어셈블리 함수는 이 값을
                        // 참고하로 분석하기에 모두 0 으로 만들어주는 개념. 문제는 이 값
                        // 자체를 0 으로 만들면 현재 패치되어있는 상태인 원본 지점의 코드를
                        // 원복시키는데 문제가 발생한다는 얘기였음. 그래서 dna.branch_jump
                        // 라는 플래그도 만들어서 점프 상황이면 다르게 처리하도록 경우의
                        // 수를 두었음.
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (ZF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x75:  // JNE, JNZ :: ZF = 0 (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (ZF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x76:  // JBE, JNA :: CF = 1 or ZF = 1 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (CF || ZF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x77:  // JA, JNBE :: CF = 0 and ZF = 0 (short jump opcodes)
                    {
                        BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        if (CF == 0 && ZF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x78:  // JS :: SF = 1 (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        if (SF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x79:  // JNS :: SF = 0 (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        if (SF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7A:  // JP, JPE :: PF = 1 (short jump opcodes)
                    {
                        BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                        if (PF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7B:  // JNP, JPO :: PF = 0 (short jump opcodes)
                    {
                        BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                        if (PF == 0)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7C:  // JL, JNGE :: SF <> OF (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (SF != OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7D:  // JGE, JNL :: SF = OF (short jump opcodes)
                    {
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (SF == OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7E:  // JLE, JNG :: ZF = 1 or SF <> OF (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (ZF || SF != OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x7F:  // JG, JNLE :: ZF = 0 and SF = OF (short jump opcodes)
                    {
                        BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                        BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                        BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                        if (ZF == 0 && SF == OF)
                        {
                            dna.branch_jump = true;
                            dna.SavedPatchSize = dna.PatchSize;
                            dna.PatchSize = 0;
                            SizeNextInst = 0;
                            dbg.reg.eip = x86->operands[index].imm;
                        }
                    }
                    break;
                case 0x0F:
                    {
                        switch(x86->opcode[1])
                        {
                        case 0x80:  // JO :: OF = 1 (near jump opcodes)
                            {
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x81:  // JNO :: OF = 0 (near jump opcodes)
                            {
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (OF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x82:  // JB, JNAE, JC :: CF = 1 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                if (CF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x83:  // JNB, JAE, JNC :: CF = 0 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                if (CF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x84:  // JE, JZ :: ZF = 1 (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (ZF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x85:  // JNE, JNZ :: ZF = 0 (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (ZF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x86:  // JBE, JNA :: CF = 1 or ZF = 1 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (CF || ZF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x87:  // JA, JNBE :: CF = 0 and ZF = 0 (near jump opcodes)
                            {
                                BOOL CF = dbg.reg.eflags & X86_EFLAGS_CF ? 1 : 0;
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                if (CF == 0 && ZF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x88:  // JS :: SF = 1 (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                if (SF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x89:  // JNS :: SF = 0 (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                if (SF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8A:  // JP, JPE :: PF = 1 (near jump opcodes)
                            {
                                BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                                if (PF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8B:  // JNP, JPO :: PF = 0 (near jump opcodes)
                            {
                                BOOL PF = dbg.reg.eflags & X86_EFLAGS_PF ? 1 : 0;
                                if (PF == 0)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8C:  // JL, JNGE :: SF <> OF (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (SF != OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8D:  // JGE, JNL :: SF = OF (near jump opcodes)
                            {
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (SF == OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8E:  // JLE, JNG :: ZF = 1 or SF <> OF (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (ZF || SF != OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        case 0x8F:  // JG, JNLE :: ZF = 0 and SF = OF (near jump opcodes)
                            {
                                BOOL ZF = dbg.reg.eflags & X86_EFLAGS_ZF ? 1 : 0;
                                BOOL SF = dbg.reg.eflags & X86_EFLAGS_SF ? 1 : 0;
                                BOOL OF = dbg.reg.eflags & X86_EFLAGS_OF ? 1 : 0;
                                if (ZF == 0 && SF == OF)
                                {
                                    dna.branch_jump = true;
                                    dna.SavedPatchSize = dna.PatchSize;
                                    dna.PatchSize = 0;
                                    SizeNextInst = 0;
                                    dbg.reg.eip = x86->operands[index].imm;
                                }
                            }
                            break;
                        }
                    }
                    break;
                case 0xE8:  // CALL
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.esp -= 4;
                        *((DWORD *)(dbg.reg.esp)) = dbg.reg.eip + 5;
                        dbg.reg.eip = x86->operands[index].imm;
                        dbg.reg.call = true;
                    }
                    break;
                case 0xE9:  // JMP
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.eip = x86->operands[index].imm;
                    }
                    break;
                case 0xEB:  // JMP
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        dbg.reg.eip = x86->operands[index].imm;
                    }
                    break;
                case 0xFF:
                    {
                        switch(x86->modrm)
                        {
                        case 0x25:  // JMP
                            {
                                // ENG: This is symbol of import function addresses.
                                // KOR: 심볼 처리를 해야되는데..

                                // 이전에 CALL 명령이 실행됐었고, CALL 안쪽에 기어들어
                                // 오니까 바로 0xFF 0x25 JMP 명령이 버티고 있다면 이건
                                // 대부분 임포트 함수 호출한 상황임. 예를들어서 CALL memset
                                // 같은 부류가 호출된 상황임. 그러면 esp 스택에서 값을 하나
                                // 뽑아보면 리턴주소가 될 것이고, 나는 memset 안쪽으로 기어
                                // 들어가서 브랜치 처리를 할 생각이 없기 때문에 리턴 주소
                                // 쪽에다가 인라인 패치를 걸어둘려는 것임. memset 이 다 호출
                                // 되서 처리하고 되돌아오면 후킹 루틴으로 다시 타고 들어오도록
                                // 하겠다는 얘기임.
                                if (dbg.reg.call) {
                                    // 이 부분은 아래의 설명에 디테일하게 적어놨음
                                    dbg.reg.ret = *((DWORD *)(dbg.reg.esp));
                                }
                                else {
                                    // 만약, 이전에 CALL 이 호출된 상황이 아니라면, 거참
                                    // 좀 거시기 하지만 여전히 이런 경우에도 임포트 테이블
                                    // 함수를 호출하는 상황임.
                                    // 예를들면 이렇게 두가지가 있음.
/*
CASE 1:  다음과 같이 memset 을 호출하면 안에 딸랑 0xFF 0x25 (JMP) 가 존재하는 상황.
         그러나 이 안쪽까지 추적해서 들어갈 필요가 없음. 선택 사항으로 빼두어야 함.
         만약, 추적을 허용해서 처리하면 계속해서 미친듯이 빨려들어가다가 밑바닥까지
         핥을려고 하면서 접근이 불가능한 지점이 오면 뻑이 나버림. 메모리 범위를 지정
         해주도록 할 수도 있지만, 최대한 하드코딩은 빼고 사용자에게 선택할 수 있는
         상황으로 만들어줘야하기 때문에 일단, 고민을 해봐야하고 현재는 내부까지 추적
         해서 들어가지 못하고 겉으로 빠져나가게 할려고 함. 즉, 일반 인스트럭션 처럼
         처리하도록 할려고 함. (나중에 심볼 처리 부분만 추가로 구현해둘려고 함)
         그렇다면 0xFF 0x25 명령에서 +6 바이트를 해주면 될까? 절대 안됨. 그렇게 할
         경우에는 아래의 jmp ds:__imp_memset 은 딸랑 JMP 만 존재하고 있고 다음 명령
         자체가 없음. 그렇기 때문에 다음 인스트럭션 부분에 인라인 패치를 걸면 다른
         함수의 머리통이 될 것임. 또한 인라인 패치한 지점으로 들어오지도 않음.
         이 말은 memset 함수가 리턴한다는 의미임. 그러므로 이전 단계에서 만약, CALL
         명령이 실행되었다면 dbg.reg.call 을 셋팅해두었기 때문에 현재가 0xFF 0x25 상태
         일 경우에는 dbg.reg.esp 에서 주소를 뽑아서 해당 리턴 어드레스 위치에 인라인
         패치를 걸어야 다시 후킹루틴으로 빨려들어올 것임. 그 주소는 아래에서 6C1A37E2
         주소가 될 것임.
----------------------------------------------------------------------------------------------------------
.text:6C1A37DC 56                                                  push    esi             ; Dst
.text:6C1A37DD E8 09 00 00 00   [Import Table's function!!] =>     call    memset
.text:6C1A37E2 83 4E 14 FF                                         or      dword ptr [esi+14h], 0FFFFFFFFh
----------------------------------------------------------------------------------------------------------
.text:6C1A37D2                                     ; int __thiscall sub_6C1A37D2(void *Dst)
.text:6C1A37D2                                     sub_6C1A37D2    proc near       
.text:6C1A37EB FF 25 C8 27 1A 6C                                   jmp     ds:__imp_memset
.text:6C1A37EB                                     memset          endp
----------------------------------------------------------------------------------------------------------

CASE 1:  두번째 경우는 아래와 같은 부류임. 이전에 CALL 명령이 호출되지 않았음.
         단순히 임포트 테이블에 있는 함수를 호출하는 것임. 이 경우에는 memset
         처럼 CRT 함수가 아니라 MS 오피스의 써드파티 라이브러리 DLL 안에 있는
         API 처럼 외장함수를 호출할 경우임. 이 경우에도 추적할지 말지는 사용자
         선택을 둘 수 있도록 해줘야 함. 다만, 현재는 귀찮으니까 추적할 생각이
         없으므로 일반 명령처럼 처리해줄려고 함. 그럴려면 스택에서 값을 뽑아서는
         안되고 다음 0xFF 0x25 JMP 다음 인스트럭션 라인쪽에 패치를 걸어주어야 함.
         즉, 일반 명령 처럼 증감 처리해야됨. (문제는 여기서 발생함. 다음의 부분
         까지 추적하게되면 JMP 까지 찍히고 다음부터 안찍힘. 추적이 멈춤. 아래의
         JMP 명령이 실행된 다음에 두번다시 집나가서 제어가 안돌아옴. 후킹 걸은
         다음라인의 패치지점으로 실행이 안된단 얘기임. 문제를 알아낼려고 디버깅을
         시도했는데 엄한 부분에서 계속 익셉션이 떨어져서 원인확인이 불가능함.
         디버거로 볼때는 무조건 advapi32.dll 안에서 계속 뻑이나서 걸림. 정말로
         문제가 뭐냐면 프로그램이 뻑나지 않고 잘만 실행되고 있는데 디버거로 볼때만
         뻑이 난다는 것임. 그래서 아래의 JMP 까지 잘 실행되고나서 추적이 중단되는
         상황이 발생하고 프로그램은 아무 문제없이 잘만 실행되고 있음. 아무런 버그
         증상없이 잘 실행됨. 디버거로 왜 추적이 안되는지 확인할려고 할때만 advapi32.dll
         안에서 뻑나서 더이상 추적을 못하게 한다는 것이.. 마치, 양자역학을 경험하고
         있는 것 같은 느낌임. 확인해볼려고 관찰자가 있으면 전자가 입자로 바뀌어서
         점무늬로 찍히는데, 확인안하면 관찰자가 없으니까 입자가 아닌 파동으로 간섭
         무늬를 만들고 그런 느낌이랄까? 무슨 양자역학도 아니고 디버거로 확인할려면
         레지스터 값이 0 이되면서 익셉션이 발생해서 뻑나는 곳이 생겨나고 그냥 돌릴
         경우에는 아무런 문제도 없이 잘만 실행되는데 추적만 중단되는 상황. 결국,
         엄청난 고생 끝에 일단 여기까지로 GG 쳤음. 누가 왜 이런건지 좀 버그가 있다면
         잡아주면 좋겠지만.. 일단, 컨셉은 이렇다는 거.

.text:6C1AFC4B 0F 84 13 21 00 00                                   jz      loc_6C1B1D64
.text:6C1AFC51 5D                                                  pop     ebp
.text:6C1AFC52 FF 25 00 10 FE 6C                                   jmp     _MsoFreePv@4    ; MsoFreePv(x)
.text:6C1AFC52                                     sub_6C1AFC44    endp
.text:6C1AFC52
*/

                                    // 그래서 dbg.reg.eip 에 +6 을 더한다. 일반적인
                                    // 명령 처럼 처리할려고..
                                    dbg.reg.ret = dbg.reg.eip + 6;
                                }

                                dna.branch_jump = false;
                                dna.SavedPatchSize = dna.PatchSize;
                                dna.PatchSize = 0;
                                SizeNextInst = 0;

                                // 0xFF 0x25 일 경우에는 IMM 값이 아니라 DISP 값이 주소부분이다
                                cs_x86_op *op = &(x86->operands[0]);
                                dbg.reg.eip = *((DWORD *)(op->mem.disp));
                            }
                            break;
                        }
                    }
                    break;
                case 0xC2:  // retn
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;
                        // ex) retn 10h
                        // 
                        // retn instruction is get the Saved Return Address and
                        // and It is plus 0x04 of the esp.
                        // retn 10h (esp + 0x04 and esp + 0x10)
                        // dbg.reg.esp is 0x04 + 0x10.
                        // Do You Understand of My Explain? ㅎㅎㅎ
                        // dumpcode((unsigned char *)(dbg.reg.esp), 200);

                        // 안되는 영어로 굳이 설명을 했는데, 한글로 다시 설명하면
                        // 리턴 명령을 만나면 esp 에서 값을 뺀다. 그리고, eip 를
                        // 리턴 주소 값으로 바꿔주는 것임.
                        // 이때, 0x04 를 더해주는 것은 ret 명령이 현재 esp 에서
                        // 값을 빼낼때 pop 시키는 명령이기 때문에 +4 를 해준 것임.
                        // 그리고 retn 10h 라고 할때 10h 가 x86->operands[index].imm
                        // 값이라눈.. 이 값을 스택에서 마저 더해주어야 함. 스택정리
                        // 값이기 때문임. 참.. 쉽죠?
                        dbg.reg.eip = *((DWORD *)(dbg.reg.esp));
                        dbg.reg.esp += 0x04 + x86->operands[index].imm;
                    }
                    break;
                case 0xC3:  // ret
                    {
                        dna.branch_jump = true;
                        dna.SavedPatchSize = dna.PatchSize;
                        dna.PatchSize = 0;
                        SizeNextInst = 0;

                        // 여기는 더 쉬움. 더해줄 것도 없음 그냥 ret 에 대한 popping
                        // +4 처리만 해주면 됨.
                        dbg.reg.eip = *((DWORD *)(dbg.reg.esp));
                        dbg.reg.esp += 0x04;
                    }
                    break;
                }
            }
		}

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
#ifdef _DEBUG
		DBGMSG.Format("[+][IMATINIB] ****************\n");
        OutputDebugString(DBGMSG);
		DBGMSG.Format("[+][IMATINIB] ERROR: Failed to disasm given code!\n");
        OutputDebugString(DBGMSG);
#endif
	}

#ifdef _DEBUG
	DBGMSG.Format("[+][IMATINIB] \n");
    OutputDebugString(DBGMSG);
#endif

    return SizeNextInst;
}

void RecoveryInst(FINGERPRINTSTRUCT &dna)
{
    // 이 함수는 후킹걸때 패치한 부분을 원복시킨다.

    // 만약 브랜치일 경우에는 원래 명령어로 실행시켜주는게 아니라 내가 직접
    // 점프를 해주었기 때문에 패치 사이즈가 문제가 됨. 그래서 패치 사이즈를
    // 미리 백업해둔 변수가 dna.SavedPatchSize 값임. 그래서 이 값으로 dna.PatchSize
    // 변수에 넣어주어서 일단 코드를 복원시키고 다시 dna.PatchSize 값은 0 으로
    // 만들어줌. 왜 이렇게 하냐면 디스어셈블리를 시켜서 다음번에 패치할 위치의
    // 공간을 확보하는 함수에서 dna.PatchSize 값이 0 이어야 함. 점프뛸 지점의
    // 패치 사이즈로 지정해주어야 하는게 아니라 흐름이 완전 바뀌기 때문에 점프
    // 지점에 패치 사이즈를 지정해주지 않는 것임. 왜냐면, dna.PatchSize 값이
    // 명령어가 여러개가 조합된 상태라면, 현재 명령어 사이즈만큼 빼주고 나머지
    // 값을 기본으로 두고 추가적인 공간 사이즈를 구하는 상황인데, 그 위치가
    // dbg.reg.eip 인데 이놈이 점프처리 때문에 주소 자체가 새롭게 지정이 된
    // 상황에서 나머지 값을 구하는 것 자체가 의미도 없고 구해서도 안됨.
    // 그래서 dna.PatchSize 값은 현재 구현에서는 반드시 0 이어야 됨. 그런데 0 을
    // 만들어 버리면 점프 뛰기 이전에 지점은 어떻게 원래 코드로 원복시켜주노..
    // 그렇기 때문에 0 으로 만들기 전에 값을 미리 저장해 놓은 dna.SavedPatchSize
    // 값은 점프 뛰기전에 패치되어 있는 지점의 코드 원복을 위해서 백업해놓은
    // 값임. 점프를 하더라도 코드는 원복 시켜놓아야 하니까 이놈을 다시 꺼내서
    // 원래 원복시킬 지점을 패치하려는 의도임. 이때, dbg.reg.ret 의 경우도 마찬
    // 가지로 처리를 해줌. 그러나, dbg.reg.ret 값은 0xFF 0x25 명령일 때 셋팅하는
    // 값임. 0xFF 0x25 는 브랜치 명령이지만 처리했다가는 지옷되는 상황이므로,
    // 브랜치 처럼 처리를 해서 코드 원복은 시키지만, 점프할 지점에 패치를 걸어서
    // 후킹루틴으로 타고들어오는 처리를 하지못하게 만들어야 됨. 현재는 일단 코드를
    // 원복시키는 루틴이기 때문에 여기서는 그냥 브랜치 처리하듯이 처리를 묶어준
    // 것임.
    if (dna.branch_jump || dbg.reg.ret) {
        dna.PatchSize = dna.SavedPatchSize;
        RecoveryCode(dna.AddressFound, dna);
        dna.PatchSize = 0;
    }
    else {
        // 일반적인 다음 명령 지점에 패치걸기 전에 원래 코드 지점의 코드를 복원시킴
        RecoveryCode(dna.AddressFound, dna);
    }

    // 원본 시킨 다음에는 캐쉬를 비워주어야 갱신된다. 그러나, 별 효과 없었다.
    /*
    FlushInstructionCache(GetCurrentThread(),
                          (LPCVOID)GetBaseAddress(dna.ModuleName),
                          GetImageSize(dna.ModuleName));
    */
}

void ChainRecoveryInst(FINGERPRINTSTRUCT &dna)
{
    // 이 함수는 인스트루멘테이션을 흉내내기 위해서 연속 인라인 패치를 해서 후킹을
    // 하는 아주 중요한 역할을 하는 핵심루틴이다.

    // 현재 인스트럭션 사이즈 얻기
    DWORD SizeNextInst = GetNextInst(dna);
    
    // ENG: Restore Original Codes
    // KOR: 인라인 패치한 지점을 다시 원복 시킴
    RecoveryInst(dna);

    DWORD SizeNextFetchInst;

    // 이 부분은 후킹을 하기위해서 찾은 지점에 디스어셈블러를 돌려서 나온 현재 패치한 곳의
    // 첫번째 원래 명령의 사이즈를 더한다. 증감시키고 다시 연속으로 이어서 다음 지점에 패치를
    // 걸기 위해서이다.

    // 브랜치일 경우
    if (dna.branch_jump) {
        // 다음번에 패치할 곳의 사이즈 얻기
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        dna.AddressFound = dbg.reg.eip;
        dna.branch_jump = false;
    } // 브랜치지만 브랜치를 타면 아되는 경우 (\xFF\x25 명령에 대한 처리를 하기위함.)
    else if (dbg.reg.ret) { // (대부분 주소가 임포트 함수 주소들이기 때문임)
        // 현재 dbg.reg.eip 는 이미 0xFF 0x25 때문에 disp 주소임. 즉, 임포트 함수 주소
        DWORD EIP = dbg.reg.eip;
        // 0xFF 0x25 는 두가지 경우가 있는데 CALL 안에 있을 때와 아닐 때임.
        // 만약 아니면 일반 인스트럭션 처럼 처리하고 맞다면 CALL 에서의 리턴
        // 주소로 되돌려야됨. dbg.reg.ret 값은 0xFF 0x25 명령이 CALL 다음에
        // 실행된 상태일 경우에는 CALL 의 리턴주소이고, 일반 상태에서 실행된
        // 상태라면 이 값은 다음 인스트럭션 부분을 인라인 패치하기 위해서 +6
        // Byte 만큼 더해준 값임.
        dbg.reg.eip = dbg.reg.ret;
        // 현재 dbg.reg.eip 는 + 6 (0xFF 0x25 는 6 Byte 임) 가 된 상태임.
        // 이 위치에서 디스어셈블리 시킨 후에 명령어 사이즈를 구해냄.
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        // dna.AddressFound 는 모냐면, 브랜치가 없으면 순차적으로 인스트럭션
        // 명령 만큼씩 증가시키는 순차모드로 사용하기 위해서 쓰는 값임. 물론,
        // 최초에 인라인 패치지점을 찾았을 때부터 시작함. dbg.reg.eip 를 직접
        // 지정해주는 이유는 이미 0xFF 0x25 처리할때 dbg.reg.eip 에 +6 을 했기
        // 때문임. 만약, CALL 안에서 0xFF 0x25 명령이 실행된 경우라면 esp 값을
        // 꺼내기 때문에 그 위치에 리턴주소가 있고 그 주소 값이 패치해야할 지점임.
        dna.AddressFound = dbg.reg.eip;
        // 콜 다음에 실행된 것일 경우를 대비해서 call 표시를 초기화 함.
        dbg.reg.call = false;
        // dbg.reg.eip 값은 다시 백업해둔 값으로 되돌림. 여기서 백업해둔 값은
        // 0xFF 0x25 명령의 인자값(disp 값) 주소임. 대부분 import 주소로 확인이
        // 되었음. 나중엔 주소를 임포트 테이블에서 직접 찾아서 함수 이름으로 바꿔
        // 심볼처리를 해줄려고 함. 여튼, dna.AddressFound 는 순차 주소로 지정해서
        // 브랜치가 아닌 상태를 처리하도록 해놓고 dbg.reg.eip 는 0xFF 0x25 명령의
        // 점프 주소로 날려버림. 즉, dbg.reg.eip 지점에서 한참 실행되고 나서 되돌
        // 아 오는 일이 발생하면 인라인 패치가 걸린 지점인 dna.AdddressFound 지점
        // 에서 다시 후킹함수 쪽으로 제어가 들어오게 될 것임.
        // (Fix: 현재 이 부분이 골머리를 썩고 있음. 점프한 뒤에 안돌아오는 구간이
        //       생김. 집나가서 안들어오는 아이 처럼 안돌아오는 부분을 이해를 하지
        //       못해서 버그를 못잡고 있음. 다 잘되는데 특정 부분에서 안됨.)
        dbg.reg.eip = EIP;
        // dbg.reg.ret 값을 초기화 시켜서 다음에는 이 부분으로 안들어오게 함.
        dbg.reg.ret = 0;
    }
    else {
        // 이 부분은 일반 인스트럭션 처리를 하기 위해서 순차적으로 현재 인스트럭션
        // 사이즈 만큼 건너띄고 다음 부분의 인스트럭션 사이즈를 구해서 SizeNextFetchInst
        // 값으로 지정해주는 것임. 그렇게 해야 현재 인스트럭션 만큼 뒷부분에 충분한
        // 패치공간이 있는지 확인하고 DNA_Injector 함수로 패치를 걸 수 있기 때문임.
        SizeNextFetchInst = GetSizeNextFetchInst(dna, SizeNextInst);
        // 현재 인스트럭션 부분 만큼 건너뜀. 조심할 개념은 인라인 패치는 모두
        // dna.AddressFound 값을 기준으로 패치함. dbg.reg.eip 는 브랜치 처럼
        // 급격하게 실행할 주소가 달라져도 상관이 없게 해놨다면 이 dna.AddressFound
        // 값은 기본 모드가 순차적인 패치임. 그래서 점프 명령일 때는 위와 같이 상황별
        // 처리를 별도로 두어서 dna.AddressFound 를 급격하게 바꿀 수 있는 상황으로 해준
        // 것이고 여기서는 순차 명령 패치이니까 SizeNextInst 처럼 현재 명령어 사이즈를
        // 구해서 더해줌. 그러면 그 위치에 패치를 거는데 충분한 패치 공간이 있는지 알아야
        // 하기 때문에 Capstone 의 Disassembly 능력을 빌어서 패치 공간 사이즈를 구하는 것임.
        // SizeNextInst(현재 명령 즉, 건너뛸 사이즈) 이고 SizeNextFetchInst 는 다음번 패치할
        // 공간이 충분하냐와 충분하면 사이즈가 몇이냐라고 생각하셈.
        dna.AddressFound += SizeNextInst;
        // 역시나 마찬가지로 일반 명령어가 실행된 것이면, CALL 호출이 있어다고 하더라도
        // 현재는 일반 인스트럭션이 호출된 것이니까 CALL 표식을 초기화 시켜주어야함.
        // 이렇게 안하면 0xFF 0x25 같은 무시무시한 놈을 만나면 지옷이 됨.
        dbg.reg.call = false;
    }

    // 위에서 설명한 부분이다. 디스어셈블러를 돌려서 충분히 사이즈가 마련되면 해당 사이즈를 리턴
    // 하는 함수를 설명하였다. 이 함수의 리턴값은 다음번 명령 위치에서 패치할때 그곳의 위치가
    // 부족할 수 있으므로, 얼마만큼의 명령들을 패치해야 충분한 사이즈인가를 의미한다. 그 함수를
    // 통해서 충분한 공간이 몇인지 얻어내면 이 값을 다음번에 패치할 상황에서 총 패치 사이즈 크기로
    // 지정해준다.
    dna.PatchSize = SizeNextFetchInst;

    // 처음에 최초 후킹을 걸었을 때와 똑같은 함수를 호출하여 다음 명령 위치를 후킹걸린 상태에서
    // 패치시킨다. 이미 코드는 위에서 원복시킨 상황이다. 원복을 자주 안하게 코드를 좀 개선할 수
    // 있기는 하지만 크게 속도적은 문제가 생기지 않으므로 그냥 원복 시키고 패치하게 했다.
    DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna);

    // 캐쉬에 남아있는 명령을 플러시 시켜서 갱신된 이미지의 코드가 반영되게 한다.
    // 이거 원래 반영 안되는 건가. 패치하면 바로바로 적용이 됨. 이거 굳이 안해도
    // 문제 없는거 같은데, 나중에 문제되면 주석 풀던지 말던지.. 일단 이거 주석을
    // 처리해놓은 이유는 아무 문제가 없으면 속도 좀 더 빠르게 올려볼려고 한거임.
    /*
    FlushInstructionCache(GetCurrentThread(),
                          (LPCVOID)GetBaseAddress(dna.ModuleName),
                          GetImageSize(dna.ModuleName));
    */
}

// 인스트루멘테이션 샘플 코드 (활용하는 방법을 보여주기 위해 첨부한 예제임)
void __fastcall DNA_Instrument(DWORD EIP)
{
    if (EIP == dna->DNA.Imatinib.AddressFound)
    {
        // 인스트루멘테이션 예제. 앞에서 설명한 함수들이 사용됨.
        ChainRecoveryInst(dna->DNA.Imatinib);
    }
}

///////////////////////////////////////////////////////////////////////
// Instrument()
///////////////////////////////////////////////////////////////////////
void __fastcall Instrument(DWORD EIP)
{
    ////////////////////////////////////////////
    // Instruction Instrumentation START
    ////////////////////////////////////////////
    
    // KOR: 크리티컬을 걸어주는게 맞을지 안맞을지
    //      모르겠음. 프로그래밍 도중에 자꾸만 뻑
    //      나는 일이 생겨서 만들어뒀는데 동기화
    //      문제가 아니었음. 코드가 아까워서 준비만
    //      해놨음.

    // EnterCriticalSection(&cs);

    // ENG: Instrumentation Sample - 1 (Instruction Tracing)
    // KOR: 인스트루멘테이션 샘플 1 번 - (인스트럭션 추적하기)
    DNA_Instrument(EIP);

    // LeaveCriticalSection(&cs);
    ////////////////////////////////////////////
    // Instruction Instrumentation END
    ////////////////////////////////////////////
}

//////////////////////////////////////////////////////////////////////
// Imatinib_STUB()
// Description: Imatinib_STUB trampoline function stub
// -------------------------------------------------------------------
void __declspec(naked) Imatinib_STUB()
{
    __asm {

        // ENG: pushfd and pop before dirty of stack.
        // KOR: 스택이 오염되는 것을 방지하기 위해서 먼저 pushfd 를 처리해줘야 함
        pushfd
        pop    dbg.reg.eflags

        // ENG: Get Saved Return Address & Delete CALL Stack Gap (translate CALL to JMP)
        // KOR: 원본 코드위치의 EIP 값을 얻고, 콜 후킹을 걸었기 때문에 발생한 4 바이트가
        //      POP 때문에 제거됨. 이것은 CALL 호출을 JMP 점프로 처리하기 위함.
        pop    dbg.reg.eip

        // ENG: Get Registers
        // KOR: naked 함수이기 때문에 여기서 얻는 레지스터들은 모두 깨끗한 값들이 얻어짐.
        //      다만, EIP 와 ESP 가 약간 차이가 발생하기 때문에 교정해줘야 함.
        mov    dbg.reg.eax, eax
        mov    dbg.reg.ecx, ecx
        mov    dbg.reg.edx, edx
        mov    dbg.reg.ebx, ebx
        mov    dbg.reg.esp, esp
        mov    dbg.reg.ebp, ebp
        mov    dbg.reg.esi, esi
        mov    dbg.reg.edi, edi

        // ENG: Adjust EIP (This EIP have the size of added 5 on CALL hooked routine.)
        // KOR: 먼저, EIP 값을 교정해줌. 현재 얻은 EIP 는 CALL 명령이 인라인 패치된
        //      상태에서 함수안에 들어와서 얻어낸 값이므로 리턴 어드레스가 되어있음.
        //      그러므로 리턴어드레스가 아니라 원래 EIP 값을 얻어야 하므로 -5 만큼을
        //      빼주어야 함.

        push   eax
        mov    eax, dbg.reg.eip
        sub    eax, 5
        mov    dbg.reg.eip, eax
        pop    eax
    
        // ENG: Backup registers
        // KOR: 이거 안해주면 뻑남. 뒤에서 분명 레지스터를 0x20 바이트 모두 다
        //      복원해주고 있는데도 불구하고 안해주면 뻑이남.
        pushad
    }

    // ENG: Instrument the instructions by current EIP.
    // KOR: EIP 값을 식별자로 취하여 인스트루멘테이션 루틴을 호출함.
    //      내부의 인스트루멘테이션 함수들은 자기가 작업할 상황이
    //      맞는지 EIP 값을 확인해서 맞으면 자신의 루틴을 수행함.
    Instrument(dbg.reg.eip);

    __asm {

        // ENG: The pushfd & popfd or push & popfd or pushfd & pop makes dirty the top stack.
        //      It must use bitween pushad and popad. Current DNA_Instrument function translate
        //      instruction the CALL to the JMP therefore if current instruction is the CALL,
        //      esp != dbg.reg.esp. Do you understand of my explains? If push & popfd is used
        //      after DNA_Instrument, top stack is dirty.
        // KOR: push 와 popfd 또는 pushfd 와 pop 또는 push 와 popfd 모두 현재 스택 값을 더럽힐
        //      수 있다. 현재 CALL 을 JMP 로 바꾼 상태이므로, DNA_Instrument 함수에 들어갔다가
        //      나왔을때 스택이 4 바이트가 차이가 나는 상태이다. 왜냐면, 원래 원본 코드가 CALL
        //      명령 처리하고 할때 역시도, 현재 지금 자체 점프 처리로 바꿔서 처리하고 있기 때문
        //      에 스택에 4 만큼의 처리가 실제로 갭이 일어나고 있다는 얘기이다. 즉, 현재 실제
        //      esp 와 dbg.reg.esp 는 4 바이트 만큼의 차이가 나는데 push 했다가 popfd 를 해버리면
        //      리턴 주소가 있어야 할 곳에 eflag 값이 들어가게된다. 왜냐면 이 뒷 부분에서 실제로
        //      mov esp, dbg.reg.esp 로 스택을 실제로 맞춰주지 않나. 즉, 실제와 가상을 구분짓지
        //      못하면 헷갈릴 수 밖에 없다. 실제로는 스택이 4 만큼 차이가 나고 있지만 Instrument
        //      함수 안쪽에서는 CALL 명령을 JMP 명령으로 처리해주면서 실제로 스택에 값을 모두
        //      정상적으로 셋팅해주고 있는 상황이다. 그러나, 현재 지금 요기부분 명령 처리를 하는
        //      상황에서는 push dbg.reg.eflags 와 popfd 쌍이 실행되면 실제 esp 를 건드린다는 것이
        //      라는 얘기이다. 그렇게 되면 4 바이트 만큼을 건드려온다는 얘기이다. 그렇기 때문에
        //      Instrument 함수안쪽에서 아무리 제대로된 값을 넣어줘도 이 push popfd 명령 쌍이
        //      스택을 더럽히기 때문에 그 바로 뒤의 mov esp, dbg.reg.esp 명령이 실행되기 전에
        //      더럽혀진 스택을 전달하게 된다. 그럼 당연히 eflags 값을 주소로 생각하고 점프하려고
        //      할테니 뻑날 것이다. 그러므로 pushad 와 popad 로 묶은 뒤에 그 안쪽에서 실행시켜야만
        //      한다. 그래야 정상적으로 실행된다.
        //
        push   dbg.reg.eflags
        popfd

        // ENG: Restore registers
        // KOR: 레지스터 복원
        popad

        // ENG: Overwrite Registers
        // KOR: 만약 Instrument 함수에서 레지스터를 조작해주거나 할 경우에는
        //      여기서 새롭게 오버라이트 시킴.

        mov    eax, dbg.reg.eax
        mov    ecx, dbg.reg.ecx
        mov    edx, dbg.reg.edx
        mov    ebx, dbg.reg.ebx
        mov    esp, dbg.reg.esp
        mov    ebp, dbg.reg.ebp
        mov    esi, dbg.reg.esi
        mov    edi, dbg.reg.edi

        // ENG: JUMP EIP
        // KOR: EIP 로 점프하도록 바꿈. 모든 브랜치 인스트럭션들은 전부 원래
        //      코드로 실행되는게 아니라 이 후킹 DLL 안에서 처리함. 원래의
        //      인스트럭션으로 되돌려서 원래 인스트럭션이 실행되어 점프하는
        //      개념이 아니라 직접 인스트럭션을 판단해서 내부에서 점프를 모두
        //      직접 컨트롤하도록 걸어놓은 상태임. 이렇게 해야지 나중에 Basic
        //      Block 들을 처리할 수 있을 것 같아서 일부러 그렇게 해놓았음.
        jmp    dbg.reg.eip
    }
}

/* 외장 디버깅 컨트롤러와 연결시킬 방법을 구현해볼려고 끄적여 본 개념
코드 정도인데, 현재 서버와 연동되어 작동은 가능하지만 이렇게 구현하는
것은 효율이 좋지 않다는 점 때문에 실제로 사용할 수는 없고 개선시켜야됨.
//////////////////////////////////////////////////////////////////////
// Pseudo Codes for communications with external debugger controller.
//////////////////////////////////////////////////////////////////////

extern bool is_Listen;
extern bool is_StartDebugger;
extern LPBYTE pMemoryMap;

///////////////////////////////////////
// InprocServer
///////////////////////////////////////
DWORD WINAPI InprocServer(LPVOID lpARG)
{
    LRESULT hr = S_OK;
    HANDLE  hConn = (HANDLE)lpARG;

    DWORD retCode;
    DWORD bytesRead;
    DWORD lastError;

	IMATINIB_DATA packet;

    while (is_StartDebugger)
    {
		memset(&packet, 0, sizeof(_IMATINIB_DATA));

		retCode = ReadFile(hConn, &packet, sizeof(_IMATINIB_DATA), &bytesRead, NULL);
		if (!retCode)
		{
			lastError = GetLastError();
			switch (lastError)
			{
			  case ERROR_BROKEN_PIPE:
			  default:
				is_StartDebugger = FALSE;
				break;
			}
		}

        if (retCode)
        {
 			if(bytesRead > 0)
			{
				switch (packet.dwState)
				{
					case IMATINIB_GET_REG:
						SendToDebugger(DBG_CONTROL_DUMP, (const char *)&dbg, sizeof(_DBGDATA));
						break;

					case IMATINIB_GET_IMM:
						break;

					case IMATINIB_GET_DWORD:
						break;

					case IMATINIB_GET_STRING:
						break;

                    case IMATINIB_GET_DUMP:
					{
                        DWORD addr = GetBaseAddress(MODULE_NAME);
                        DWORD size = GetImageSize(MODULE_NAME);

                        SendToDebugger(DBG_CONTROL_NORMAL, (char *)addr, size);
						break;
					}

                    case IMATINIB_GET_GETFINGERPRINT:
                    {
						DNA_FingerPrintList(0, 0, dna->DNA.Imatinib);
                        packet.Address = dna->DNA.Imatinib.AddressFound;
                        packet.Offset = dna->DNA.Imatinib.PatchSize;
                        break;
                    }

                    case IMATINIB_GET_INTERCEPT:
                    {
                        if (dna->DNA.Imatinib.AddressFound)
                        {
                            DNA_Injector(INST_CALL, (DWORD)&Imatinib_STUB, dna->DNA.Imatinib);
                        }
                        break;
                    }

					case IMATINIB_GET_STOP:
						is_StartDebugger = FALSE;
						break;
				}
			}
        }

        Sleep(1);
    }

    FlushFileBuffers(hConn);
    CloseHandle(hConn);
    DisconnectNamedPipe(hConn);

    return hr;
}

///////////////////////////////////////////////////////////////////////////
// SendToDebugger
///////////////////////////////////////////////////////////////////////////
BOOL WINAPI SendToDebugger(DWORD CtrlMode, const char *Data, DWORD dwBytes)
{
    LRESULT bSend;
    PVOID lpData;
    
    COPYDATASTRUCT cpStructData;

    cpStructData.dwData = CtrlMode;
    cpStructData.cbData = dwBytes;

    __try {

        lpData = LocalAlloc(LPTR, cpStructData.cbData);
    
        DWORD oldSourceProt = 0;
        VirtualProtect((void*)Data, cpStructData.cbData, PAGE_EXECUTE_READWRITE, &oldSourceProt);
          memcpy((void *)lpData, (const void*)Data, (size_t)cpStructData.cbData);
        VirtualProtect((void*)Data, cpStructData.cbData, oldSourceProt, &oldSourceProt);

        cpStructData.lpData = (void *)lpData;

		if (dna->hProcess)
		{
			switch(CtrlMode)
			{
				case DBG_CONTROL_START:

					if (!is_Listen)
					{
						is_Listen = TRUE;
						is_StartDebugger = TRUE;

                        // cpStructData.dwData = DBG_CONTROL_START;
                        // bSend = ::SendMessage(psp->hProcess, WM_COPYDATA, (WPARAM)psp->hProcess, (LPARAM)&cpStructData);

                        // char PIPE_NAME[] = "\\\\.\\PIPE\\IDAIMATINIB";

                        // HANDLE PIPE_HANDLE = CreateFile(PIPE_NAME, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                        // if (PIPE_HANDLE != INVALID_HANDLE_VALUE)
                        // {
                               // DWORD dwThread;
                               // CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)InprocServer, (LPVOID)PIPE_HANDLE, NULL, &dwThread);
                        // }
					}

					break;

				case DBG_CONTROL_STOP:

					if (is_Listen)
					{
						is_Listen = FALSE;
						is_StartDebugger = FALSE;

						cpStructData.dwData = DBG_CONTROL_STOP;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				case DBG_CONTROL_NORMAL:

					if (is_Listen)
					{
						cpStructData.dwData = DBG_CONTROL_NORMAL;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				case DBG_CONTROL_DUMP:

					if (is_Listen)
					{
						cpStructData.dwData = DBG_CONTROL_DUMP;
						bSend = ::SendNotifyMessage(dna->hProcess, WM_COPYDATA, (WPARAM)dna->hProcess, (LPARAM)&cpStructData);
					}

					break;

				default: break;
			}
		}
    }
    __finally {
        LocalFree(lpData);
    }

    return(bSend);
}

///////////////////////////////////////////////////
// CheckTimeOver
///////////////////////////////////////////////////
BOOL CheckTimeOver(time_t tTime, DWORD dwCheckTime)
{
	time_t tCurrentTime = time(0);

	if(tCurrentTime >= tTime)
	{
		return ((tCurrentTime-tTime) >= dwCheckTime) ? TRUE : FALSE;
	}

	return ((tTime-((((time_t)(-1))-tTime)+tCurrentTime)) >= dwCheckTime) ? TRUE : FALSE;
}

////////////////////////////////////////
// DBG_CONNECT
////////////////////////////////////////
DWORD WINAPI DBG_CONNECT(LPVOID lpParam)
{
    static time_t tCheckT = time(0);

    while (TRUE)
    {
        if(CheckTimeOver(tCheckT, 1))
        {
			dna->hProcess = FindWindowEx(NULL, NULL, "TFormImatinibCenter", "IDAImatinib");
            if (dna->hProcess)
            {
				CString CtrlMsg = "IMATINIB INIT..";
				SendToDebugger(DBG_CONTROL_START, CtrlMsg, CtrlMsg.GetLength());
            }
            else
            {
                is_Listen = FALSE;
				is_StartDebugger = FALSE;
            }

            tCheckT = time(0);
        }

        Sleep(1);
    }

    return 0;
}

/////////////////////////////////////////////////////////////////
// GetRemoteProcAddress
/////////////////////////////////////////////////////////////////
PVOID GetRemoteProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    PVOID pFunctionAddress = NULL;
    
    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
        PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG) ModuleBase + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
        ULONG addr = expdir->VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((ULONG)ModuleBase + addr);
        PULONG functions = (PULONG)((ULONG)ModuleBase + exports->AddressOfFunctions);
        PSHORT ordinals  = (PSHORT)((ULONG)ModuleBase + exports->AddressOfNameOrdinals);
        PULONG names     = (PULONG)((ULONG)ModuleBase + exports->AddressOfNames);
        ULONG  max_name  = exports->NumberOfNames;
        ULONG  max_func  = exports->NumberOfFunctions;

        ULONG i;

        for (i = 0; i < max_name; i++)
        {
            ULONG ord = ordinals[i];

            if(i >= max_name || ord >= max_func) {
                return NULL;
            }

            if (functions[ord] < addr || functions[ord] >= addr)
            {
                if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
                {
                    // pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
					pFunctionAddress = (PVOID)functions[ord];
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        pFunctionAddress = NULL;
    }

    return pFunctionAddress;
}

/////////////////////////////////////////////////////////////////
// GetRemoteCallBack
/////////////////////////////////////////////////////////////////
PVOID GetRemoteCallBack(HANDLE process_handle,
                        DWORD lpProcessId,
                        LPCSTR lpBuffer,
                        LPCSTR lpModule,
                        PCHAR pFunctionName)
{
	PVOID pFunctionAddress = NULL;

    HANDLE hSnapshot;
    MODULEENTRY32 me32;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lpProcessId);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &me32))
        {
            do
            {
				if (!stricmp(me32.szModule, lpModule))
				{
					__try {
						lpBuffer = (LPCSTR)malloc(me32.modBaseSize);
						ReadProcessMemory(process_handle, (void *)me32.modBaseAddr, (PVOID)lpBuffer, me32.modBaseSize, 0);
						pFunctionAddress = (PVOID)((DWORD)GetRemoteProcAddress((PVOID)lpBuffer, pFunctionName) + (DWORD)me32.modBaseAddr);
					}
					__finally {
						free((PVOID)lpBuffer);
					}
					
					break;
				}
            }
            while (Module32Next(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
    }
    return pFunctionAddress;
}

///////////////////////////////////
// Imatinib
///////////////////////////////////
void __fastcall Imatinib(char *ecx)
{
	PDBGDATA mem = (PDBGDATA)pMemoryMap;
	memcpy(mem, &dbg, sizeof(_DBGDATA));

	MEMORY_BASIC_INFORMATION MemInfo = {0,};

	SIZE_T nResult = 0;

	nResult = VirtualQuery((const void *)mem->reg.eax, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.eax, (const void *)mem->reg.eax, 1024);
	else
		memset(mem->mem.eax, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.ebx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ebx, (const void *)mem->reg.ebx, 1024);
	else
		memset(mem->mem.ebx, 0x00, 1024);
	
	nResult = VirtualQuery((const void *)mem->reg.ecx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ecx, (const void *)mem->reg.ecx, 1024);
	else
		memset(mem->mem.ecx, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.edx, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.edx, (const void *)mem->reg.edx, 1024);
	else
		memset(mem->mem.edx, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.esi, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.esi, (const void *)mem->reg.esi, 1024);
	else
		memset(mem->mem.esi, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.edi, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.edi, (const void *)mem->reg.edi, 1024);
	else
		memset(mem->mem.edi, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.ebp, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.ebp, (const void *)mem->reg.ebp, 1024);
	else
		memset(mem->mem.ebp, 0x00, 1024);

	nResult = VirtualQuery((const void *)mem->reg.esp, &MemInfo, sizeof(MemInfo));

	if (MemInfo.State & MEM_COMMIT)
		memcpy(mem->mem.esp, (const void *)mem->reg.esp, 1024);
	else
		memset(mem->mem.esp, 0x00, 1024);

	DWORD dwProcessId;
	GetWindowThreadProcessId(dna->hProcess, &dwProcessId);
	HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (process_handle)
	{
        LPCSTR lpBuffer = NULL;
        LPTHREAD_START_ROUTINE RemoteCallBack = (LPTHREAD_START_ROUTINE)GetRemoteCallBack(process_handle,
                                                                                          dwProcessId,
                                                                                          lpBuffer,
                                                                                          "IDAServ.exe",
                                                                                          "IoCompleteRemoteCallBackForSharedMemory");
		if (RemoteCallBack)
		{
			DWORD thread_id = 0;
			HANDLE thread = CreateRemoteThread(process_handle, NULL, 0, RemoteCallBack, NULL, 0, &thread_id);

			if (thread != NULL && thread_id != 0) {
				WaitForSingleObject(thread, INFINITE);
				DWORD exit_code = 0;
				GetExitCodeThread(thread, &exit_code);
			}
		}
	}
}
*/
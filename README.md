# Imatinib
Imatinib is a instrumentation tool that uses the only inline patch hooking.<br>
<br>
The build has been tested with Visual Studio 2017.<br>
We plan to provide it soon as x64dbg plugin.<br>
(It no longer supports Visual Studio 6.0.)<br>
<br>
# CRISPR
The name of this project has been changed to "CRISPR" from "Imatinib".<br>
<br>
- The CRISPR(pronounced "crisper") is an acronym for "Code Reroute In Self Program Runtime"<br>
  in this project only.<br>
<br>
- The original version of "CRISPR" (pronounced "crisper") stands for Clustered Regularly<br>
  Interspaced Short Palindromic Repeats, which are the hallmark of a baacterial defense system<br>
  which forms the basis for the popular CRISPR-Cas9 genome editing technology also known as<br>
  "Genetic Scissors".<br>
<br>
- Do not misunderstand the "CRISPR" term.<br>
<br>
- https://www.broadinstitute.org/what-broad/areas-focus/project-spotlight/crispr<br>
  (This CRISPR does not have anything to do with this project.)<br>
<br>

# Roadmap
<pre>
----------------
Code Name CRISPR
----------------
CRISPR/Bin-x86
CRISPR/Bin-x64
CRISPR/Bin-ARM32
CRISPR/Bin-ARM64
----------------
</pre>
<br>

# Build Explanation
This tool is designed to be compiled in VC++ 6.0 by fixing header support issues.<br>
Capstone does not support VC++ 6.0, and I modified some parts of Capstone to compile<br>
my project in VC++ 6.0.<br>
(i.e. removing stdint.h and modifying "long long" type to __int64 ...)<br>
If you want to use the MSVC 2010 or 2013, say higher version of MSVC, you should restore<br>
the changed parts of Capstone and WTL to the original or higher version.<br>
<br>
# VC++ 6.0 Build
Install VC++ 6.0 with Service Pack 6.0 and the platform SDK 2003 R2.<br>
And take msvcp file if you are using Windows 8.x.<br>
<br>
I can solves that the VC++ 6.0 is not operating on Windows 8.x.<p>
- Please run by copying the msvcp.exe or msvcs.exe files in the following directory<p>
- C:\Program Files (x86)\Microsoft Visual Studio\Common\MSDev98\Bin<p>
<br>
Please start the msvcp.exe or msvcs.exe instead of msdev.exe.<br>
<br>
Open the VC, choose the following menu.<br>
- Tools->Options->Directories->Include Files.<br>
Please set in the order as follows:<br>
C:\PROGRAM FILES (X86)\MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2\INCLUDE<br>
C:\PROGRAM FILES (X86)\MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2\INCLUDE\MFC<br>
C:\PROGRAM FILES (X86)\MICROSOFT PLATFORM SDK FOR WINDOWS SERVER 2003 R2\INCLUDE\ATL<br>
C:\Program Files (x86)\Microsoft Visual Studio\VC98\INCLUDE<br>
C:\Program Files (x86)\Microsoft Visual Studio\VC98\MFC\INCLUDE<br>
C:\Program Files (x86)\Microsoft Visual Studio\VC98\ATL\INCLUDE<br>
<br>
Compile and run.<br>
<br>
I'll push MSVC 2010 or 2013 edition in the near future on github.<br>
The work is much easier. There is no need to us to particularly change.<br>
I prefer the VC++ 6.0 in 32-bit hooking Because of the dependency problem..<br>

# Mandatory use (Required to you)
It is first seen by opening the file IniFileHandlers.cpp.<br>
The need to focus on the next part<br>
- strcpy(DNA_Sequences[0], "wwlib.dll,5,0,3BC38946207473663918746E50FF15xxxxxxxx50FF7620E8xxxxxxxx3BC38985xxxxxxxx745468000200008D7E0C5756FFB5xxxxxxxx50FF15xxxxxxxx85C07439");<br>
- This strcpy part has to be changed because you do not need.<br>
- For example, look at the following:<br>
<pre>
.text:00401010                         _main_0         proc near               ; CODE XREF: _mainj<br>
.text:00401010<br>
.text:00401010                         var_40          = byte ptr -40h<br>
.text:00401010<br>
.text:00401010 55                                      push    ebp<br>
.text:00401011 8B EC                                   mov     ebp, esp<br>
.text:00401013 83 EC 40                                sub     esp, 40h<br>
.text:00401016 53                                      push    ebx<br>
.text:00401017 56                                      push    esi<br>
.text:00401018 57                                      push    edi<br>
.text:00401019 8D 7D C0                                lea     edi, [ebp+var_40]<br>
.text:0040101C B9 10 00 00 00                          mov     ecx, 10h<br>
.text:00401021 B8 CC CC CC CC                          mov     eax, 0CCCCCCCCh<br>
.text:00401026 F3 AB                                   rep stosd<br>
.text:00401028 68 1C 20 42 00                          push    offset aHelloWorld ; "Hello World!\n"<br>
.text:0040102D E8 2E 00 00 00                          call    _printf<br>
</pre>
<br>
- Binary String (or DNA Sequences)<br>
55 8B EC 83 EC 40 53 56 57 8D 7D C0 B9 10 00 00 00 B8 CC CC CC CC F3 AB 68 xx xx xx xx E8 xx xx xx xx<br>
558BEC83EC405356578D7DC0B910000000B8CCCCCCCCF3AB68xxxxxxxxE8xxxxxxxx<br>
You already know that there is a need for masking of 0x68 and 0xE8 instructions.<br>
(These instructions, the value of the operand is changed for relocation.)<br>
If you want to trace from the main entry point, it may be specified as follows.<br>
- strcpy(DNA_Sequences[0], "HelloWorld.exe,6,0,558BEC83EC405356578D7DC0B910000000B8CCCCCCCCF3AB68xxxxxxxxE8xxxxxxxx");<br>
- strcpy's 0 is the number of offset value when searching sequence.<br>
- strcpy's 6 is the push ebp and mov ebp, esp and sub esp, 40h instructions.<br>
- This is because it has the first 5 bytes when all instruction was added.<br>
- strcpy's HelloWorld.exe is the name of the binary target for the instrument. (or DLL name)<br>
- You are in the DLL, it may be used as follows.<br>
- strcpy(DNA_Sequences[0], "HelloWorld.dll,5,0,!HelloWorldFunc); // HelloWorldFunc is a export function name.<br>
- strcpy(DNA_Sequences[0], "HelloWorld.dll,5,0,!10005); // 10005 is a ordinal number.<br>
- strcpy(DNA_Sequences[0], "HelloWorld.dll,5,0,#0x10004321); // #0x10004321 is a address.<br>
- Please use to your choice, It is both common EXE and DLL binaries.<br>
To run this DLL tool, you are required loader.<br>
There is a choice of setdll.exe and withdll.exe.<br>
I personally recommend setdll.exe.<br>
pintool requires always loader.<br>
This tool, using the setdll.exe, there is no need loader.<br>
If you want to instrument a huge program, After copying the winmm.dll to the target program directory,<br>
Please insert the tool in the winmm.dll using the setdll.exe.<br>
This method is efficient to reversing massive program.<br>

# ETC
In addition, IMATINIB had been further added to be able to easily use the detours library.<br>
However, I had been to disable the function.<br>
Detours Library is a simply utility functions.<br>
<p>
Is it enough in this degree of explanation?<br>
When the description is insufficient, please tell me.<br>
<br>
# TEST VIDEO
https://youtu.be/aDTfpvD5FoI
<br>
Thank you..<br>
<br>
by AmesianX.. ^^<br>

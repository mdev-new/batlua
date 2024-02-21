#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <string.h>

#define NOMANGLE extern "C"
#define EXPORT __declspec(dllexport)

DWORD CALLBACK ThreadMain(void *data) {

	char *content = NULL;

	{
		DWORD dwRead = 0;
		char *filename = (char *)data;
		HANDLE hFile = CreateFile(filename);

		ReadFile(hFile, content, &dwRead);
		CloseHandle(hFile);
	}

	// init
	lua_State * L = lua_open();
	luaL_openlibs(L);

	// todo bind lua vars to batch vars
	// todo bind native functions
	// atleast those that are being used inside of getinput
	// getting/setting console font
	// getkeystate/asyncgetkeystate
	// getsystemmetrics
	// getenv/setenv <- those will be bound to batch vars
	// readconsoleinput, getstdhandle
	// xinput interface
	// reading/writing files
	// get/setconsolemode, setconsolewindowinfo, setconsolescreenbuffersize
	// sleep
	// setwindowlong, drawmenubar
	// setwindowshookex, unhookwindowshookex, callnexthookex
	// threads
	// getmonitorinfo, monitorfromwindow, getwindowrect

	// execute
	int load_stat = luaL_loadbuffer(L, content, strlen(content), content);
	lua_pcall(L, 0, 0, 0);

	// cleanup
	lua_close(L);

	return 0;
}

DWORD getppid(char *target) {
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot;
	DWORD ppid = -1, pid = GetCurrentProcessId();

	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		if (Process32First(hSnapshot, &pe32)) {
			do {
				// todo target is untested
				if (
					(
						target != NULL &&
						pe32.th32ProcessID == pid &&
						strcmp(target, pe32.szExeFile)
					) || (
						target == NULL &&
						pe32.th32ProcessID == pid
					)
				) {
					ppid = pe32.th32ParentProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
	}

	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return ppid;
}

NOMANGLE EXPORT BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved) {

	// Check if not running inside rundll32
	// since rundll fires both the specified entry point and DllMain
	char name[MAX_PATH];
	GetModuleFileName(NULL, name, sizeof(name));
	int lastTvelveChars = (strlen(name) - 12);
	if(lastTvelveChars >= 0) {
		if(strcmp("rundll32.exe", name + lastTvelveChars) == 0) {
			return TRUE;
		}
	}

	char *luafilename[MAX_PATH] = {0};
	GetEnvironmentVariable("luafile", luafilename, luafilename);

	if (dwReason == DLL_PROCESS_ATTACH) {
		CreateThread(
			NULL,
			0,
			ThreadMain,
			/*NULL*/ luafilename, /* TODO - here we need to pass the file name */
			0,
			NULL
		);
	}/* else if(dwReason == DLL_PROCESS_DETACH) {

	}*/

	return TRUE;
}

NOMANGLE EXPORT void CALLBACK start(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
	char filename[MAX_PATH];
	HMODULE hDll = NULL;

	GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&getppid,
		&hDll
	);

	if (!GetModuleFileName(hDll, filename, MAX_PATH)) return;

	int pid = getppid("cmd.exe");
	if(pid != -1) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

		int filename_len = strlen(filename);

		LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, filename_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProcess, lpBaseAddress, filename, filename_len, NULL);

		void *loadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

		LPTHREAD_START_ROUTINE startAddr = (LPTHREAD_START_ROUTINE)loadLibrary;
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, startAddr, lpBaseAddress, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
	return;
}

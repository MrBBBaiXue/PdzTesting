// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <easyhook.h>
#include <cstdio>

long newRa3Ftell(FILE* file);

auto vc2005 = GetModuleHandleW(L"MSVCR80.dll");
auto ra3Ftell = reinterpret_cast<decltype(&ftell)>(GetProcAddress(vc2005, "ftell"));
auto ra3Fflush = reinterpret_cast<decltype(&ftell)>(GetProcAddress(vc2005, "fflush"));

void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* remoteEntryInfo)
{
	vc2005 = GetModuleHandleW(L"MSVCR80.dll");
	if (vc2005 == NULL)
	{
		MessageBox(NULL, L"Module vc2005 not found!" , L"Error" , MB_ICONEXCLAMATION | MB_OK);
		return;
	}	
	if (ra3Ftell == NULL)
	{
		MessageBox(NULL, L"Module ra3Ftell not found!", L"Error", MB_ICONEXCLAMATION | MB_OK);
		return;
	}
	if (ra3Fflush == NULL)
	{
		MessageBox(NULL, L"Module ra3Fflush not found!", L"Error", MB_ICONEXCLAMATION | MB_OK);
		return;
	}
	//hooking...
	const auto processHeap = GetProcessHeap();
	if (processHeap == nullptr)
	{
		return;
	}

	const auto ftellHook = static_cast<HOOK_TRACE_INFO*>(HeapAlloc(processHeap, HEAP_ZERO_MEMORY, sizeof(HOOK_TRACE_INFO)));

	const auto hookResult = LhInstallHook(ra3Ftell, newRa3Ftell, nullptr, ftellHook);
	if (FAILED(hookResult))
	{
		return;
	}

	auto placeholder = static_cast<ULONG>(0);
	LhSetExclusiveACL(&placeholder, 1, ftellHook);
}

long newRa3Ftell(FILE* file)
{
	ra3Fflush(file);
	return ra3Ftell(file);
}


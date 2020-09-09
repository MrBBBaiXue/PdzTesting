#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <easyhook.h>
#include <cstddef>

#ifdef DLL_EXPORTS
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif

extern "C"
{
    void DLL_API __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* const inRemoteInfo) noexcept;
    bool DLL_API injectDll
    (
        ULONG const targetProcessId, 
        void const* const data, 
        std::size_t const size, 
        char* const messageBuffer, 
        std::size_t* const bufferSize
    ) noexcept;
}

#include "pch.h"
#include "FunctionFinder.hpp"
#include <Psapi.h>
#include <execution>

#pragma comment(lib, "PsApi.lib")

FunctionFinder::FunctionFinder()
{
    auto const gameModule = GetModuleHandleW(nullptr);
    auto moduleInfo = MODULEINFO{};
    if (!GetModuleInformation(GetCurrentProcess(), gameModule, &moduleInfo, sizeof(moduleInfo)))
    {
        throw std::runtime_error{ "cannot get module information" };
    }

    m_gameModuleBegin = static_cast<std::uint32_t*>(moduleInfo.lpBaseOfDll);
    if (reinterpret_cast<std::uintptr_t>(m_gameModuleBegin) % sizeof(std::uint32_t) != 0)
    {
        throw std::runtime_error{ "process module base is not aligned" };
    }
    m_gameModuleEnd = m_gameModuleBegin + moduleInfo.SizeOfImage / sizeof(std::uint32_t);
}

void* FunctionFinder::find(std::uint32_t const* markBegin, std::uint32_t const* markEnd) const
{
    auto const found = std::search
    (
        std::execution::par_unseq, 
        m_gameModuleBegin, 
        m_gameModuleEnd, 
        markBegin, 
        markEnd
    );
    if (found == m_gameModuleEnd)
    {
        throw std::runtime_error{ "function not found" };
    }
    auto const next = std::search
    (
        std::execution::par_unseq, 
        found + 1, 
        m_gameModuleEnd, 
        markBegin, 
        markEnd
    );
    if (next != m_gameModuleEnd)
    {
        auto message = std::ostringstream{};
        message << "found multiple possible alternatives: "
            << found << " and " << next << std::endl
            << "Dumping contents. First: " << std::endl;
        auto const offset = markEnd - markBegin;
        auto const p1 = reinterpret_cast<std::byte*>(found);
        for (int i = 0; i < 28; ++i)
        {
            message << std::hex << static_cast<unsigned>(p1[i]) << ' ';
        }
        message << std::endl << "Second: " << std::endl;
        auto const p2 = reinterpret_cast<std::byte*>(next);
        for (int i = 0; i < 28; ++i)
        {
            message << std::hex << static_cast<unsigned>(p2[i]) << ' ';
        }
        message << std::endl;
        throw std::runtime_error{ message.str() };
    }

    return found;
}

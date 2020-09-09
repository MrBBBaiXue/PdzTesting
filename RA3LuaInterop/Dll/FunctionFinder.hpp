#pragma once
#include "pch.h"

class FunctionFinder
{
private:
    std::uint32_t* m_gameModuleBegin;
    std::uint32_t* m_gameModuleEnd;
public:
    FunctionFinder();
    void* find
    (
        std::uint32_t const* markBegin, 
        std::uint32_t const* markEnd
    ) const;
};


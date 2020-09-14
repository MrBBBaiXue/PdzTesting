// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Dll/framework.h>

#include <easyhook/easyhook.h>
#include <boost/locale.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <Windows.h>
#include <TlHelp32.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <thread>

bool inject();

struct FunctionData
{
    std::array<std::uint32_t, 8> data;
    std::array<char, 16> name = { 0 };
    int offset;
};

int main()
{
    try
    {
        // Set console code page to UTF-8 so console known how to interpret string data
        SetConsoleOutputCP(CP_UTF8);
        // Enable buffering to prevent VS from chopping up UTF-8 byte sequences
        setvbuf(stdout, nullptr, _IOFBF, 1000);

        std::cout << "Will look for ra3_1.12.game..." << std::endl;
        while (true)
        {
            auto injected = inject();
            if (injected)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds{ 1 });
        }
        std::cout << "Completed. Press Enter to exit." << std::endl;
        std::cin.get();
        return 0;
    }
    catch (std::exception const& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "Unknown exception" << std::endl;
    }
    std::cin.get();
    return 1;
}

struct HandleCloser
{
    using pointer = HANDLE;
    void operator()(pointer const handle) const noexcept
    {
        CloseHandle(handle);
    }
};
using UniqueHandle = std::unique_ptr<HANDLE, HandleCloser>;

bool inject()
{
    auto snapshot = UniqueHandle{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
    if (snapshot.get() == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error{ "failed to create snapshot" };
    }

    auto found = false;

    auto entry = PROCESSENTRY32{};
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot.get(), &entry) == TRUE)
    {
        while (Process32Next(snapshot.get(), &entry) == TRUE)
        {
            auto upperCase = std::wstring{ entry.szExeFile };
            std::transform(begin(upperCase), end(upperCase), begin(upperCase), std::toupper);
            if (upperCase.ends_with(L"RA3_1.12.GAME"))
            {
                std::cout << "Found "
                    << boost::locale::conv::utf_to_utf<char>(entry.szExeFile)
                    << " with pid " << entry.th32ProcessID << std::endl;
                std::cout << "Trying to inject..." << std::endl;
                auto message = std::string{};
                message.resize(256);
                auto size = message.size();
                auto const injected = injectDll
                (
                    entry.th32ProcessID, 
                    nullptr, 
                    0, 
                    message.data(), 
                    &size
                );
                message.resize(size);
                std::cout << "Injection result: " << message << std::endl;
                if (not injected)
                {
                    std::cout << "Failed." << std::endl;
                }
                found = true;
            }
        }
    }
    return found;
}

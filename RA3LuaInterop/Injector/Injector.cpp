// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Dll/framework.h>

#include <easyhook.h>
#include <boost/locale.hpp>

#include <Windows.h>
#include <TlHelp32.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <thread>

extern "C" {
#include <lua-4.0.1/include/lua.h>
}
#pragma comment(lib, "legacy_stdio_definitions.lib")
extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }
#pragma comment(lib, "../lua-4.0.1/Debug/lua4.lib")

bool inject();
void printLuaFunction(std::string_view const name, void const* address);
#define PRINT_LUA(name) printLuaFunction(#name, name)

struct FunctionData
{
    std::array<std::uint32_t, 8> data;
    std::array<char, 16> name = { 0 };
    int offset;
};
auto checked = std::vector<FunctionData>{};

int main()
{
    try
    {
        // Set console code page to UTF-8 so console known how to interpret string data
        SetConsoleOutputCP(CP_UTF8);
        // Enable buffering to prevent VS from chopping up UTF-8 byte sequences
        setvbuf(stdout, nullptr, _IOFBF, 1000);

        /*
        ** state manipulation
        */
        PRINT_LUA(lua_open);
        PRINT_LUA(lua_close);


        /*
        ** basic stack manipulation
        */
        PRINT_LUA(lua_gettop);
        PRINT_LUA(lua_settop);
        PRINT_LUA(lua_pushvalue);
        PRINT_LUA(lua_remove);
        PRINT_LUA(lua_insert);
        PRINT_LUA(lua_stackspace);


        /*
        ** access functions (stack -> C)
        */

        PRINT_LUA(lua_type);
        PRINT_LUA(lua_typename);
        PRINT_LUA(lua_isnumber);
        PRINT_LUA(lua_isstring);
        PRINT_LUA(lua_iscfunction);
        PRINT_LUA(lua_tag);

        PRINT_LUA(lua_equal);
        PRINT_LUA(lua_lessthan);

        PRINT_LUA(lua_tonumber);
        PRINT_LUA(lua_tostring);
        PRINT_LUA(lua_strlen);
        PRINT_LUA(lua_tocfunction);
        PRINT_LUA(lua_touserdata);
        PRINT_LUA(lua_topointer);


        /*
        ** push functions (C -> stack)
        */
        PRINT_LUA(lua_pushnil);
        PRINT_LUA(lua_pushnumber);
        PRINT_LUA(lua_pushlstring);
        PRINT_LUA(lua_pushstring);
        PRINT_LUA(lua_pushcclosure);
        PRINT_LUA(lua_pushusertag);


        /*
        ** get functions (Lua -> stack)
        */
        PRINT_LUA(lua_getglobal);
        PRINT_LUA(lua_gettable);
        PRINT_LUA(lua_rawget);
        PRINT_LUA(lua_rawgeti);
        PRINT_LUA(lua_getglobals);
        PRINT_LUA(lua_gettagmethod);
        PRINT_LUA(lua_getref);
        PRINT_LUA(lua_newtable);


        /*
        ** set functions (stack -> Lua)
        */
        PRINT_LUA(lua_setglobal);
        PRINT_LUA(lua_settable);
        PRINT_LUA(lua_rawset);
        PRINT_LUA(lua_rawseti);
        PRINT_LUA(lua_setglobals);
        PRINT_LUA(lua_settagmethod);
        PRINT_LUA(lua_ref);


        /*
        ** "do" functions (run Lua code)
        */
        PRINT_LUA(lua_call);
        PRINT_LUA(lua_rawcall);
        PRINT_LUA(lua_dofile);
        PRINT_LUA(lua_dostring);
        PRINT_LUA(lua_dobuffer);

        /*
        ** Garbage-collection functions
        */
        PRINT_LUA(lua_getgcthreshold);
        PRINT_LUA(lua_getgccount);
        PRINT_LUA(lua_setgcthreshold);

        /*
        ** miscellaneous functions
        */
        PRINT_LUA(lua_newtag);
        PRINT_LUA(lua_copytagmethods);
        PRINT_LUA(lua_settag);

        PRINT_LUA(lua_error);

        PRINT_LUA(lua_unref);

        PRINT_LUA(lua_next);
        PRINT_LUA(lua_getn);

        PRINT_LUA(lua_concat);

        PRINT_LUA(lua_newuserdata);

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
                    checked.data(), 
                    checked.size() * sizeof(*checked.data()), 
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

void printLuaFunction(std::string_view const name, void const* address)
{
    
    auto const function = static_cast<std::byte const*>(address);
    auto needAttention = false;
    auto output = std::ostringstream{};
    for (int i = 0; i < 32; ++i)
    {
        output << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<unsigned>(function[i]) << ' ';
        auto const attention = std::string_view{ "\xC3\xCB\xC2\xCA\xCC" };
        if (attention.find(static_cast<char>(function[i])) != attention.npos)
        {
            needAttention = true;
        }
    }
    
    if (needAttention)
    {
        std::cout << "Excluded " << name << " because too short " << std::endl;
    }
    else
    {
        auto const offset = (static_cast<std::byte const*>(address) - reinterpret_cast<std::byte const*>(&lua_setglobal));
        std::cout << "offset to lua_setglobal: " << offset << std::endl;
        auto& that = checked.emplace_back();
        std::copy_n
        (
            static_cast<std::byte const*>(address),
            32,
            reinterpret_cast<std::byte*>(that.data.data())
        );
        std::copy_n(begin(name), (std::min<std::size_t>)(name.size(), 15), begin(that.name));
        that.offset = offset;
    }
}

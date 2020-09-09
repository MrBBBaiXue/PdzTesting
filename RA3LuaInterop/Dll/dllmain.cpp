// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "FunctionFinder.hpp"
#include <fstream>
#include <mutex>
extern "C"
{
#include <Lua/include/lua.h>
}

extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }
#pragma comment(lib, "legacy_stdio_definitions.lib")
#pragma comment(lib, "../lua-4.0.1/Release/lua4.lib")
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void installHook(void* const original, void* const newFunction);
void __stdcall printLine(char const* const what);
void __stdcall luaSetGlobalHandler(lua_State* const luaState, char const* const name);

void newLuaBindingsSetter();
void newLuaSetGlobal();
auto originalLuaBindingsSetter = static_cast<void*>(nullptr);
auto originalLuaVCClosure = static_cast<void*>(nullptr);
auto originalLuaSetGlobal = static_cast<void*>(nullptr);

auto mutex = std::mutex{};
auto output = std::ofstream{};

auto const startLuaBindingLiteral = "start lua binding";
auto const endLuaBindingLiteral = "end lua binding";

void DLL_API __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* const inRemoteInfo) noexcept
{

    auto const luaBindingsSetter = std::array<std::uint32_t, 6>
    {
        0x83F18B56u, 0x0F00247Eu, 0x0004F385u, 0x00685700u, 0xE8000001u, 0x004C3C18u
    };
    auto const luaVCClosure = std::array<std::uint32_t, 6>
    {
        0x0C24448Bu, 0x24748B56u, 0xFF82E808u, 0x4C8BFFFFu, 0x08890C24u, 0x0C40C766u
    };
    auto const luaSetGlobal = std::array<std::uint32_t, 6>
    {
        0x0824448Bu, 0x24748B56u, 0x3E8B5708u, 0x2DE85650u, 0x5000003Cu, 0xC596E856u
    };
    try
    {
        {
            auto const lock = std::scoped_lock{ mutex };
            auto path = boost::dll::this_line_location()
                .replace_extension(".txt")
                .wstring();
            output.open(path);
            if (not output.is_open())
            {
                throw std::runtime_error{ "Opening " + boost::locale::conv::utf_to_utf<char>(path) + " for writing failed" };
            }
        }

        auto const finder = FunctionFinder{};

        printLine("trying to find lua bindings setter");
        originalLuaBindingsSetter = finder.find
        (
            luaBindingsSetter.data(), 
            luaBindingsSetter.data() + luaBindingsSetter.size()
        );
        printLine("trying to find luaV_Cclosure");
        originalLuaVCClosure = finder.find
        (
            luaVCClosure.data(),
            luaVCClosure.data() + luaVCClosure.size()
        );
        printLine("trying to find lua_setglobal");
        originalLuaSetGlobal = finder.find
        (
            luaSetGlobal.data(),
            luaSetGlobal.data() + luaSetGlobal.size()
        );
        

        printLine("installing ra3 lua setter hook");
        installHook(originalLuaBindingsSetter, newLuaBindingsSetter);
        printLine("installing lua set global hook");
        installHook(originalLuaSetGlobal, newLuaSetGlobal);
        printLine("everything done");
    }
    catch (std::exception const& e)
    {
        MessageBoxA(nullptr, e.what(), nullptr, MB_OK);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    catch (...)
    {
        MessageBoxA(nullptr, "Unknown exception", nullptr, MB_OK);
    }
}

bool DLL_API injectDll
(
    ULONG const targetProcessId, 
    void const* const data, 
    std::size_t const size, 
    char* const messageBuffer, 
    std::size_t* const bufferSize
) noexcept
{
    if (messageBuffer == nullptr || bufferSize == nullptr || *bufferSize < 1)
    {
        return false;
    }

    using boost::locale::conv::utf_to_utf;

    auto selfPath = boost::dll::this_line_location().wstring();
    auto copy = std::vector<char>{};
    copy.resize(size);
    std::copy_n(static_cast<char const*>(data), size, begin(copy));
    auto const result = RhInjectLibrary
    (
        targetProcessId, // target pid
        0, 
        EASYHOOK_INJECT_DEFAULT, 
        selfPath.data(), // path of self
        nullptr, // no x64 dll
        copy.data(), // no custom data
        copy.size()
    );
    if (not NT_SUCCESS(result))
    {
        auto const why = "Inject failed: " + utf_to_utf<char>(RtlGetLastErrorString());
        *bufferSize = (why.size() < *bufferSize)
            ? why.size()
            : *bufferSize - 1;
        std::copy_n(begin(why), *bufferSize, messageBuffer);
        
        return false;
    }
    return true;
}

void installHook(void* const original, void* const newFunction)
{
    using boost::locale::conv::utf_to_utf;

    auto handle = HOOK_TRACE_INFO{};
    auto const result = LhInstallHook(original, newFunction, nullptr, &handle);
    if (not NT_SUCCESS(result))
    {
        auto const why = "InstallHook failed: " + utf_to_utf<char>(RtlGetLastErrorString());
        throw std::runtime_error{ why };
    }
    auto thisThread = ULONG{ 0 };
    auto const aclResult = LhSetExclusiveACL(&thisThread, 1, &handle);
    if (not NT_SUCCESS(result))
    {
        auto const why = "ActivateHook failed: " + utf_to_utf<char>(RtlGetLastErrorString());
        throw std::runtime_error{ why };
    }
}
void __stdcall printLine(char const* const what)
{
    auto const lock = std::scoped_lock{ mutex };
    output << what << std::endl;
}
void __stdcall luaSetGlobalHandler(lua_State* const luaState, char const* const name)
{
    {
        auto const lock = std::scoped_lock{ mutex };
        output << "Setting global " << name << " on lua state " << luaState << std::endl;
    }
    using namespace std::string_view_literals;
    if (name == "GetFrame"sv) // assuming GetFrame will only be initialized once
    {
        auto const messageBox = [](lua_State* L)
        {
            
            auto const numberOfArguments = lua_gettop(L);
            if (numberOfArguments < 1)
            {
                MessageBoxA(nullptr, "No arguments", "From Lua", MB_OK);
                return 0;
            }
            auto const pointer = lua_tostring(L, 1);
            if (pointer == NULL)
            {
                MessageBoxA(nullptr, "Is not string", "From Lua", MB_OK);
                return 0;
            }

            auto const length = lua_strlen(L, 1);
            //static auto yes = true;
            //if (not yes)
            //{
            //    return 0;
            //}
            //if (
            MessageBoxA(nullptr, pointer, "From Lua", MB_YESNO);
                    //!= IDYES)
            //{
            //    yes = false;
            //}
            return 0;
        };
        
        static_cast<decltype(&lua_pushcclosure)>(originalLuaVCClosure)(luaState, messageBox, 0);
        static_cast<decltype(&lua_setglobal)>(originalLuaSetGlobal)(luaState, "MessageBox");
    }
}

__declspec(naked) void newLuaBindingsSetter()
{
    __asm
    {
        push eax;
        push edx;
        push ecx;
        push startLuaBindingLiteral;
        call printLine;
        pop ecx;
        pop edx;
        pop eax;

        call originalLuaBindingsSetter;

        push eax;
        push edx;
        push ecx;
        push endLuaBindingLiteral;
        call printLine;
        pop ecx;
        pop edx;
        pop eax;

        ret;
    }
}

__declspec(naked) void newLuaSetGlobal()
{
    __asm 
    {
        push ebp;
        mov ebp, esp;
        push eax;
        
        push ecx;
        push edx;

        mov eax, [ebp + 12];
        push eax;
        mov eax, [ebp + 8];
        push eax;
        call luaSetGlobalHandler;

        pop edx;
        pop ecx;

        pop eax;
        pop ebp;
        
        jmp originalLuaSetGlobal;
    }
}
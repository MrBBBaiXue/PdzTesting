// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "FunctionFinder.hpp"
#include <fstream>
#include <mutex>
#include <boost/algorithm/string.hpp>
extern "C"
{
#include <Lua/include/lua.h>
#include <iostream>
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

template<typename T>
void installHook(T* const original, T* const newFunction);
void __stdcall printL(char const* const what);
void __stdcall luaSetGlobalHandler(lua_State* const luaState, char const* const name);

void newLuaBindingsSetter();
void newLuaSetGlobal();
auto originalLuaBindingsSetter = static_cast<void*>(nullptr);
auto originalLuaVCClosure = static_cast<void*>(nullptr);
auto originalLuaSetGlobal = static_cast<void*>(nullptr);

auto const showMessage = [](auto&&... args)
{
    auto const message = (std::stringstream{} << ... << args).str();
    MessageBoxA(nullptr, message.c_str(), nullptr, MB_OK);
};

//Edited Hooking functions
long new_ftell(FILE* file);
FILE* new__wfopen(const wchar_t* fileName, const wchar_t* mode);
size_t new_fwrite(const void* buffer, size_t elementSize, size_t elementCount, FILE* file);
int new_fclose(FILE* file);
void AnalyseReplayData(std::string_view const replayData);
int AnalyseCurrentPlayerInLua(std::string_view const replayData, int replaySaver);

auto ra3_ftell = static_cast<decltype(&ftell)>(nullptr);
auto ra3_fflush = static_cast<decltype(&fflush)>(nullptr);
auto ra3__wfopen = static_cast<decltype(&_wfopen)>(nullptr);
auto ra3_fwrite = static_cast<decltype(&fwrite)>(nullptr);
auto ra3_fclose = static_cast<decltype(&fclose)>(nullptr);

auto ra3_mbstowcs = static_cast<decltype(&mbstowcs)>(nullptr);
auto ra3__mbstowcs_l = static_cast<decltype(&_mbstowcs_l)>(nullptr);

FILE* replayFile;
std::string replayData;
//target
std::atomic<int> currentPlayerInLua(-1);
//从 0 到 5 ， 出错为 -1


auto mutex = std::mutex{};
auto output = std::ofstream{};
std::ostream& operator<<(std::ostream& os, std::wstring_view const view)
{
    using boost::locale::conv::utf_to_utf;
    return os << utf_to_utf<char>(view.data(), view.data() + view.size());
}
auto const print = [](auto&&... stuffs)
{
    auto const lock = std::scoped_lock{ mutex };
    (output << ... << stuffs) << std::endl;
};

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

        printL("trying to find lua bindings setter");
        originalLuaBindingsSetter = finder.find
        (
            luaBindingsSetter.data(),
            luaBindingsSetter.data() + luaBindingsSetter.size()
        );
        printL("trying to find luaV_Cclosure");
        originalLuaVCClosure = finder.find
        (
            luaVCClosure.data(),
            luaVCClosure.data() + luaVCClosure.size()
        );
        printL("trying to find lua_setglobal");
        originalLuaSetGlobal = finder.find
        (
            luaSetGlobal.data(),
            luaSetGlobal.data() + luaSetGlobal.size()
        );


        printL("installing ra3 lua setter hook");
        installHook<void>(originalLuaBindingsSetter, newLuaBindingsSetter);
        printL("installing lua set global hook");
        installHook<void>(originalLuaSetGlobal, newLuaSetGlobal);
        printL("installing hook functions....");
        auto const vc2005 = GetModuleHandleW(L"MSVCR80.dll");
        if (vc2005 == NULL)
        {
            printL("HMODULE vc2005 not found!");
            return;
        }
        auto const getVC2005Function = [vc2005](auto* prototype, char const* name)
        {
            auto const result = reinterpret_cast<decltype(prototype)>(GetProcAddress(vc2005, name));
            if (result == nullptr)
            {
                MessageBoxA(nullptr, name, "Failed to get address of", MB_ICONERROR);
                exit(1);
            }
            return result;
        };
#define GET_FROM_VC2005(x) getVC2005Function(static_cast<decltype(&x)>(nullptr), #x)
        ra3_ftell = GET_FROM_VC2005(ftell);
        ra3_fflush = GET_FROM_VC2005(fflush);
        ra3__wfopen = GET_FROM_VC2005(_wfopen);
        ra3_fwrite = GET_FROM_VC2005(fwrite);
        ra3_fclose = GET_FROM_VC2005(fclose);
        // utf8
        ra3_mbstowcs = GET_FROM_VC2005(mbstowcs);
        ra3__mbstowcs_l = GET_FROM_VC2005(_mbstowcs_l);

#undef GET_FROM_VC2005
        //hooking...
        installHook(ra3_ftell, new_ftell);
        installHook(ra3__wfopen, new__wfopen);
        installHook(ra3_fwrite, new_fwrite);
        installHook(ra3_fclose, new_fclose);
        decltype(ra3_mbstowcs) new_ra3mbstowcs = [](wchar_t* dest, char const* src, size_t max)
        {
            auto const result = ra3_mbstowcs(dest, src, max);
            if (result == -1)
            {
                print("mbstowcs - conversion of {", src, "} failed");
            }
            else
            {
                print("mbstowcs - {", src, "} => {", std::wstring_view{ dest, result }, "}");
            }
            return result;
        };
        decltype(ra3__mbstowcs_l) new_ra3mbstowcs_l = [](wchar_t* dest, char const* src, size_t max, _locale_t locale)
        {
            auto const result = ra3__mbstowcs_l(dest, src, max, locale);
            if (result == -1)
            {
                print("_mbstowcs_l - conversion of {", src, "} failed");
            }
            else
            {
                print("_mbstowcs_l - {", src, "} => {", std::wstring_view{ dest, result }, "}");
            }
            return result;
        };
        installHook(ra3_mbstowcs, new_ra3mbstowcs);
        installHook(ra3__mbstowcs_l, new_ra3mbstowcs_l);

        const auto processHeap = GetProcessHeap();
        if (processHeap == nullptr)
        {
            return;
        }
        printL("everything done.");
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

template<typename T>
void installHook(T* const original, T* const newFunction)
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
void __stdcall printL(char const* const what)
{
    print(what);
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
            auto const string = std::string{ pointer, length };
            MessageBoxA(nullptr, string.c_str(), "From Lua", MB_OK);
            return 0;
        };

        auto const getCurrentPlayer = [](lua_State* L)
        {
            auto const value = currentPlayerInLua.load();
            print("lua - getCurrentPlayer called on thread ", GetCurrentThreadId(), ", returning value ", value);
            lua_pushnumber(L, value);
            return 1;
        };

        static_cast<decltype(&lua_pushcclosure)>(originalLuaVCClosure)(luaState, messageBox, 0);
        static_cast<decltype(&lua_setglobal)>(originalLuaSetGlobal)(luaState, "MessageBox");
        static_cast<decltype(&lua_pushcclosure)>(originalLuaVCClosure)(luaState, getCurrentPlayer, 0);
        static_cast<decltype(&lua_setglobal)>(originalLuaSetGlobal)(luaState, "getCurrentPlayer");
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
        call printL;
        pop ecx;
        pop edx;
        pop eax;

        call originalLuaBindingsSetter;

        push eax;
        push edx;
        push ecx;
        push endLuaBindingLiteral;
        call printL;
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

long new_ftell(FILE* file)
{
    if (file == replayFile)
    {
        ra3_fflush(file);
        try
        {
            print("ftell() called on replay file on thread ", GetCurrentThreadId(), ", start analysing replay data...");
            AnalyseReplayData(replayData);
            printL("replay data analyzed, clearing global variable FILE* replayFile and std::string replayData");
            replayFile = nullptr;
            replayData.clear();
        }
        catch (...)
        {
            MessageBoxA(nullptr, "exception", nullptr, MB_OK);
        }
    }
    return ra3_ftell(file);
}

FILE* new__wfopen(const wchar_t* fileName, const wchar_t* mode)
{
    auto const wFileName = std::wstring_view{ fileName };
    auto const wMode = std::wstring_view{ mode };
    auto const file = ra3__wfopen(fileName, mode);
    if (wFileName.ends_with(L".RA3Replay") && wMode == L"wb+")
    {
        print("replay created with name {", wFileName, "} and mode {", wMode, "}, initializing global variables");
        replayFile = file;
        replayData.clear();
        currentPlayerInLua = -1;
    }
    return file;
}

size_t new_fwrite(const void* buffer, size_t elementSize, size_t elementCount, FILE* file)
{
    if (file == replayFile)
    {
        try
        {
            //game is writing replay file , append replayHeader.
            replayData.append(static_cast<const char*>(buffer), elementSize * elementCount);
        }
        catch (...)
        {
            MessageBoxA(nullptr, "failed to append replay data", nullptr, MB_OK);
        }
    }
    return ra3_fwrite(buffer, elementSize, elementCount, file);
}

int new_fclose(FILE* file)
{
    if (file == replayFile)
    {
        printL("replay file is being closed, clearing global variables and currentPlayerInLua");
        replayFile = nullptr;
        replayData.clear();
        currentPlayerInLua = -1;
    }
    return ra3_fclose(file);
}

void AnalyseReplayData(std::string_view const replayData)
{
    print("Analysing replay data {", replayData, "}");
    auto replayDataStartPos = replayData.find(";S=H");
    if (replayDataStartPos == replayData.npos)
    {
        currentPlayerInLua = -1;
        printL("Unable to find player data start pos, -1");
        return;
    }
    auto replayDataEndPos = replayData.find(";", replayDataStartPos + 1);
    if (replayDataEndPos == replayData.npos)
    {
        currentPlayerInLua = -1;
        printL("Unable to find player data end pos, -1");
        return;
    }

    auto replaySaver = replayData.at(replayDataEndPos + 1);
    print("Replay saver is ", +replaySaver);

    auto playersDataStartPos = replayDataStartPos + 3;
    auto playersDataLength = replayDataEndPos - playersDataStartPos;
    auto playersData = replayData.substr(playersDataStartPos, playersDataLength);
    print("Player list obtained: {", playersData, "}");

    currentPlayerInLua = AnalyseCurrentPlayerInLua(playersData, replaySaver);
}

int AnalyseCurrentPlayerInLua(std::string_view const replayData, int replaySaver)
{
    try
    {
        using namespace std::string_view_literals;
        auto constexpr maxPlayers = 6;
        auto constexpr observer = "1"sv;
        auto constexpr commentator = "3"sv;

        std::vector<std::string> players;
        boost::split(players, replayData, boost::is_any_of(":"));
        std::vector<int> playerOrders(players.size());
        playerOrders.resize(players.size(), -1);
        int playerOrder = 0;

        for (size_t n = 0; n < maxPlayers; n++)
        {
            print("checking player slot #", n, " = {", players.at(n), "}");
            if (players.at(n).at(0) == 'H')
            {
                std::vector<std::string> factions;
                boost::split(factions, players.at(n), boost::is_any_of(","));
                if (factions.at(5) == observer || factions.at(5) == commentator)
                {
                    print("player #", n, " {", players.at(n), "} is obs/commentator, skipping");
                    continue;
                }
            }
            else if (players.at(n).at(0) == 'X')
            {
                print("player slot #", n, "is empty (X), skipping");
                continue;
            }

            print("player slot #", n, ", assigning playerOrder = ", playerOrder);
            playerOrders.at(n) = playerOrder;
            playerOrder++;

        }

        print("Current player = playerOrders.at(replaySaver = {", replaySaver, "}) = {", playerOrders.at(replaySaver), "}");
        return playerOrders.at(replaySaver);
    }
    catch (std::exception const& e)
    {
        print("Exception when parsing replay data: ", e.what());
        return -1;
    }
    catch (...)
    {
        print("Unknown exception when parsing replay data");
        return -1;
    }
}
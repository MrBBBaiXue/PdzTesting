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

void installHook(void* const original, void* const newFunction);
void __stdcall printLine(char const* const what);
void __stdcall luaSetGlobalHandler(lua_State* const luaState, char const* const name);

void newLuaBindingsSetter();
void newLuaSetGlobal();
auto originalLuaBindingsSetter = static_cast<void*>(nullptr);
auto originalLuaVCClosure = static_cast<void*>(nullptr);
auto originalLuaSetGlobal = static_cast<void*>(nullptr);

//Edited Hooking functions
HMODULE vc2005;
long new_ftell(FILE* file);
FILE* new__wfopen(const wchar_t* fileName, const wchar_t* mode);
size_t new_fwrite(const void* buffer, size_t elementSize, size_t elementCount, FILE* file);
int new_fclose(FILE* file);
void AnalyseReplayData();
int AnalysePlayers(std::vector<std::string>& players, int pos);
int GetReplaySaver(std::string string);

auto ra3_ftell = static_cast<decltype(&ftell)>(nullptr);
auto ra3_fflush = static_cast<decltype(&fflush)>(nullptr);
auto ra3__wfopen = static_cast<decltype(&_wfopen)>(nullptr);
auto ra3_fwrite = static_cast<decltype(&fwrite)>(nullptr);
auto ra3_fclose = static_cast<decltype(&fclose)>(nullptr);

FILE* replayFile;
std::string replayData;
size_t replayDataSize = 0;
//target
//从 0 到 5，默认(如果尝试获得X或者commentator)为6，出错/重置为0
int currentPlayerInLua = 0;

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
        printLine("installing hook functions....");
        vc2005 = GetModuleHandleW(L"MSVCR80.dll");
        if (vc2005 == NULL)
        {
            printLine("HMODULE vc2005 not found!");
            return;
        }
        //
        ra3_ftell = reinterpret_cast<decltype(&ftell)>(GetProcAddress(vc2005, "ftell"));
        if (ra3_ftell == NULL)
        {
            printLine("ra3_ftell not found!");
            return;
        }
        ra3_fflush = reinterpret_cast<decltype(&fflush)>(GetProcAddress(vc2005, "fflush"));
        if (ra3_fflush == NULL)
        {
            printLine("ra3_fflush not found!");
            return;
        }
        ra3__wfopen = reinterpret_cast<decltype(&_wfopen)>(GetProcAddress(vc2005, "_wfopen"));
        if (ra3__wfopen == NULL)
        {
            printLine("ra3__wfopen not found!");
            return;
        }
        ra3_fwrite = reinterpret_cast<decltype(&fwrite)>(GetProcAddress(vc2005, "fwrite"));
        if (ra3_fwrite == NULL)
        {
            printLine("ra3_fwrite not found!");
            return;
        }
        ra3_fclose = reinterpret_cast<decltype(&fclose)>(GetProcAddress(vc2005, "fclose"));
        if (ra3_fclose == NULL)
        {
            printLine("ra3_fclose not found!");
            return;
        }
        //hooking...
        installHook(ra3_ftell, new_ftell);
        installHook(ra3__wfopen, new__wfopen);
        installHook(ra3_fwrite, new_fwrite);
        installHook(ra3_fclose, new_fclose);
        //
        const auto processHeap = GetProcessHeap();
        if (processHeap == nullptr)
        {
            return;
        }
        printLine("everything done.");
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
            //ToDo : analyse lua script not running...
            //return 0;
        };

        auto const getCurrentPlayer = [](lua_State* L)
        {
            return currentPlayerInLua;
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

long new_ftell(FILE* file)
{
    ra3_fflush(file);
    if (file == replayFile)
    {
        AnalyseReplayData();
    }
    return ra3_ftell(file);
}

FILE* new__wfopen(const wchar_t* fileName, const wchar_t* mode)
{
    std::wstring wFileName = fileName;
    std::wstring wMode = mode;
    if (wFileName.ends_with(L".RA3Replay") && wMode == L"wb+")
    {
        //ToDo : Remove this messageBox after testing.
        //MessageBox(NULL, L"Get RA3Replay opening!", L"Info", MB_ICONEXCLAMATION | MB_OK);
        FILE* file = ra3__wfopen(fileName, mode);
        replayFile = file;
        return file;
    }
    return ra3__wfopen(fileName,mode);
}

size_t new_fwrite(const void* buffer, size_t elementSize, size_t elementCount, FILE* file)
{
    if (file == replayFile)
    {
        //game is writing replay file , expand replayHeader.
        replayDataSize += elementSize * elementCount / sizeof(char);
        replayData.append(reinterpret_cast<const char*>(buffer), elementSize * elementCount / sizeof(char));
    }
    return ra3_fwrite(buffer,elementSize,elementCount,file);
}

int new_fclose(FILE* file)
{
    if (file == replayFile)
    {
        currentPlayerInLua = 0;
    }
    return ra3_fclose(file);
}

void AnalyseReplayData()
{
    replayFile = NULL;
    auto replaySaver = GetReplaySaver(replayData);
    auto playerDataStartPos = replayData.find(";S=") + 3;
    auto playerDataEndPos = replayData.rfind(":;") + 1;
    auto playerData = replayData.substr(playerDataStartPos, playerDataEndPos - playerDataStartPos);
    std::vector<std::string> players;
    boost::split(players, playerData, boost::is_any_of(":"));
    currentPlayerInLua = AnalysePlayers(players, replaySaver);
    //MessageBox for test use.
    std::string test1 = std::to_string(currentPlayerInLua);
    MessageBoxA(NULL, test1.c_str(), "Info", MB_ICONEXCLAMATION | MB_OK);
}

int AnalysePlayers(std::vector<std::string>& players, int pos)
{
    int playerOrders[6] = { 6,6,6,6,6,6 };
    int playerOrder = 0;
    for (size_t n = 0; n < 6; n++)
    {
        if (players[n].substr(0, 1) == "H")
        {
            std::vector<std::string> factions;
            boost::split(factions, players[n], boost::is_any_of(","));
            if (factions[5] == "1" || factions[5] == "3")
            {
                continue;
            }
            else
            {
                playerOrders[n] = playerOrder;
                playerOrder++;
            }
        }
        else if (players[n].substr(0, 1) == "C")
        {
            playerOrders[n] = playerOrder;
            playerOrder++;
        }
        else if (players[n].substr(0, 1) == "X")
        {
            continue;
        }

    }
    return playerOrders[pos];
}

int GetReplaySaver(std::string replayData)
{
    auto endPos = replayData.find(":;") + 2;
    auto replaySaver = replayData.at(endPos);
    //char replayChar[2];
    //strcpy_s(replayChar,replaySaver.c_str());
    //

    try
    {
        //要怎么把 string "\x0" 转为 int 0 呢？
        //没时间了，暂时先这么写吧...
        if (replaySaver == "\0" or "")
        {
            return 0;
        }
        else if (replaySaver == "\x1")
        {
            return 1;
        }
        else if (replaySaver == "\x2")
        {
            return 2;
        }
        else if (replaySaver == "\x3")
        {
            return 3;
        }
        else if (replaySaver == "\x4")
        {
            return 4;
        }
        else if (replaySaver == "\x5")
        {
            return 5;
        }
    }
    catch (std::exception e)
    {
        return 0;
    }
}


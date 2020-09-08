// InjectPDZ.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <easyhook.h>
#include <iostream>
#include <string>
#include <cstdio>
#include <filesystem>

int main()
{
    int processID;
    std::wstring dllName = L".\\pdz.dll";
    const auto dllPath = std::filesystem::absolute(std::filesystem::path{ dllName });
    std::cout << dllPath << std::endl;
    std::cout << "Type the ProcessID you want to inject \"pdz.dll\" to." << std::endl;
    std::cin >> processID;
    //Injection
    try
    {
        std::cout << "Injecting..." << std::endl;
        auto result = RhInjectLibrary(processID, 0, EASYHOOK_INJECT_DEFAULT, dllName.data(), nullptr, nullptr, 0);
        std::cout << "Result : " << result << std::endl;
        system("pause");
    }
    catch (std::exception e)
    {
        std::cout << "Unhandled error : "<< e.what() << std::endl;
        return 0;
    }
}


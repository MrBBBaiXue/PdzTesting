// ReplayAnalyst.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <filesystem>

int AnalyseCurrentPlayerInLua(const std::string& replayData, int pos);
int GetReplaySaver(const std::string& replayData);

void main()
{
    //Read
    std::ifstream input;
    auto const fileString = "exampleReplay-1.dat";
    std::ifstream ifs(fileString);

    std::string replayData((std::istreambuf_iterator<char>(ifs)),
                             (std::istreambuf_iterator<char>()));
    auto replayDataStartPos = replayData.find(";S=") + 3;
    if (replayDataStartPos == replayData.npos)
    {
        return;
    }
    auto replayDataEndPos = replayData.rfind(":;") + 3;
    if (replayDataEndPos == replayData.npos)
    {
        return;
    }
    replayData = replayData.substr(replayDataStartPos, replayDataEndPos - replayDataStartPos);

    auto replaySaver = GetReplaySaver(replayData);
    auto currentPlayerInLua = AnalyseCurrentPlayerInLua(replayData,replaySaver);

    std::cout << "Result : " <<  currentPlayerInLua << std::endl;
}

int AnalyseCurrentPlayerInLua(const std::string& replayData ,int replaySaver)
{
    try
    {
        std::vector<std::string> players;
        boost::split(players, replayData, boost::is_any_of(":"));
        std::vector<int> playerOrders(players.size());
        playerOrders.resize(players.size(), 6);
        int playerOrder = 0;

        for (size_t n = 0; n < players.size(); n++)
        {
            if (players[n].substr(0, 1) == "H")
            {
                std::vector<std::string> factions;
                boost::split(factions, players[n], boost::is_any_of(","));
                if (factions[5] == "1" || factions[5] == "3")
                {
                    continue;
                }
            }
            else if (players[n].substr(0, 1) == "X" or ";")
            {
                continue;
            }
            playerOrders[n] = playerOrder;
            playerOrder++;
        }
        return playerOrders[replaySaver];
    }
    catch (std::exception e)
    {
        return -1;
    }
}

int GetReplaySaver(const std::string& replayData)
{
    auto endPos = replayData.rfind(":;") + 2;
    auto replaySaver = replayData.at(endPos);

    try
    {
        return replaySaver;
    }
    catch (std::exception e)
    {
        return -1;
    }
}

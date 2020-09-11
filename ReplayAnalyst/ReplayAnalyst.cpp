// ReplayAnalyst.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <filesystem>

int AnalyseCurrentPlayerInLua(const std::string& replayData, int replaySaver);


void main()
{
    //Read
    std::ifstream input;
    auto const fileString = "exampleReplay-5.dat";
    std::ifstream ifs(fileString);
    //target
    std::atomic<int> currentPlayerInLua;
    //从 0 到 5 ， 出错为 -1

    std::string replayData((std::istreambuf_iterator<char>(ifs)),
                             (std::istreambuf_iterator<char>()));
    auto replayDataStartPos = replayData.find(";S=H");
    if (replayDataStartPos == replayData.npos)
    {
        currentPlayerInLua = -1;
        return;
    }
    auto replayDataEndPos = replayData.find(";", replayDataStartPos + 1);
    if (replayDataEndPos == replayData.npos)
    {
        currentPlayerInLua = -1;
        return;
    }

    auto replaySaver = replayData.at(replayDataEndPos + 1);
    if (replaySaver == 0)
    {
        std::cout << "replaySaver:0" << std::endl;
    }
    if (replaySaver == 1)
    {
        std::cout << "replaySaver:1" << std::endl;
    }
    if (replaySaver == 2)
    {
        std::cout << "replaySaver:2" << std::endl;
    }
    if (replaySaver == 3)
    {
        std::cout << "replaySaver:3" << std::endl;
    }
    if (replaySaver == 4)
    {
        std::cout << "replaySaver:4" << std::endl;
    }
    if (replaySaver == 5)
    {
        std::cout << "replaySaver:5" << std::endl;
    }
    auto playersDataStartPos = replayDataStartPos + 3;
    auto playersDataLength = replayDataEndPos - playersDataStartPos;
    auto playersData = replayData.substr(playersDataStartPos, playersDataLength);

    currentPlayerInLua = AnalyseCurrentPlayerInLua(playersData, replaySaver);

    std::cout << "Result : " <<  currentPlayerInLua << std::endl;
}

int AnalyseCurrentPlayerInLua(const std::string& replayData, int replaySaver)
{
    try
    {

        std::vector<std::string> players;
        boost::split(players, replayData, boost::is_any_of(":"));
        std::vector<int> playerOrders(players.size());
        players.resize(6);
        playerOrders.resize(players.size(), 6);
        int playerOrder = 0;
        std::cout << "replayData:" << std::endl;
        std::cout << replayData << std::endl;
        std::cout << "Players:" << std::endl;
        std::cout << "PlayersSize" << players.size() << std::endl;
        for (size_t n = 0; n < players.size(); n++)
        {
            std::cout << players[n] << std::endl;
        }
        std::cout << "Analysing..." << std::endl;
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
            else if (players[n].substr(0, 1) == "X")
            {
                continue;
            }
            playerOrders[n] = playerOrder;
            std::cout << playerOrder << std::endl;
            playerOrder++;

        }

        std::cout << "PlayerOrders:" << std::endl;
        for (size_t n = 0; n < playerOrders.size(); n++)
        {
            std::cout << playerOrders[n] << std::endl;
        }
        std::cout << "PlayerOrders[replaysaver]" << playerOrders[replaySaver] << std::endl;
        return playerOrders[replaySaver];
    }
    catch (const std::exception& e)
    {
        return -1;
    }
}


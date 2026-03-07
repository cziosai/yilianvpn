#include <iostream>
#include <map>
#include <string>
#include "VpnServer.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif // _WIN32

int speed = 100; // 这个决定网速，越大越快 

int setConfig(int argc, char **argv)
{
	map<std::string, std::string> argsMap;
	for (int i = 1; i < argc; ++i) {
		std::string argi = argv[i];
		if(argi == "help" || argi == "-h")
		{
			std::cout << "----------options-----------" << std::endl;
			std::cout << "port=[arg]" << std::endl;
			std::cout << "  -p=[arg] set port" << std::endl;
			std::cout << "speed=[arg]" << std::endl;
			std::cout << "  -sp=[arg] number, set run speed" << std::endl;
			std::cout << "user=[arg]" << std::endl;
			std::cout << "  -u=[arg] set user name" << std::endl;
			std::cout << "password=[arg]" << std::endl;
			std::cout << "     -pw=[arg] set password" << std::endl;
			std::cout << "max_client=[arg]" << std::endl;
			std::cout << "       -mc=[arg] set max client number" << std::endl;
			std::cout << "max_proxy=[arg]" << std::endl;
			std::cout << "      -mp=[arg] set max proxy number" << std::endl;
			std::cout << "help" << std::endl;
			std::cout << "  -h get help" << std::endl;
			return -1;
		} 
		std::vector<std::string> arrayStrings = CommonMethods::split(argv[i], '=');
		if(arrayStrings.size() >= 2)
		{
			argsMap[arrayStrings[0]] = arrayStrings[1];
		}
		else
		{
			std::cout << "unknown arg " << argi << std::endl;
		}
	}
	
	for (std::map <std::string, std::string>::iterator it = argsMap.begin(); it != argsMap.end(); ++it) {
		if(it->first == "port" || it->first == "-p")
		{
			Config::PORT = atoi(it->second.c_str());
		}
		else if(it->first == "speed" || it->first == "-sp")
		{
			speed = atoi(it->second.c_str());
		}
		else if(it->first == "user" || it->first == "-u")
		{
			Config::USER_NAME = atoi(it->second.c_str());
		}
		else if(it->first == "password" || it->first == "-pw")
		{
			Config::USER_PASSWD = atoi(it->second.c_str());
		}
		else if(it->first == "max_client" || it->first == "-mc")
		{
			Config::MAX_CLIENT_NUM = atoi(it->second.c_str());
		}
		else if(it->first == "max_proxy" || it->first == "-mp")
		{
			Config::CLIENT_MAX_PROXY = atoi(it->second.c_str());
		}
		else
		{
			std::cout << "unknown arg " << it->first << "=" << it->second << std::endl;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	if(setConfig(argc, argv) == -1)
	{
		return 0;
	}
	std::cout << "[Main]run speed " << speed * 1000 << " hz" << std::endl;
	VpnServer vpnServer;

	int count = 0; 
	// 启动任务
	while(task_loop() > 0)
	{
		count++;
		if(count > speed)
		{
			count = 0;
#ifdef _WIN32
			Sleep(1);
#else
			usleep(1000);
#endif // _WIN32
		}

	}
	vpnServer.close();
	printf("[Main]Vpn exit.\n");

	return 0;
}




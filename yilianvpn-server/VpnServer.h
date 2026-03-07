#ifndef VPNSERVER_H
#define VPNSERVER_H
#include <vector>
#include "Config.h"
#include "Socket.h"
#include "ServerSocket.h"
#include "Client.h"

class VpnServer: public Task
{
public:
	VpnServer()
	{
		closed = false;
		serverSocket = ServerSocket(0, Config::PORT);
		if(!serverSocket.isClose())
		{
			printf("[VpnServer]socket bind 0.0.0.0:%d success.\n", Config::PORT);
			printf("[VpnServer]use user name %d password %d verify.\n", Config::USER_NAME, Config::USER_PASSWD);
		}
		else
		{
			perror("[VpnServer]socket error msg");
			printf("[VpnServer]socket bind 0.0.0.0:%d fail.\n", Config::PORT);
			close();
		}
	}

	~VpnServer()
	{
	}

	void close()
	{
		quit();
		closed = true;
		serverSocket.iClose();
		closeAllClient();
	}

	bool isClose()
	{
		return closed;
	}
	
	/*
	 * 清除不活动客户端 
	 */
	int clearExpireClient()
	{
		int ret = 0;
		for (int i = 0; i < clients.size(); i++)
		{
			Client *client = clients[i];
			if(client->isExpire())
			{
				if(!client->isClose())
				{
					client->close(true, 400);
				}
				clients.erase(clients.begin() + i);
				i--;
				ret++;
				delete client;
			}
		}	
		return ret;
	}

	/*
	 * 清除已关闭客户端 
	 */
	int clearCloseClient()
	{
		int ret = 0;
		for (int i = 0; i < clients.size(); i++)
		{
			Client *client = clients[i];
			if(client->isClose())
			{
				clients.erase(clients.begin() + i);
				i--;
				ret++;
				delete client;
			}

		}
		return ret;
	}
	
	/*
	 * 清除所有客户端 
	 */
	int closeAllClient()
	{
		int ret = 0;
		for (int i = 0; i < clients.size(); i++)
		{
			Client *client = clients[i];
			if(!client->isClose())
			{
				client->close(true, 400);
			}
			clients.erase(clients.begin());
			i--;
			ret++;
			delete client;
		}
		return ret;
	}
	

	bool loop()
	{
		clearCloseClient();
		clearExpireClient();

		int socket_fd = serverSocket.getClientSocket();
		if(socket_fd == -1)
		{
			return false;
		}
		if(socket_fd == 0)
		{
			close();
			perror("[VpnServer]socket error msg");
			printf("[VpnServer]vpnserver socket error closed.\n");
			return true;
		}
		Socket socket = Socket(socket_fd);
		Client *client = new Client(socket);
		// 是否建立客户端
		if (clients.size() < Config::MAX_CLIENT_NUM)
		{
			clients.push_back(client);
			printf("[VpnServer]new client(%ld)connecting, total client number %lu.\n", client->clientId, clients.size());
		}
		else
		{
			printf("[VpnServer]client connet number reach max, total: %lu, client closeing.\n", clients.size());
			client->close(true, 404);
			delete client;
		}
		return false;
	}

private:
	// 服务器套接字
	ServerSocket serverSocket;
	// 客户端容器
	std::vector<Client *> clients;
	// 已关闭状态
	bool closed;
};

#endif


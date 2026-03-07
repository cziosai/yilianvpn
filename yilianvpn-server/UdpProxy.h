#ifndef UDPPROXY_H
#define UDPPROXY_H
#include <ctime>
#include "Config.h"
#include "Socket.h"
#include "Task.h"
#include "IPHeader.h"
#include "UDPHeader.h"
#include "Proxy.h"


class UdpProxy: public Proxy
{
public:
	UdpProxy()
	{
	}

	UdpProxy(long clientId, Socket clientSocket, char *packet) : Proxy(clientId, clientSocket)
	{
		protocol = IPHeader::UDP;
		dataBuffer = buffer + Proxy::UDP_HEADER_SIZE;
		IPHeader oldIPHeader = IPHeader(packet, 0);
		int ipHeaderLen = oldIPHeader.getHeaderLength();
		srcIp = oldIPHeader.getSourceIP();
		destIp = oldIPHeader.getDestinationIP();
		UDPHeader oldUDPHeader = UDPHeader(packet, ipHeaderLen);
		srcPort = oldUDPHeader.getSourcePort();
		destPort = oldUDPHeader.getDestinationPort();
		
		IPHeader ipHeader = IPHeader(buffer, 0);
		UDPHeader udpHeader = UDPHeader(buffer, IPHeader::IP4_HEADER_SIZE);
		ipHeader.setHeaderLength(IPHeader::IP4_HEADER_SIZE);
		ipHeader.setTos(oldIPHeader.getTos());
		ipHeader.setIdentification(0);
		ipHeader.setFlagsAndOffset(oldIPHeader.getFlagsAndOffset());
		ipHeader.setTTL(32);
		ipHeader.setProtocol(IPHeader::UDP);
		ipHeader.setSourceIP(destIp);
		ipHeader.setDestinationIP(srcIp);

		udpHeader.setSourcePort(destPort);
		udpHeader.setDestinationPort(srcPort);
	}

	~UdpProxy()
	{
	}

	void close(std::string msg = "")
	{
		quit();
		errorMsg = msg;
		closed = true;
		destSocket.iClose();
		// printf("[UdpProxy](%s) closed, the msg is %s.\n", toString().c_str(), errorMsg.c_str());
	}

	bool isClose()
	{
		return closed;
	}

	/*
	 * 发送数据给服务器 
	 */
	int sendToServer(char *bytes, int size)
	{
		int res = sendData(destSocket, bytes, 0, size);
		if(res < size)
		{
			perror("[UdpProxy]socket error msg");
			printf("[UdpProxy](%s) send data to server fail, total %d bytes, success send %d bytes.\n", toString().c_str(), size, res);
			close();
		}
		return res;
	}

	/*
	 * 发送数据给客户端 
	 */
	int sendToClient(char *bytes, int size)
	{
		int res = sendData(clientSocket, bytes, 0, size);
		if(res < size)
		{
			perror("[UdpProxy]socket error msg");
			printf("[UdpProxy](%s) send data to client fail, total %d bytes, success send %d bytes.\n", toString().c_str(), size, res);
			close();
		}
		return res;
	}

	/*
	 * 处理第一个包，建立远程连接 
	 */
	void processFisrtPacket(char *packet, int size)
	{
		destSocket = Socket(destIp, destPort, Socket::UDP);
		if(!destSocket.isClose())
		{
			processPacket(packet, size);
		}
		else
		{
			close("socket create fail");
			printf("[UdpProxy](%s) socket create fail.\n", toString().c_str());
		}
	}

	/*
	 * 处理数据包 
	 */
	void processPacket(char *packet, int size)
	{
		IPHeader ipHeader = IPHeader(packet, 0);
		int headerLen = ipHeader.getHeaderLength() + UDPHeader::UDP_HEADER_SIZE;
		int dataSize = ipHeader.getTotalLength() - headerLen;
		if(dataSize > 0)
		{
			// 转发给服务器
			sendToServer(packet + headerLen, dataSize);
		}
	}

	bool loop()
	{
		// 从服务器接收数据
		int size = destSocket.socketRecv(dataBuffer, Proxy::UDP_BUFFER_SIZE);
		if (size > 0)
		{
			updateUDPBuffer(size);
			// 转发给客户端
			sendToClient(buffer, Proxy::UDP_HEADER_SIZE + size);
		}
		else if(size == 0)
		{
			close();
			return true;
		}
		return false;
	}

	/*
	 * 数据包是否为同一个套接字 
	 */
	bool equal(char *packet)
	{
		IPHeader ipHeader = IPHeader(packet, 0);
		UDPHeader udpHeader = UDPHeader(packet, ipHeader.getHeaderLength());
		return protocol == ipHeader.getProtocol() && srcIp == ipHeader.getSourceIP() && srcPort == udpHeader.getSourcePort() && destIp == ipHeader.getDestinationIP() && destPort == udpHeader.getDestinationPort();
	}

	/*
	 * 更新UDP头部 
	 */
	void updateUDPBuffer(int size)
	{
		identification++;
		IPHeader ipHeader = IPHeader(buffer, 0);
		UDPHeader udpHeader = UDPHeader(buffer, ipHeader.getHeaderLength());
		ipHeader.setTotalLength(Proxy::UDP_HEADER_SIZE + size);
		ipHeader.setIdentification(identification);
		udpHeader.setTotalLength(UDPHeader::UDP_HEADER_SIZE + size);
		udpHeader.ComputeUDPChecksum(ipHeader);
	}
};

#endif


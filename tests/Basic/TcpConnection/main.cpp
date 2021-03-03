// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/TcpConnection.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"
#include "System/TcpListener.h"
#include "System/TcpConnector.h"
#include "System/ContextGroup.h"

using namespace System;

// constructor
TEST(TcpConnection, 1)
{
  TcpConnection();
}

// constructor
TEST(TcpConnection, 2)
{
  TcpConnection tcpConnection1;
  TcpConnection tcpConnection2(std::move(tcpConnection1));
}

// constructor
TEST(TcpConnection, 3)
{
  TcpConnection tcpConnection1;
  TcpConnection tcpConnection2 = std::move(tcpConnection1);
}

// read() and write()
TEST(TcpConnection, 4)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = listener.accept();
  uint8_t dataSend[] = "Hello World";
  sender.write(dataSend, 11);
  uint8_t dataReceived[1024];
  size_t size = receiver.read(dataReceived, 1024);
  ASSERT_EQ(11, size);
  ASSERT_EQ(0, memcmp(dataReceived, "Hello World", 11));
}

// getPeerAddressAndPort()
TEST(TcpConnection, 5)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  std::pair<Ipv4Address, uint16_t> addressAndPort = tcpConnection.getPeerAddressAndPort();
  ASSERT_EQ(Ipv4Address("127.0.0.1"), addressAndPort.first);
  ASSERT_EQ(6666, addressAndPort.second);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
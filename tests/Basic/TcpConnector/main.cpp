// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/TcpConnector.h"
#include "System/TcpConnection.h"
#include "System/Ipv4Address.h"
#include "System/TcpListener.h"

using namespace System;

// constructor
TEST(TcpConnector, 1)
{
  TcpConnector();
}

// constructor
TEST(TcpConnector, 2)
{
  Dispatcher dispatcher;
  TcpConnector tcpConnector(dispatcher);
}

// constructor
TEST(TcpConnector, 3)
{
  TcpConnector TcpConnector1;
  TcpConnector TcpConnector2(std::move(TcpConnector1));
}

// constructor
TEST(TcpConnector, 4)
{
  TcpConnector TcpConnector1;
  TcpConnector TcpConnector2 = std::move(TcpConnector1);
}

// connect
TEST(TcpConnector, 5)
{
  Dispatcher dispatcher;
  TcpConnector tcpConnector(dispatcher);
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  tcpConnector.connect(LISTEN_ADDRESS, LISTEN_PORT);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
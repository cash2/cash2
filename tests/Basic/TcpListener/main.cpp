// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/TcpListener.h"
#include "System/TcpConnector.h"
#include "System/TcpConnection.h"
#include "System/Ipv4Address.h"
#include "System/ContextGroup.h"

using namespace System;

// constructor
TEST(TcpListener, 1)
{
  TcpListener();
}

// constructor
TEST(TcpListener, 2)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener tcpListener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
}

// constructor
TEST(TcpListener, 3)
{
  TcpListener tcpListener1;
  TcpListener tcpListener2(std::move(tcpListener1));
}

// constructor
TEST(TcpListener, 4)
{
  TcpListener tcpListener1;
  TcpListener tcpListener2 = std::move(tcpListener1);
}

// accept()
TEST(TcpListener, 5)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener tcpListener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = tcpListener.accept();
  uint8_t dataSend[] = "Hello World";
  sender.write(dataSend, 11);
  uint8_t dataReceived[1024];
  size_t size = receiver.read(dataReceived, 1024);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
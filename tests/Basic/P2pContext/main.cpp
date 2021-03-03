// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "P2p/P2pContext.h"
#include "P2p/LevinProtocol.h"
#include "P2p/P2pInterfaces.h"
#include "System/TcpConnection.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"
#include "System/TcpListener.h"
#include "System/TcpConnector.h"
#include "System/ContextGroup.h"
#include "System/Context.h"

/*

My Notes

class P2pContext
public
  P2pContext()
  getPeerId()
  getPeerPort()
  getRemoteAddress()
  isIncoming()
  setPeerInfo()
  readCommand()
  writeMessage()
  start()
  stop()

*/

using namespace CryptoNote;
using namespace System;

// constructor
TEST(P2pContext, 1)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);
}

// getPeerId()
TEST(P2pContext, 2)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  PeerIdType peerIdType = p2pContext.getPeerId();
  ASSERT_EQ(0, peerIdType);
}

// getPeerPort()
TEST(P2pContext, 3)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  uint16_t peerPort = p2pContext.getPeerPort();
  ASSERT_EQ(0, peerPort);
}

// getRemoteAddress()
TEST(P2pContext, 4)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  NetworkAddress networkAddressRet = p2pContext.getRemoteAddress();
  ASSERT_EQ(1000, networkAddressRet.ip);
  ASSERT_EQ(2000, networkAddressRet.port);
}

// isIncoming()
TEST(P2pContext, 5)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  ASSERT_FALSE(p2pContext.isIncoming());
}

// setPeerInfo()
TEST(P2pContext, 6)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  uint8_t protocolVersion = 100;
  PeerIdType id = 200;
  uint16_t port = 300;
  p2pContext.setPeerInfo(protocolVersion, id, port);

  ASSERT_EQ(0, p2pContext.getPeerPort()); // port is changed only if isIncoming() is true
  ASSERT_EQ(id, p2pContext.getPeerId());
}

// readCommand()
TEST(P2pContext, 7)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  Context<> context1(dispatcher, [&] {
    LevinProtocol levinProtocol(tcpConnection);
    LevinProtocol::Command cmd;
    cmd.command = 1;
    cmd.isNotify = false;
    cmd.isResponse = false;
    cmd.buf = {1, 2, 3, 4};
    ASSERT_TRUE(p2pContext.readCommand(cmd));
  });

  Context<> context2(dispatcher, [&] { context1.get(); });  
}

// writeMessage()
TEST(P2pContext, 8)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  P2pMessage p2pMessage;
  P2pContext::Message::Type type = P2pContext::Message::Type::NOTIFY;
  P2pContext::Message message(std::move(p2pMessage), type);
  p2pContext.writeMessage(message);
}

// start()
TEST(P2pContext, 9)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  p2pContext.start();
}

// stop()
TEST(P2pContext, 10)
{
  System::Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection tcpConnection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  bool isIncoming = false;
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  std::chrono::nanoseconds timedSyncInterval = std::chrono::nanoseconds{3000};
  CORE_SYNC_DATA timedSyncData;
  timedSyncData.current_height = 100;
  timedSyncData.top_id = getRandHash();
  P2pContext p2pContext(dispatcher, std::move(tcpConnection), isIncoming, networkAddress, timedSyncInterval, timedSyncData);

  p2pContext.stop();
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
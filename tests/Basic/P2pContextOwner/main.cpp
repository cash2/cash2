// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "P2p/P2pContextOwner.h"
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

SKIP FOR NOW

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
TEST(P2pContextOwner, 1)
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

  P2pContextOwner::ContextList contextList;
  // P2pContextOwner(&p2pContext, contextList);
}














int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
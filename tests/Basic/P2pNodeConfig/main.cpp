// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "P2p/P2pNode.h"
#include "P2p/NetNodeConfig.h"
#include "System/Dispatcher.h"
#include "Logging/ConsoleLogger.h"

/*

SKIP FOR NOW

My Notes

*/

using namespace CryptoNote;

// constructor
TEST(P2pNode, 1)
{
  P2pNodeConfig p2pNodeConfig;
  p2pNodeConfig.setBindIp("127.0.0.1");
  p2pNodeConfig.setBindPort(6666);
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger;
  Crypto::Hash genesisHash = getRandHash();
  PeerIdType peerId = 200;
  P2pNode(p2pNodeConfig, dispatcher, logger, genesisHash, peerId);
}

// receiveConnection()
TEST(P2pNode, 2)
{
  P2pNodeConfig p2pNodeConfig;
  p2pNodeConfig.setBindIp("127.0.0.1");
  p2pNodeConfig.setBindPort(6666);
  System::Dispatcher dispatcher;
  Logging::ConsoleLogger logger;
  Crypto::Hash genesisHash = getRandHash();
  PeerIdType peerId = 200;
  P2pNode p2pNode(p2pNodeConfig, dispatcher, logger, genesisHash, peerId);

  // std::unique_ptr<IP2pConnection> ptr = p2pNode.receiveConnection(); // stuck in while loop
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
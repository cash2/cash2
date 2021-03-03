// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "P2p/P2pConnectionProxy.h"
#include "P2p/P2pContext.h"
#include "P2p/P2pContextOwner.h"
#include "P2p/IP2pNodeInternal.h"
#include "System/TcpConnection.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"
#include "System/TcpListener.h"
#include "System/TcpConnector.h"
#include "System/ContextGroup.h"
#include <iostream>

/*

SKIP FOR NOW

My Notes

class P2pConnectionProxy
public
  P2pConnectionProxy()
  processIncomingHandshake()
  read()
  write()
  ban()
  stop()

*/

using namespace CryptoNote;
using namespace System;

class MyIP2pNodeInternal : public IP2pNodeInternal {
public:
  MyIP2pNodeInternal() : m_genesisPayload(CORE_SYNC_DATA{1, getRandHash()}) {};

  virtual const CORE_SYNC_DATA& getGenesisPayload() const
  {
    return m_genesisPayload;
  };

  virtual std::list<PeerlistEntry> getLocalPeerList() const 
  { 
    NetworkAddress networkAddress;
    networkAddress.ip = 1000;
    networkAddress.port = 2000;
    PeerIdType peerIdType = 3000;
    uint64_t lastSeen = 4000;

    PeerlistEntry peerlistEntry;
    peerlistEntry.adr = networkAddress;
    peerlistEntry.id = peerIdType;
    peerlistEntry.last_seen = lastSeen;

    std::list<PeerlistEntry> peerList;
    peerList.push_back(peerlistEntry);
    
    return peerList; 
  };

  virtual basic_node_data getNodeData() const { return basic_node_data(); };
  virtual PeerIdType getPeerId() const { return PeerIdType(); };

  virtual void handleNodeData(const basic_node_data& node, P2pContext& ctx) {};
  virtual bool handleRemotePeerList(const std::list<PeerlistEntry>& peerlist, time_t local_time) { return true; };
  virtual void tryPing(P2pContext& ctx) {};

private:
  const CORE_SYNC_DATA m_genesisPayload;
};

template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// constructor
// Keeps segfaulting
// Skip for now
TEST(P2pConnectionProxy, 1)
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
  // std::unique_ptr<P2pContext> p2pContextPtr(std::move(p2pContext));
  // contextList.push_back(p2pContextPtr);
  // MyIP2pNodeInternal myIP2pNodeInternal;
  // P2pContextOwner p2pContextOwner(&p2pContext, contextList);
  // P2pConnectionProxy(p2pContextOwner, myIP2pNodeInternal);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
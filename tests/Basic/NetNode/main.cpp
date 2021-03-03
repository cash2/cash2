// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/NetNode.h"
#include "CryptoNoteCore/Core.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNoteCore/Currency.h"
#include <iostream>

/*

My Notes

class NodeServer
public
  *init_options()
  *NodeServer()
  run()
  *init()
  *deinit()
  *sendStopSignal()
  *get_this_peer_port()
  *get_payload_object()
  serialize()
  *log_peerlist()
  *log_connections()
  *get_connections_count()
  *get_outgoing_connections_count()
  *getPeerlistManager()

*/

using namespace CryptoNote;

class CryptonoteProtocol : public i_cryptonote_protocol
{
public:
  void relay_block(NOTIFY_NEW_BLOCK_request& arg) override
  {
    std::cout << "relay block" << std::endl;
  }

  void relay_transactions(NOTIFY_NEW_TRANSACTIONS_request& arg) override
  {
    std::cout << "relay transactions" << std::endl;
  }
};

// constructor
TEST(NetNode, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer(dispatcher, handler, logger);
}

// init_options()
TEST(NetNode, 2)
{
  boost::program_options::options_description desc("Allowed options");
  desc.add_options()
    ("help", "produce help message")
    ("optimization", "optimization level")
    ("verbose, v", "enable verbosity (optionally specify level)")
    ("listen, l", "listen on a port.")
    ("include-path, I", "include path")
    ("input-file", "input file")
  ;
  
  NodeServer::init_options(desc);
}

// init()
TEST(NetNode, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));
}

// run()
// Assertion fails and aborts
TEST(NetNode, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));
  // ASSERT_TRUE(nodeServer.run());
}

// deinit()
// Assertion fails and aborts
TEST(NetNode, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));
  // ASSERT_TRUE(nodeServer.run());
  // ASSERT_TRUE(nodeServer.deinit());
}

// sendStopSignal()
TEST(NetNode, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));
  ASSERT_TRUE(nodeServer.sendStopSignal());
}

// get_this_peer_port()
TEST(NetNode, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  uint32_t peerPort = nodeServer.get_this_peer_port();
  ASSERT_EQ(6666, peerPort);
}

// get_payload_object()
TEST(NetNode, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  nodeServer.get_payload_object().log_connections();
}

// log_peerlist()
TEST(NetNode, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  ASSERT_TRUE(nodeServer.log_peerlist());
}

// log_connections()
TEST(NetNode, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  ASSERT_TRUE(nodeServer.log_connections());
}

// get_connections_count()
TEST(NetNode, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  uint32_t connectionCount = nodeServer.get_connections_count();
  ASSERT_EQ(0, connectionCount);
}

// get_outgoing_connections_count()
TEST(NetNode, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  size_t connectionCount = nodeServer.get_outgoing_connections_count();
  ASSERT_EQ(0, connectionCount);
}

// getPeerlistManager()
TEST(NetNode, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NetNodeConfig netNodeConfig;
  netNodeConfig.setBindIp("127.0.0.1");
  netNodeConfig.setBindPort(6666);
  netNodeConfig.setExternalPort(0);
  netNodeConfig.setAllowLocalIp(false);
  netNodeConfig.setHideMyPort(false);
  netNodeConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(netNodeConfig));

  ASSERT_NO_THROW(nodeServer.getPeerlistManager());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
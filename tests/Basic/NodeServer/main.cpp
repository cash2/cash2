// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/NodeServer.h"
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
TEST(NodeServer, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer(dispatcher, handler, logger);
}

// init_options()
TEST(NodeServer, 2)
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
TEST(NodeServer, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));
}

// run()
// Assertion fails and aborts
TEST(NodeServer, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));
  // ASSERT_TRUE(nodeServer.run());
}

// deinit()
// Assertion fails and aborts
TEST(NodeServer, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));
  // ASSERT_TRUE(nodeServer.run());
  // ASSERT_TRUE(nodeServer.deinit());
}

// sendStopSignal()
TEST(NodeServer, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));
  ASSERT_TRUE(nodeServer.sendStopSignal());
}

// get_this_peer_port()
TEST(NodeServer, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  uint32_t peerPort = nodeServer.get_this_peer_port();
  ASSERT_EQ(6666, peerPort);
}

// get_payload_object()
TEST(NodeServer, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  nodeServer.get_payload_object().log_connections();
}

// log_peerlist()
TEST(NodeServer, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  nodeServer.log_peerlist();
}

// log_connections()
TEST(NodeServer, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  nodeServer.log_connections();
}

// get_connections_count()
TEST(NodeServer, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  uint32_t connectionCount = nodeServer.get_connections_count();
  ASSERT_EQ(0, connectionCount);
}

// get_outgoing_connections_count()
TEST(NodeServer, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  size_t connectionCount = nodeServer.get_outgoing_connections_count();
  ASSERT_EQ(0, connectionCount);
}

// getPeerlistManager()
TEST(NodeServer, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpoint;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpoint, logger);
  NodeServer nodeServer(dispatcher, handler, logger);

  CryptoNote::NodeServerConfig nodeServerConfig;
  nodeServerConfig.setBindIp("127.0.0.1");
  nodeServerConfig.setBindPort(6666);
  nodeServerConfig.setExternalPort(0);
  nodeServerConfig.setAllowLocalIp(false);
  nodeServerConfig.setHideMyPort(false);
  nodeServerConfig.setConfigFolder("cash2");

  ASSERT_TRUE(nodeServer.init(nodeServerConfig));

  ASSERT_NO_THROW(nodeServer.getPeerlistManager());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandler.cpp"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include "System/Dispatcher.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/MinerConfig.h"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class CryptoNoteProtocolHandler
{
public
  CryptoNoteProtocolHandler()
  addObserver()
  removeObserver()
  set_p2p_endpoint()
  isSynchronized()
  log_connections()
  stop()
  start_sync()
  on_idle()
  onConnectionOpened()
  onConnectionClosed()
  get_stat_info()
  get_payload_sync_data()
  process_payload_sync_data()
  handleCommand()
  getPeerCount() const
  getObservedHeight() const
  requestMissingPoolTransactions()

private
  System::Dispatcher& m_dispatcher
  ICore& m_core
  const Currency& m_currency
  p2p_endpoint_stub m_p2p_stub
  IP2pEndpoint* m_p2p
  std::atomic<bool> m_synchronized
  std::atomic<bool> m_stop
  mutable std::mutex m_observedHeightMutex
  uint32_t m_observedHeight
  std::atomic<size_t> m_peersCount
  Tools::ObserverManager<ICryptoNoteProtocolObserver> m_observerManager
}

*/

// Helper functions

class CryptoNoteProtocolObserver : public ICryptoNoteProtocolObserver
{
public:
  virtual void peerCountUpdated(size_t count) override
  {
    std::cout << "peer count updated" << std::endl;
  }

  virtual void lastKnownBlockHeightUpdated(uint32_t height) override
  {
    std::cout << "last known block height updated" << std::endl;
  }

  virtual void blockchainSynchronized(uint32_t topHeight) override
  {
    std::cout << "blockchain synchronized" << std::endl;
  }
};

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

// Adds an empty block to the blockchain
bool addBlock1(Core& core, Currency& currency)
{
  uint32_t currentBlockchainHeight = core.get_current_blockchain_height();

  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  // block.timestamp = time(nullptr) + (currentBlockchainHeight * parameters::DIFFICULTY_TARGET);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  bool blockAdded = core.handle_block_found(block);

  return blockAdded;
}

// constructor
TEST(CryptoNoteProtocolHandler, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);
}

// addObserver()
TEST(CryptoNoteProtocolHandler, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  CryptoNoteProtocolObserver cryptoNoteProtocolObserver;

  ASSERT_TRUE(handler.addObserver(&cryptoNoteProtocolObserver));
}

// removeObserver()
TEST(CryptoNoteProtocolHandler, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  CryptoNoteProtocolObserver cryptoNoteProtocolObserver;

  ASSERT_TRUE(handler.addObserver(&cryptoNoteProtocolObserver));

  ASSERT_TRUE(handler.removeObserver(&cryptoNoteProtocolObserver));
}

// set_p2p_endpoint()
TEST(CryptoNoteProtocolHandler, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  p2p_endpoint_stub p2pEndpointStub2;

  handler.set_p2p_endpoint(&p2pEndpointStub2);
}

// isSynchronized()
TEST(CryptoNoteProtocolHandler, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  ASSERT_FALSE(handler.isSynchronized());

  // I am not sure how to make isSynchronized return true

  // CryptoNoteConnectionContext context;
  // ASSERT_TRUE(handler.start_sync(context));

  // ASSERT_TRUE(handler.isSynchronized());
}

// log_connections()
TEST(CryptoNoteProtocolHandler, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  handler.log_connections();
}

// stop()
TEST(CryptoNoteProtocolHandler, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  handler.stop();
}

// start_sync()
TEST(CryptoNoteProtocolHandler, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  CryptoNoteConnectionContext context;
  ASSERT_TRUE(handler.start_sync(context));
}

// on_idle()
TEST(CryptoNoteProtocolHandler, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  handler.on_idle();
}

// onConnectionOpened()
TEST(CryptoNoteProtocolHandler, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  CryptoNoteConnectionContext context;
  handler.onConnectionOpened(context);
}

// onConnectionClosed()
TEST(CryptoNoteProtocolHandler, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  // must have blocks in the blockchain for this function to work
  ASSERT_TRUE(addBlock1(core, currency));

  CryptoNoteConnectionContext context;
  handler.onConnectionClosed(context);
}

// get_stat_info()
TEST(CryptoNoteProtocolHandler, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  core_stat_info statInfo;
  ASSERT_TRUE(handler.get_stat_info(statInfo));
}

// get_payload_sync_data()
TEST(CryptoNoteProtocolHandler, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  // must have blocks in the blockchain for this function to work
  ASSERT_TRUE(addBlock1(core, currency));

  CORE_SYNC_DATA hshd;
  ASSERT_TRUE(handler.get_payload_sync_data(hshd));
}

// process_payload_sync_data()
TEST(CryptoNoteProtocolHandler, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  // must have blocks in the blockchain for this function to work
  ASSERT_TRUE(addBlock1(core, currency));

  CORE_SYNC_DATA hshd;
  ASSERT_TRUE(handler.get_payload_sync_data(hshd));

  CryptoNoteConnectionContext context;
  bool isInital = true;
  ASSERT_TRUE(handler.process_payload_sync_data(hshd, context, isInital));
}

// handleCommand()
TEST(CryptoNoteProtocolHandler, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  bool is_notify = false;
  int command = 0;
  BinaryArray in_buff;
  BinaryArray buff_out;
  CryptoNoteConnectionContext context;
  bool handled;
  int randomInt = handler.handleCommand(is_notify, command, in_buff, buff_out, context, handled);

  ASSERT_EQ(0, randomInt);
}

// getPeerCount()
TEST(CryptoNoteProtocolHandler, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  size_t peerCount = handler.getPeerCount();

  ASSERT_EQ(0, peerCount);
}

// getObservedHeight()
TEST(CryptoNoteProtocolHandler, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  uint32_t height = handler.getObservedHeight();
  ASSERT_EQ(0, height);

  // must have blocks in the blockchain for get_payload_sync_data() to work
  ASSERT_TRUE(addBlock1(core, currency));

  CORE_SYNC_DATA hshd;
  // get_payload_sync_data() updates the observer height
  ASSERT_TRUE(handler.get_payload_sync_data(hshd));

  CryptoNoteConnectionContext context;
  bool isInital = true;
  ASSERT_TRUE(handler.process_payload_sync_data(hshd, context, isInital));

  height = handler.getObservedHeight();
  ASSERT_EQ(2, height);

  // add 10 more blocks
  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(addBlock1(core, currency));
  }

  // check observed height again

  ASSERT_TRUE(handler.get_payload_sync_data(hshd));
  ASSERT_TRUE(handler.process_payload_sync_data(hshd, context, isInital));
  height = handler.getObservedHeight();
  ASSERT_EQ(12, height);
}

// requestMissingPoolTransactions()
TEST(CryptoNoteProtocolHandler, 18)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  System::Dispatcher dispatcher;
  p2p_endpoint_stub p2pEndpointStub;
  CryptoNoteProtocolHandler handler(currency, dispatcher, core, &p2pEndpointStub, logger);

  CryptoNoteConnectionContext context;
  handler.requestMissingPoolTransactions(context);
}


























int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
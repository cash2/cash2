// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/IMinerHandler.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "Logging/ConsoleLogger.h"
#include <random>

using namespace CryptoNote;

/*

My Notes

class miner {
public
  miner()
  ~miner()

  init()
  set_block_template(const Block& bl, const difficulty_type& diffic)
  on_block_chain_update()
  start()
  uint64_t get_speed()
  send_stop_signal()
  stop()
  is_mining()
  on_idle()
  on_synchronized()
  find_nonce_for_given_block1()
  pause()
  resume()
  do_print_hashrate()

private
  worker_thread()
  request_block_template()
  merge_hr()

  struct miner_config
  
  Currency& m_currency
  Logging::LoggerRef logger

  std::atomic<bool> m_stop
  std::mutex m_template_lock
  Block m_template
  std::atomic<uint32_t> m_template_no
  std::atomic<uint32_t> m_starter_nonce
  difficulty_type m_diffic

  std::atomic<uint32_t> m_threads_total
  std::atomic<int32_t> m_pausers_count
  std::mutex m_miners_count_lock

  std::list<std::thread> m_threads
  std::mutex m_threads_lock
  IMinerHandler& m_handler
  AccountPublicAddress m_mine_address
  OnceInInterval m_update_block_template_interval
  OnceInInterval m_update_merge_hr_interval

  std::vector<BinaryArray> m_extra_messages
  miner_config m_config
  std::string m_config_folder_path
  std::atomic<uint64_t> m_last_hr_merge_time
  std::atomic<uint64_t> m_hashes
  std::atomic<uint64_t> m_current_hash_rate
  std::mutex m_last_hash_rates_lock
  std::list<uint64_t> m_last_hash_rates
  m_do_print_hashrate
  m_do_mining
}

struct BlockHeader {
  uint32_t nonce
  uint64_t timestamp
  Crypto::Hash previousBlockHash
}

struct Block : public BlockHeader {
  Transaction baseTransaction
  std::vector<Crypto::Hash> transactionHashes
}

using difficulty_type = std::uint64_t;

*/

// Helper functions

class MinerHandler : public IMinerHandler
{
public:
  bool handle_block_found(Block& b)
  {
    return true;
  }

  bool get_block_template(Block& b, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce)
  {
    m_difficulty++;
    diffic = m_difficulty;
    return true;
  }

private:
  difficulty_type m_difficulty;
  Block m_block;
  uint32_t m_height;
  AccountPublicAddress m_address;
  BinaryArray m_extraNonce;
};

/*

// constructor
TEST(Miner, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);
}

// set_block_template()
TEST(Miner, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  Block block;
  difficulty_type difficultyType = 100;

  ASSERT_TRUE(miner.set_block_template(block, difficultyType));

  // m_template = block
  // m_diffic = 100
  // m_template_no = 1
  // m_starter_nonce = 2367499508
}

// on_block_chain_update()
// mining not started
TEST(Miner, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_TRUE(miner.on_block_chain_update());
}

// on_block_chain_update()
// mining started
TEST(Miner, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 1;

  miner.start(accountPublicAddress, threadCount);

  sleep(1);

  ASSERT_TRUE(miner.on_block_chain_update());

  sleep(1);

  ASSERT_TRUE(miner.on_block_chain_update());

  sleep(1);

  ASSERT_TRUE(miner.on_block_chain_update());

  sleep(1);
}

// on_idle()
// mining not started
TEST(Miner, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_TRUE(miner.on_idle());
}

// on_idle()
// mining started
TEST(Miner, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 1;

  miner.start(accountPublicAddress, threadCount);

  sleep(1);

  ASSERT_TRUE(miner.on_idle());
}

// do_print_hashrate()
TEST(Miner, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  miner.do_print_hashrate(true);

  miner.do_print_hashrate(false);
}

// init()
TEST(Miner, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  MinerConfig minerConfig;

  ASSERT_TRUE(miner.init(minerConfig));
}

*/

// init()
// MinerConfig extraMessages not empty
TEST(Miner, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  MinerConfig minerConfig;

  minerConfig.extraMessages = "/media/sf_Shared/cryptonote/tests/Basic/MinerCore/testFile.txt";

  ASSERT_TRUE(miner.init(minerConfig));
}

/*

// init()
// MinerConfig startMining not empty
TEST(Miner, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  MinerConfig minerConfig;

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  minerConfig.startMining = currency.accountAddressAsString(accountPublicAddress);

  ASSERT_TRUE(miner.init(minerConfig));
}

// is_mining()
TEST(Miner, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  MinerConfig minerConfig;

  ASSERT_FALSE(miner.is_mining());
}

// start()
TEST(Miner, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 1;

  ASSERT_TRUE(miner.start(accountPublicAddress, threadCount));

  sleep(1);

  ASSERT_TRUE(miner.is_mining());
}

// start()
// call miner.start twice
TEST(Miner, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 1;

  ASSERT_TRUE(miner.start(accountPublicAddress, threadCount));

  sleep(1);

  // call miner.start twice
  ASSERT_FALSE(miner.start(accountPublicAddress, threadCount));

  ASSERT_TRUE(miner.is_mining());
}

// get_speed()
// startMining() is false
TEST(Miner, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_EQ(0, miner.get_speed());
}

// get_speed()
// startMining() is true
TEST(Miner, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_EQ(0, miner.get_speed());

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 2;

  ASSERT_TRUE(miner.start(accountPublicAddress, threadCount));

  sleep(1);

  ASSERT_EQ(0, miner.get_speed());

  // have to call miner.on_idle twice before m_current_hash_rate value is set
  ASSERT_TRUE(miner.on_idle());
  
  // allow enough time for miner.merge_hr to be called
  sleep(5);

  ASSERT_TRUE(miner.on_idle());

  // allow enough time for miner.merge_hr to be called
  sleep(5);

  ASSERT_GT(miner.get_speed(), 0);
}

// send_stop_signal()
TEST(Miner, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 2;

  ASSERT_FALSE(miner.is_mining());

  ASSERT_TRUE(miner.start(accountPublicAddress, threadCount));

  sleep(1);

  ASSERT_TRUE(miner.is_mining());

  miner.send_stop_signal();

  ASSERT_FALSE(miner.is_mining());
}

// stop()
TEST(Miner, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_FALSE(miner.is_mining());

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 1;

  ASSERT_TRUE(miner.start(accountPublicAddress, threadCount));

  sleep(1);

  ASSERT_TRUE(miner.is_mining());

  ASSERT_TRUE(miner.stop());

  ASSERT_FALSE(miner.is_mining());
}

// find_nonce_for_given_block1()
// difficulty < 5
TEST(Miner, 18)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);
  
  Block block;
  block.nonce = 1;
  block.timestamp = 100;
  block.previousBlockHash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  Transaction transaction;
  transaction.version = 1;
  block.baseTransaction = transaction;
  
  difficulty_type difficulty = 2;

  Crypto::cn_context context;
  ASSERT_TRUE(miner.find_nonce_for_given_block1(context, block, difficulty));
}

// find_nonce_for_given_block1()
// difficulty > 5
TEST(Miner, 19)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);
  
  Block block;
  block.nonce = 1;
  block.timestamp = 100;
  block.previousBlockHash = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

  Transaction transaction;
  transaction.version = 1;
  block.baseTransaction = transaction;
  
  difficulty_type difficulty = 8;

  Crypto::cn_context context;
  ASSERT_TRUE(miner.find_nonce_for_given_block1(context, block, difficulty));
}

// on_synchronized()
TEST(Miner, 20)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  ASSERT_FALSE(miner.is_mining());

  MinerConfig minerConfig;

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  minerConfig.startMining = currency.accountAddressAsString(accountPublicAddress);

  miner.init(minerConfig);

  ASSERT_FALSE(miner.is_mining());

  miner.on_synchronized();

  ASSERT_TRUE(miner.is_mining());
}

// pause()
TEST(Miner, 21)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 2;

  miner.start(accountPublicAddress, threadCount);

  sleep(1);

  miner.pause();
}

// resume()
TEST(Miner, 22)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  MinerHandler minerHandler;

  miner miner(currency, minerHandler, logger);

  AccountPublicAddress accountPublicAddress;
  accountPublicAddress.viewPublicKey = generateKeyPair().publicKey;
  accountPublicAddress.spendPublicKey = generateKeyPair().publicKey;

  size_t threadCount = 2;

  miner.start(accountPublicAddress, threadCount);

  // wait 1 second for mining to start
  sleep(1);

  // should log an error
  miner.resume();

  miner.pause();

  miner.resume();
}

*/

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
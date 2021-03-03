// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Logging/ConsoleLogger.h"
#include <time.h>
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class ISerializer

class OnceInTimeInterval {
public
  OnceInTimeInterval()
  call()

private
  time_t m_lastWorkedTime
  unsigned m_interval
  CryptoNote::ITimeProvider& m_timeProvider
}


class tx_memory_pool {
public
  tx_memory_pool()
  addObserver()
  removeObserver()
  init()
  deinit()
  have_tx()
  add_tx()
  add_tx()
  take_tx()
  on_blockchain_inc()
  on_blockchain_dec()
  lock()
  unlock()
  obtainGuard()
  fill_block_template1()
  get_transactions()
  get_difference()
  get_transactions_count()
  print_pool()
  on_idle()
  getTransactionIdsByPaymentId()
  getTransactionIdsByTimestamp()
  getTransactions()
  serialize()

private
  using main_index_t = hashed_unique<BOOST_MULTI_INDEX_MEMBER(TransactionDetails, Crypto::Hash, id)>
  using fee_index_t = ordered_non_unique<identity<TransactionDetails>, TransactionPriorityComparator> fee_index_t
  using tx_container_t = multi_index_container<TransactionDetails, indexed_by<main_index_t, fee_index_t>>
  using GlobalOutput = std::pair<uint64_t, uint64_t>
  using GlobalOutputsContainer = std::set<GlobalOutput>
  using key_images_container = std::unordered_map<Crypto::KeyImage, std::unordered_set<Crypto::Hash>>

  addTransactionInputs()
  haveSpentInputs()
  removeTransactionInputs()
  removeTransaction()
  removeExpiredTransactions()
  is_transaction_ready_to_go()
  buildIndexes()

  Tools::ObserverManager<ITxPoolObserver> m_observerManager
  const CryptoNote::Currency& m_currency
  OnceInTimeInterval m_txCheckInterval
  mutable std::recursive_mutex m_transactions_lock
  key_images_container m_spent_key_images
  GlobalOutputsContainer m_spentOutputs
  std::string m_config_folder
  CryptoNote::ITransactionValidator& m_validator
  CryptoNote::ITimeProvider& m_timeProvider
  tx_container_t m_transactions  
  tx_container_t::nth_index<1>::type& m_fee_index
  std::unordered_map<Crypto::Hash, uint64_t> m_recentlyDeletedTransactions
  Logging::LoggerRef logger
  PaymentIdIndex m_paymentIdIndex
  TimestampTransactionsIndex m_timestampIndex
}

*/

class TransactionValidator : public ITransactionValidator
{
  virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock) override
  {
    return true;
  }

  virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) override
  {
    return true;
  }

  virtual bool haveSpentKeyImages(const CryptoNote::Transaction& tx) override
  {
    return false;
  }

  virtual bool checkTransactionSize(size_t blobSize) override
  {
    return true;
  }
};

class TimeProvider : public ITimeProvider
{
public:
  TimeProvider(time_t timeInput = time(nullptr)) : m_time(timeInput) {}; 
  virtual time_t now() override { return m_time; };

private:
  time_t m_time;
};

class TxPoolObserver : public ITxPoolObserver
{
public:
  virtual void txDeletedFromPool() override
  {
    std::cout << "tx deleted from pool" << std::endl;
  };
};

// constructor
TEST(TransactionPool, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
}

// addObserver()
TEST(TransactionPool, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  TxPoolObserver observer;
  ASSERT_TRUE(tx_memory_pool.addObserver(&observer));
}

// removeObserver()
TEST(TransactionPool, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  TxPoolObserver observer;

  ASSERT_FALSE(tx_memory_pool.removeObserver(&observer));

  ASSERT_TRUE(tx_memory_pool.addObserver(&observer));

  ASSERT_TRUE(tx_memory_pool.removeObserver(&observer));
}

// init()
TEST(TransactionPool, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  std::string config_folder = "/home/aphivantrakul/Desktop/Shared/cryptonote/tests/TransactionPool";
  ASSERT_TRUE(tx_memory_pool.init(config_folder));
}

// deinit()
TEST(TransactionPool, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  std::string config_folder = "/home/aphivantrakul/Desktop/Shared/cryptonote/tests/TransactionPool";
  ASSERT_TRUE(tx_memory_pool.init(config_folder));

  ASSERT_TRUE(tx_memory_pool.deinit());
}

// have_tx()
TEST(TransactionPool, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Crypto::Hash id = getRandHash();
  ASSERT_FALSE(tx_memory_pool.have_tx(id));
}

// add_tx(transaction, id, blobSize, tvc, keptByBlock)
TEST(TransactionPool, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Transaction transaction;
  transaction.version = 1;

  Crypto::Hash id = getRandHash();
  size_t blobSize = getObjectBinarySize(transaction);
  tx_verification_context tvc;
  bool keptByBlock = true;

  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, id, blobSize, tvc, keptByBlock));

  ASSERT_TRUE(tx_memory_pool.have_tx(id));
}

// add_tx()
TEST(TransactionPool, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Transaction transaction;
  transaction.version = 1;

  tx_verification_context tvc;
  bool keptByBlock = true;

  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, keptByBlock));

  Crypto::Hash id;
  getObjectHash(transaction, id);

  ASSERT_TRUE(tx_memory_pool.have_tx(id));
}

// take_tx()
TEST(TransactionPool, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Transaction transaction;
  transaction.version = 1;

  tx_verification_context tvc;
  bool keptByBlock = true;

  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, keptByBlock));

  Crypto::Hash id;
  getObjectHash(transaction, id);

  ASSERT_TRUE(tx_memory_pool.have_tx(id));

  Transaction transactionOutput;
  size_t blobSize;
  uint64_t fee;

  ASSERT_TRUE(tx_memory_pool.take_tx(id, transactionOutput, blobSize, fee));

  ASSERT_EQ(1, transactionOutput.version);
  ASSERT_EQ(0, fee);

  ASSERT_FALSE(tx_memory_pool.have_tx(id));
}

// on_blockchain_inc()
TEST(TransactionPool, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  uint64_t new_block_height = 10;
  Crypto::Hash top_block_id = getRandHash();

  ASSERT_TRUE(tx_memory_pool.on_blockchain_inc(new_block_height, top_block_id));
}

// on_blockchain_dec()
TEST(TransactionPool, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  uint64_t new_block_height = 10;
  Crypto::Hash top_block_id = getRandHash();

  ASSERT_TRUE(tx_memory_pool.on_blockchain_dec(new_block_height, top_block_id));
}

// lock()
TEST(TransactionPool, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_memory_pool.lock();
}

// unlock()
TEST(TransactionPool, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_memory_pool.unlock();
}

// obtainGuard()
TEST(TransactionPool, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  ASSERT_NO_THROW(tx_memory_pool.obtainGuard());
}

// fill_block_template1()
TEST(TransactionPool, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Block block;
  size_t total_size;
  uint64_t fee;

  size_t median_size = 1000;
  size_t maxCumulativeSize = 50000;
  uint64_t already_generated_coins = 10;

  ASSERT_TRUE(tx_memory_pool.fill_block_template1(block, median_size, maxCumulativeSize, already_generated_coins, total_size, fee));
}

// get_transactions()
TEST(TransactionPool, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Transaction transaction;
  transaction.version = 1;

  tx_verification_context tvc;
  bool keptByBlock = true;

  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, keptByBlock));

  std::list<Transaction> transactions;
  tx_memory_pool.get_transactions(transactions);

  ASSERT_EQ(1, transactions.size());
  Crypto::Hash hash1 = getObjectHash(transaction);
  Crypto::Hash hash2 = getObjectHash(transactions.front());

  ASSERT_TRUE(hashesEqual(hash1, hash2));
}

// get_difference()
TEST(TransactionPool, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_verification_context tvc;
  bool keptByBlock = true;

  Transaction transaction1;
  transaction1.version = 1;
  transaction1.unlockTime = 1;
  Crypto::Hash txHash1 = getObjectHash(transaction1);
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction1, tvc, keptByBlock));

  Transaction transaction2;
  transaction2.version = 1;
  transaction2.unlockTime = 2;
  Crypto::Hash txHash2 = getObjectHash(transaction2);
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction2, tvc, keptByBlock));

  Transaction transaction3;
  transaction3.version = 1;
  transaction3.unlockTime = 3;
  Crypto::Hash txHash3 = getObjectHash(transaction3);
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction3, tvc, keptByBlock));

  Transaction transaction4;
  transaction4.version = 1;
  transaction4.unlockTime = 4;
  Crypto::Hash txHash4 = getObjectHash(transaction4);

  Transaction transaction5;
  transaction5.version = 1;
  transaction5.unlockTime = 5;
  Crypto::Hash txHash5 = getObjectHash(transaction5);

  std::vector<Crypto::Hash> known_tx_ids;
  known_tx_ids.push_back(txHash2);
  known_tx_ids.push_back(txHash3);
  known_tx_ids.push_back(txHash4);
  known_tx_ids.push_back(txHash5);

  std::vector<Crypto::Hash> new_tx_ids;
  std::vector<Crypto::Hash> deleted_tx_ids;

  ASSERT_NO_THROW(tx_memory_pool.get_difference(known_tx_ids, new_tx_ids, deleted_tx_ids));

  ASSERT_EQ(1, new_tx_ids.size());
  ASSERT_EQ(2, deleted_tx_ids.size());

  ASSERT_TRUE(hashesEqual(txHash1, new_tx_ids[0]));

  // txHash4 and txHash5 should be in deleted_tx_ids but we do not know which position they are in
  ASSERT_TRUE(std::find(deleted_tx_ids.begin(), deleted_tx_ids.end(), txHash4) != deleted_tx_ids.end());
  ASSERT_TRUE(std::find(deleted_tx_ids.begin(), deleted_tx_ids.end(), txHash5) != deleted_tx_ids.end());

  // count transactions in mempool
  ASSERT_EQ(3, tx_memory_pool.get_transactions_count());
  
  // comment below out because it causes assertion on line 518 to fail for some reason
  ASSERT_TRUE(tx_memory_pool.have_tx(txHash1));
  ASSERT_TRUE(tx_memory_pool.have_tx(txHash2));
  ASSERT_TRUE(tx_memory_pool.have_tx(txHash3));
  ASSERT_FALSE(tx_memory_pool.have_tx(txHash4));
  ASSERT_FALSE(tx_memory_pool.have_tx(txHash5));
}

// get_transactions_count()
TEST(TransactionPool, 18)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_verification_context tvc;
  bool keptByBlock = true;

  Transaction transaction1;
  transaction1.version = 1;
  transaction1.unlockTime = 1;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction1, tvc, keptByBlock));

  Transaction transaction2;
  transaction2.version = 1;
  transaction2.unlockTime = 2;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction2, tvc, keptByBlock));

  Transaction transaction3;
  transaction3.version = 1;
  transaction3.unlockTime = 3;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction3, tvc, keptByBlock));

  Transaction transaction4;
  transaction4.version = 1;
  transaction4.unlockTime = 4;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction4, tvc, keptByBlock));

  Transaction transaction5;
  transaction5.version = 1;
  transaction5.unlockTime = 5;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction5, tvc, keptByBlock));

  // count transactions in mempool
  ASSERT_EQ(5, tx_memory_pool.get_transactions_count());
}

// print_pool()
TEST(TransactionPool, 19)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_verification_context tvc;
  bool keptByBlock = true;

  Transaction transaction1;
  transaction1.version = 1;
  transaction1.unlockTime = 1;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction1, tvc, keptByBlock));

  Transaction transaction2;
  transaction2.version = 1;
  transaction2.unlockTime = 2;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction2, tvc, keptByBlock));

  Transaction transaction3;
  transaction3.version = 1;
  transaction3.unlockTime = 3;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction3, tvc, keptByBlock));

  Transaction transaction4;
  transaction4.version = 1;
  transaction4.unlockTime = 4;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction4, tvc, keptByBlock));

  Transaction transaction5;
  transaction5.version = 1;
  transaction5.unlockTime = 5;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction5, tvc, keptByBlock));

  std::cout << tx_memory_pool.print_pool(true) << std::endl;

  std::cout << tx_memory_pool.print_pool(false) << std::endl;
}

// on_idle()
TEST(TransactionPool, 20)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_memory_pool.on_idle();
}

// getTransactionIdsByPaymentId()
// no transactions
TEST(TransactionPool, 21)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Crypto::Hash paymentId;
  std::vector<Crypto::Hash> transactionIds;
  ASSERT_FALSE(tx_memory_pool.getTransactionIdsByPaymentId(paymentId, transactionIds));
}

// getTransactionIdsByPaymentId()
// 1 transaction
TEST(TransactionPool, 22)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  tx_verification_context tvc;
  bool keptByBlock = true;

  Transaction transaction;
  transaction.version = 1;
  transaction.unlockTime = 1;
  // 2 signifies TransactionExtraNonce, 33 is the size of the remaining part of the vector, 0 signifies a TransactionPaymentId, all 1's is the paymentId
  transaction.extra = {2, 33, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, keptByBlock));

  Crypto::Hash paymentId;
  ASSERT_TRUE(getPaymentIdFromTxExtra(transaction.extra, paymentId));
  std::vector<Crypto::Hash> transactionIds;
  ASSERT_TRUE(tx_memory_pool.getTransactionIdsByPaymentId(paymentId, transactionIds));
}

// getTransactionIdsByTimestamp()
TEST(TransactionPool, 23)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Transaction transaction;
  transaction.version = 1;
  transaction.unlockTime = 1;
  tx_verification_context tvc;
  bool keptByBlock = true;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, keptByBlock));

  // trying to find timestamps range that includes the transactions timestamp
  uint64_t timestampBegin = time(nullptr) - 10;
  uint64_t timestampEnd = time(nullptr) + 10;
  uint32_t transactionsNumberLimit = 10;

  std::vector<Crypto::Hash> hashes;
  uint64_t transactionsNumberWithinTimestamps;

  ASSERT_TRUE(tx_memory_pool.getTransactionIdsByTimestamp(timestampBegin, timestampEnd, transactionsNumberLimit, hashes, transactionsNumberWithinTimestamps));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/Account.h"
#include "CryptoNoteConfig.h"
#include <Logging/LoggerGroup.h>
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class AccountBase

class Currency
public
  maxBlockHeight()
  maxBlockBlobSize()
  maxTxSize()
  publicAddressBase58Prefix()
  minedMoneyUnlockWindow()
  timestampCheckWindow()
  blockFutureTimeLimit()
  moneySupply()
  emissionSpeedFactor()
  rewardBlocksWindow()
  blockGrantedFullRewardZone()
  minerTxBlobReservedSize()
  numberOfDecimalPlaces()
  coin()
  minimumFee()
  defaultDustThreshold()
  difficultyTarget()
  difficultyWindow()
  difficultyLag()
  difficultyCut()
  difficultyBlocksCount()
  maxBlockSizeInitial()
  maxBlockSizeGrowthSpeedNumerator()
  maxBlockSizeGrowthSpeedDenominator()
  lockedTxAllowedDeltaSeconds()
  lockedTxAllowedDeltaBlocks()
  mempoolTxLiveTime()
  mempoolTxFromAltBlockLiveTime()
  numberOfPeriodsToForgetTxDeletedFromPool()
  blocksFileName()
  blocksCacheFileName()
  blockIndexesFileName()
  txPoolFileName()
  blockchainIndexesFileName()
  isTestnet()
  genesisBlock()
  genesisBlockHash()
  getBlockReward1()
  maxBlockCumulativeSize()
  constructMinerTx1()
  accountAddressAsString()
  accountAddressAsString()
  parseAccountAddressString()
  formatAmount()
  formatAmount()
  parseAmount()
  *nextDifficulty1()
  *checkProofOfWork1()
  getApproximateMaximumInputCount()

private
  Currency()
  init()
  generateGenesisBlock()

private
  uint64_t m_maxBlockHeight
  size_t m_maxBlockBlobSize
  size_t m_maxTxSize
  uint64_t m_publicAddressBase58Prefix
  size_t m_minedMoneyUnlockWindow
  size_t m_timestampCheckWindow
  uint64_t m_blockFutureTimeLimit
  uint64_t m_moneySupply
  unsigned int m_emissionSpeedFactor
  size_t m_rewardBlocksWindow
  size_t m_blockGrantedFullRewardZone
  size_t m_minerTxBlobReservedSize
  size_t m_numberOfDecimalPlaces
  uint64_t m_coin
  uint64_t m_mininumFee
  uint64_t m_defaultDustThreshold
  uint64_t m_difficultyTarget
  size_t m_difficultyWindow
  size_t m_difficultyLag
  size_t m_difficultyCut
  size_t m_maxBlockSizeInitial
  uint64_t m_maxBlockSizeGrowthSpeedNumerator
  uint64_t m_maxBlockSizeGrowthSpeedDenominator
  uint64_t m_lockedTxAllowedDeltaSeconds
  size_t m_lockedTxAllowedDeltaBlocks
  uint64_t m_mempoolTxLiveTime
  uint64_t m_mempoolTxFromAltBlockLiveTime
  uint64_t m_numberOfPeriodsToForgetTxDeletedFromPool
  std::string m_blocksFileName
  std::string m_blocksCacheFileName
  std::string m_blockIndexesFileName
  std::string m_txPoolFileName
  std::string m_blockchainIndexesFileName
  std::vector<uint64_t> PRETTY_AMOUNTS
  bool m_testnet
  Block m_genesisBlock
  Crypto::Hash m_genesisBlockHash
  Logging::LoggerRef logger
  friend class CurrencyBuilder

class CurrencyBuilder
public
  CurrencyBuilder()
  Currency currency()
  *generateGenesisTransaction()
  maxBlockNumber()
  maxBlockBlobSize()
  maxTxSize()
  publicAddressBase58Prefix()
  minedMoneyUnlockWindow()
  timestampCheckWindow()
  blockFutureTimeLimit()
  moneySupply()
  emissionSpeedFactor()
  rewardBlocksWindow()
  blockGrantedFullRewardZone()
  minerTxBlobReservedSize()
  numberOfDecimalPlaces()
  mininumFee()
  defaultDustThreshold()
  difficultyTarget()
  difficultyWindow()
  difficultyLag()
  difficultyCut()
  maxBlockSizeInitial()
  maxBlockSizeGrowthSpeedNumerator()
  maxBlockSizeGrowthSpeedDenominator()
  lockedTxAllowedDeltaSeconds()
  lockedTxAllowedDeltaBlocks()
  mempoolTxLiveTime()
  mempoolTxFromAltBlockLiveTime()
  numberOfPeriodsToForgetTxDeletedFromPool()
  blocksFileName()
  blocksCacheFileName()
  blockIndexesFileName()
  txPoolFileName()
  blockchainIndexesFileName()
  testnet()

private
  Currency m_currency

* means function has not yet been fully tested

must call currencyBuilder.currency() each time a currency member is updated to see the updated value
can't do Currency currency = currencyBuilder.currency() and have currency change after a new value has been set through currency builder

struct BlockHeader {
  uint32_t nonce;
  uint64_t timestamp;
  Crypto::Hash previousBlockHash;
};

struct Block : public BlockHeader {
  Transaction baseTransaction;
  std::vector<Crypto::Hash> transactionHashes;
};

b /home/aphivantrakul/Desktop/Shared/cryptonote/src/CryptoNoteCore/Currency.cpp:400

*/

uint32_t loopCount = 100;

// maxBlockHeight() and maxBlockNumber()
TEST(Currency, 1)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxBlockHeight(), parameters::CRYPTONOTE_MAX_BLOCK_NUMBER);
  // set
  currencyBuilder.maxBlockNumber(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxBlockHeight(), 100);
}

// maxBlockBlobSize()
TEST(Currency, 2)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxBlockBlobSize(), parameters::CRYPTONOTE_MAX_BLOCK_BLOB_SIZE);
  // set
  currencyBuilder.maxBlockBlobSize(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxBlockBlobSize(), 100);
}

// maxTxSize()
TEST(Currency, 3)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxTxSize(), parameters::CRYPTONOTE_MAX_TX_SIZE);
  // set
  currencyBuilder.maxTxSize(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxTxSize(), 100);
}

// publicAddressBase58Prefix()
TEST(Currency, 4)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().publicAddressBase58Prefix(), parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
  // set
  currencyBuilder.publicAddressBase58Prefix(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().publicAddressBase58Prefix(), 100);
}

// minedMoneyUnlockWindow()
TEST(Currency, 5)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().minedMoneyUnlockWindow(), parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
  // set
  currencyBuilder.minedMoneyUnlockWindow(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().minedMoneyUnlockWindow(), 100);
}

// timestampCheckWindow()
TEST(Currency, 6)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().timestampCheckWindow(), parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
  // set
  currencyBuilder.timestampCheckWindow(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().timestampCheckWindow(), 100);
}

// blockFutureTimeLimit()
TEST(Currency, 7)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blockFutureTimeLimit(), parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT);
  // set
  currencyBuilder.blockFutureTimeLimit(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blockFutureTimeLimit(), 100);
}

// moneySupply()
TEST(Currency, 8)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().moneySupply(), parameters::MONEY_SUPPLY);
  // set
  currencyBuilder.moneySupply(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().moneySupply(), 100);
}

// emissionSpeedFactor()
TEST(Currency, 9)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().emissionSpeedFactor(), parameters::EMISSION_SPEED_FACTOR);
  // set
  // emission speed factor must be less than 64
  currencyBuilder.emissionSpeedFactor(50);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().emissionSpeedFactor(), 50);
}

// rewardBlocksWindow()
TEST(Currency, 10)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().rewardBlocksWindow(), parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  // set
  currencyBuilder.rewardBlocksWindow(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().rewardBlocksWindow(), 100);
}

// blockGrantedFullRewardZone()
TEST(Currency, 11)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blockGrantedFullRewardZone(), parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE);
  // set
  currencyBuilder.blockGrantedFullRewardZone(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blockGrantedFullRewardZone(), 100);
}

// minerTxBlobReservedSize()
TEST(Currency, 12)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().minerTxBlobReservedSize(), parameters::CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
  // set
  currencyBuilder.minerTxBlobReservedSize(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().minerTxBlobReservedSize(), 100);
}

// numberOfDecimalPlaces()
TEST(Currency, 13)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().numberOfDecimalPlaces(), parameters::CRYPTONOTE_DISPLAY_DECIMAL_POINT);
  // set
  currencyBuilder.numberOfDecimalPlaces(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().numberOfDecimalPlaces(), 100);
}

// coin()
TEST(Currency, 14)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  size_t numDecimalPlaces = currencyBuilder.currency().numberOfDecimalPlaces();

  uint64_t coin = 1;
  
  for (size_t i = 0; i < numDecimalPlaces; i++)
  {
    coin *= 10;
  }

  ASSERT_EQ(currencyBuilder.currency().coin(), coin);
}

// minimumFee()
TEST(Currency, 15)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().minimumFee(), parameters::MINIMUM_FEE);
  // set
  currencyBuilder.mininumFee(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().minimumFee(), 100);
}

// defaultDustThreshold()
TEST(Currency, 16)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().defaultDustThreshold(), parameters::DEFAULT_DUST_THRESHOLD);
  // set
  currencyBuilder.defaultDustThreshold(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().defaultDustThreshold(), 100);
}

// difficultyTarget()
TEST(Currency, 17)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().difficultyTarget(), parameters::DIFFICULTY_TARGET);
  // set
  currencyBuilder.difficultyTarget(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().difficultyTarget(), 100);
}

// difficultyWindow()
TEST(Currency, 18)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().difficultyWindow(), parameters::DIFFICULTY_WINDOW);
  // set
  currencyBuilder.difficultyWindow(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().difficultyWindow(), 100);
}

// difficultyLag()
TEST(Currency, 19)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().difficultyLag(), parameters::DIFFICULTY_LAG);
  // set
  currencyBuilder.difficultyLag(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().difficultyLag(), 100);
}

// difficultyCut()
TEST(Currency, 20)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().difficultyCut(), parameters::DIFFICULTY_CUT);
  // set
  currencyBuilder.difficultyCut(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().difficultyCut(), 100);
}

// currency.difficultyBlocksCount()
TEST(Currency, 21)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().difficultyBlocksCount(), parameters::DIFFICULTY_WINDOW + parameters::DIFFICULTY_LAG);
  // set
  currencyBuilder.difficultyWindow(100);
  currencyBuilder.difficultyLag(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().difficultyBlocksCount(), 200);
}

// maxBlockSizeInitial()
TEST(Currency, 22)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeInitial(), parameters::MAX_BLOCK_SIZE_INITIAL);
  // set
  currencyBuilder.maxBlockSizeInitial(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeInitial(), 100);
}

// maxBlockSizeGrowthSpeedNumerator()
TEST(Currency, 23)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeGrowthSpeedNumerator(), parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR);
  // set
  currencyBuilder.maxBlockSizeGrowthSpeedNumerator(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeGrowthSpeedNumerator(), 100);
}

// maxBlockSizeGrowthSpeedDenominator()
TEST(Currency, 24)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeGrowthSpeedDenominator(), parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR);
  // set
  currencyBuilder.maxBlockSizeGrowthSpeedDenominator(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().maxBlockSizeGrowthSpeedDenominator(), 100);
}

// lockedTxAllowedDeltaSeconds()
TEST(Currency, 25)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().lockedTxAllowedDeltaSeconds(), parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS);
  // set
  currencyBuilder.lockedTxAllowedDeltaSeconds(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().lockedTxAllowedDeltaSeconds(), 100);
}

// lockedTxAllowedDeltaBlocks()
TEST(Currency, 26)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().lockedTxAllowedDeltaBlocks(), parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);
  // set
  currencyBuilder.lockedTxAllowedDeltaBlocks(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().lockedTxAllowedDeltaBlocks(), 100);
}

// mempoolTxLiveTime()
TEST(Currency, 27)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().mempoolTxLiveTime(), parameters::CRYPTONOTE_MEMPOOL_TX_LIVETIME);
  // set
  currencyBuilder.mempoolTxLiveTime(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().mempoolTxLiveTime(), 100);
}

// mempoolTxFromAltBlockLiveTime()
TEST(Currency, 28)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().mempoolTxFromAltBlockLiveTime(), parameters::CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME);
  // set
  currencyBuilder.mempoolTxFromAltBlockLiveTime(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().mempoolTxFromAltBlockLiveTime(), 100);
}

// numberOfPeriodsToForgetTxDeletedFromPool()
TEST(Currency, 29)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().numberOfPeriodsToForgetTxDeletedFromPool(), parameters::CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL);
  // set
  currencyBuilder.numberOfPeriodsToForgetTxDeletedFromPool(100);
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().numberOfPeriodsToForgetTxDeletedFromPool(), 100);
}

// blocksFileName()
TEST(Currency, 33)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blocksFileName(), parameters::CRYPTONOTE_BLOCKS_FILENAME);
  // set
  currencyBuilder.blocksFileName("Hello World!");
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blocksFileName(), "Hello World!");
}

// blocksCacheFileName()
TEST(Currency, 34)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blocksCacheFileName(), parameters::CRYPTONOTE_BLOCKSCACHE_FILENAME);
  // set
  currencyBuilder.blocksCacheFileName("Hello World!");
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blocksCacheFileName(), "Hello World!");
}

// blockIndexesFileName()
TEST(Currency, 35)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blockIndexesFileName(), parameters::CRYPTONOTE_BLOCKINDEXES_FILENAME);
  // set
  currencyBuilder.blockIndexesFileName("Hello World!");
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blockIndexesFileName(), "Hello World!");
}

// txPoolFileName()
TEST(Currency, 36)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().txPoolFileName(), parameters::CRYPTONOTE_POOLDATA_FILENAME);
  // set
  currencyBuilder.txPoolFileName("Hello World!");
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().txPoolFileName(), "Hello World!");
}

// blockchainIndexesFileName()
TEST(Currency, 37)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_EQ(currencyBuilder.currency().blockchainIndexesFileName(), parameters::CRYPTONOTE_BLOCKCHAIN_INDEXES_FILENAME);
  // set
  currencyBuilder.blockchainIndexesFileName("Hello World!");
  // check that value has changed
  ASSERT_EQ(currencyBuilder.currency().blockchainIndexesFileName(), "Hello World!");
}

// isTestnet() and testnet()
TEST(Currency, 38)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // get
  ASSERT_FALSE(currencyBuilder.currency().isTestnet());
  // set
  currencyBuilder.testnet(true);
  // check that value hash changed
  ASSERT_TRUE(currencyBuilder.currency().isTestnet());
}

// genesisBlock()
TEST(Currency, 39)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Block genesisBlock = currencyBuilder.currency().genesisBlock();

  ASSERT_EQ(genesisBlock.timestamp, 0);
  ASSERT_EQ(genesisBlock.nonce, 0);

  Crypto::Hash hash;

  size_t hashSize = sizeof(hash.data) / sizeof(hash.data[0]);
  
  // check previous block hash is all zeros
  for (size_t i = 0; i < hashSize; i++)
  {
    ASSERT_EQ(genesisBlock.previousBlockHash.data[i], 0);
  }
}

// genesisBlockHash()
TEST(Currency, 40)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  // Crypto::Hash genesisBlockHash = currencyBuilder.currency().genesisBlockHash();

//  genesisBlockHash =
//    {
//      0x1, 0xaa, 0xb5, 0x49, 0x8f, 0x4f, 0xe6, 0x31, 0x9b, 0x21,
//      0xf, 0x41, 0x8f, 0xf2, 0xfd, 0x5b, 0xcc, 0xd1, 0x85, 0xe3,
//      0x22, 0x77, 0x6e, 0xa5, 0x46, 0x68, 0x89, 0x47, 0x79, 0x1,
//      0xbf, 0xc1
//    }

  // no assertions for now
  // just use gdb to see the value of genesisBlockHash
}

// getBlockReward1() 1
TEST(Currency, 41)
{
  size_t medianBlockSize = 1000000;
  size_t currentBlockSize = 1000000;
  uint64_t alreadyGeneratedCoins = 1000000;
  uint64_t fee = 100;

  uint64_t reward;
  int64_t emissionChange;

  Logging::LoggerGroup logger;
  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  ASSERT_TRUE(currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, fee, reward, emissionChange));

  // baseReward is 0.894069671 plus 0.00000100 fee gives total reward of 0.894069771
  ASSERT_EQ(894069771, reward);
  ASSERT_EQ(894069671, emissionChange);
}

// getBlockReward1() 2
TEST(Currency, 42)
{
  size_t medianBlockSize = 100000;
  // currentBlockSize must be set to greater than CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE for this test to work correctly
  size_t currentBlockSize = 150000;
  uint64_t alreadyGeneratedCoins = 1000000;
  uint64_t fee = 100;

  uint64_t reward;
  int64_t emissionChange;

  Logging::LoggerGroup logger;
  CurrencyBuilder currencyBuilder(logger);

  ASSERT_TRUE(currencyBuilder.currency().getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, fee, reward, emissionChange));

  // baseReward is 0.894069671 plus 0.00000100 fee gives total reward of 0.894069771
  ASSERT_EQ(894069771, reward);
  ASSERT_EQ(894069671, emissionChange);
}

// maxBlockCumulativeSize()
TEST(Currency, 43)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  uint64_t height = 1;

  size_t maxBlockCumulativeSize = currencyBuilder.currency().maxBlockCumulativeSize(height);

  ASSERT_EQ(maxBlockCumulativeSize, parameters::MAX_BLOCK_SIZE_INITIAL + (parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR / parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR));
}

// constructMinerTx1()
TEST(Currency, 44)
{
  for (uint32_t i = 0; i < loopCount; i++)
  {
    Logging::LoggerGroup logger;

    CurrencyBuilder currencyBuilder(logger);

    Currency currency = currencyBuilder.currency();

    uint32_t height = 0;
    size_t medianSize = 0;
    uint64_t alreadyGeneratedCoins = 0;
    size_t currentBlockSize = 0;
    uint64_t fee = 0;

    AccountPublicAddress minerAddress;

    KeyPair viewKey = generateKeyPair();
    KeyPair spendKey = generateKeyPair();

    minerAddress.viewPublicKey = viewKey.publicKey;
    minerAddress.spendPublicKey = spendKey.publicKey;

    Transaction transaction;
    BinaryArray extraNonce;

    size_t maxOuts = 1;

    ASSERT_TRUE(currency.constructMinerTx1(height, medianSize, alreadyGeneratedCoins, currentBlockSize, fee, minerAddress, transaction, extraNonce, maxOuts));
  }
}

// accountAddressAsString()
TEST(Currency, 47)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  AccountBase accountBase;

  // set up account keys
  AccountKeys accountKeys;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  accountBase.setAccountKeys(accountKeys);
  accountBase.set_createtime(getRandUint64_t());

  // accountAddressStr equals "25PMd9EurzU5m3ajvtZPGxjXcwE9t8GMTeKKv5TzY56bcKyomUn96Thg6LwVKbgqriVqvbfsQFzvxahVzoKvH3xgTnwJ2Vu"
  std::string accountAddressStr = currency.accountAddressAsString(accountBase);

  ASSERT_EQ(accountAddressStr[0], '2');
}

// accountAddressAsString()
TEST(Currency, 48)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  AccountBase accountBase;

  // set up account keys
  AccountKeys accountKeys;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  accountBase.setAccountKeys(accountKeys);
  accountBase.set_createtime(getRandUint64_t());

  // accountAddressStr1 equals "29oUSYKMLx6c3q5mRijn7wKoKNp8nHa2cNCSthdgxntyKGjypGre7s75eB9F8o5kPe9K5uwBywW6e1bBxVkJ8VVxSHfQmd6"
  std::string accountAddressStr1 = currency.accountAddressAsString(accountBase);
  // accountAddressStr2 equals "29oUSYKMLx6c3q5mRijn7wKoKNp8nHa2cNCSthdgxntyKGjypGre7s75eB9F8o5kPe9K5uwBywW6e1bBxVkJ8VVxSHfQmd6"
  std::string accountAddressStr2 = currency.accountAddressAsString(accountKeys.address);

  ASSERT_EQ(accountAddressStr1, accountAddressStr2);
  ASSERT_EQ(accountAddressStr1[0], '2');
  ASSERT_EQ(accountAddressStr2[0], '2');
}

// parseAccountAddressString()
TEST(Currency, 49)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  AccountBase accountBase;

  // set up account keys
  AccountKeys accountKeys;

  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();

  accountKeys.address.viewPublicKey = viewKeyPair.publicKey;
  accountKeys.address.spendPublicKey = spendKeyPair.publicKey;
  accountKeys.viewSecretKey = viewKeyPair.secretKey;
  accountKeys.spendSecretKey = spendKeyPair.secretKey;

  accountBase.setAccountKeys(accountKeys);
  accountBase.set_createtime(getRandUint64_t());

  // accountAddressStr equals "25PMd9EurzU5m3ajvtZPGxjXcwE9t8GMTeKKv5TzY56bcKyomUn96Thg6LwVKbgqriVqvbfsQFzvxahVzoKvH3xgTnwJ2Vu"
  std::string accountAddressStr = currency.accountAddressAsString(accountBase);

  AccountPublicAddress accountPublicAddress;

  ASSERT_TRUE(currency.parseAccountAddressString(accountAddressStr, accountPublicAddress));

  ASSERT_EQ(accountKeys.address.viewPublicKey, accountPublicAddress.viewPublicKey);
  ASSERT_EQ(accountKeys.address.spendPublicKey, accountPublicAddress.spendPublicKey);
}

// formatAmount()
// amount is uint64_t
TEST(Currency, 50)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  uint64_t amount = 0;
  std::string formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "0.000000000");

  amount = 1;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "0.000000001");

  amount = 123456789;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "0.123456789");

  amount = 123456789123456789;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "123456789.123456789");

  amount = 1111111111222222222;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "1111111111.222222222");

  // near maximum amount
  amount = 9211111111111111111;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "9211111111.111111111");
}

// formatAmount()
// amount is int64_t
TEST(Currency, 51)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  int64_t amount = 0;
  std::string formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "0.000000000");

  amount = -1;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "-0.000000001");

  amount = -123456789;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "-0.123456789");

  amount = -123456789123456789;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "-123456789.123456789");

  amount = -1111111111222222222;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "-1111111111.222222222");

  // near maximum amount
  // I don't understand how this number is not too large for an int64_t
  amount = -9211111111111111111;
  formattedAmount = currency.formatAmount(amount);
  ASSERT_EQ(formattedAmount, "-9211111111.111111111");
}

// parseAmount()
TEST(Currency, 52)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  std::string amountString = "100";
  uint64_t amount;
  ASSERT_TRUE(currency.parseAmount(amountString, amount));
  ASSERT_EQ(amount, 100000000000);

  amountString = "1";
  ASSERT_TRUE(currency.parseAmount(amountString, amount));
  ASSERT_EQ(amount, 1000000000);

  amountString = "0.000000001";
  ASSERT_TRUE(currency.parseAmount(amountString, amount));
  ASSERT_EQ(amount, 1);

  amountString = "0.00000000123456";
  ASSERT_FALSE(currency.parseAmount(amountString, amount));
  ASSERT_EQ(amount, 1);
}

// nextDifficulty1()
TEST(Currency, 53)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  std::vector<uint64_t> timestamps = {1};
  std::vector<difficulty_type> cumulativeDifficulties = {1};
  ASSERT_EQ(currency.nextDifficulty1(timestamps, cumulativeDifficulties), 100000);

  timestamps = {1, 2};
  cumulativeDifficulties = {1, 2};
  ASSERT_EQ(currency.nextDifficulty1(timestamps, cumulativeDifficulties), 100000);

  // the numbers used in ASSERT_EQ are gotten using gdb
  // formula is too complicated to calculate next difficulty
  // will likely change the formula so will skip this function for now
}

// checkProofOfWork1()
TEST(Currency, 54)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  Block block = getBasicBlock();

  // I have no idea how this function works, especially check_hash1() in Difficulty.cpp
  // checkProofOfWork1() returns false if currentDifficulty is above 1 and I don't know why that is
  for (uint32_t i = 0; i < loopCount; i++)
  {
    for (difficulty_type currentDifficulty = 0; currentDifficulty < 2; currentDifficulty++)
    {
      Crypto::Hash proofOfWork;
      Crypto::cn_context context;
      ASSERT_TRUE(currency.checkProofOfWork1(context, block, currentDifficulty, proofOfWork));
    }
  }
}

// getApproximateMaximumInputCount()
TEST(Currency, 55)
{
  Logging::LoggerGroup logger;

  CurrencyBuilder currencyBuilder(logger);

  Currency currency = currencyBuilder.currency();

  size_t transactionSize = 0;
  size_t outputCount = 0;
  size_t mixinCount = 0;
  size_t maximumInputCount = currency.getApproximateMaximumInputCount(transactionSize, outputCount, mixinCount);
  ASSERT_EQ(maximumInputCount, 164703072086692424);

  transactionSize = 1;
  outputCount = 1;
  mixinCount = 1;
  maximumInputCount = currency.getApproximateMaximumInputCount(transactionSize, outputCount, mixinCount);
  ASSERT_EQ(maximumInputCount, 102481911520608619);

  // the numbers used in ASSERT_EQ are gotten using gdb
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
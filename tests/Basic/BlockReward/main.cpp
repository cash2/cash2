// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"

#include "CryptoNoteConfig.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/Currency.h"
#include <Logging/LoggerGroup.h>

using namespace CryptoNote;

const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
const uint64_t TEST_MONEY_SUPPLY = CryptoNote::parameters::MONEY_SUPPLY;
const uint64_t TEST_EMISSION_SPEED_FACTOR = CryptoNote::parameters::EMISSION_SPEED_FACTOR;

// given the settings of GRANTED_FULL_REWARD_ZONE = 100000,
// MONEY_SUPPLY = UINT64_C(15000000000000000), and 
// EMISSION_SPEED_FACTOR = 24 that is set for Cash2, the reward for the
// first block mined should be 894069671 or 0.894069671 coins
const uint64_t expectedFirstBlockReward = 894069671;

class TestCurrency1 : public ::testing::Test
{
public:
  TestCurrency1() :
    ::testing::Test(),
    m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency()) {}

protected:
  static const size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
  static const size_t medianBlockSize = 0;
  static const uint64_t transactionFees = 0;

  Logging::LoggerGroup m_logger;
  CryptoNote::Currency m_currency;
};

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 0
TEST_F(TestCurrency1, 1)
{
  uint64_t alreadyGeneratedCoins = 0;
  uint64_t expectedBlockReward = expectedFirstBlockReward; //0.89406967 coins
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// alreadyGeneratedCoins = reward from first block mined
TEST_F(TestCurrency1, 2)
{ 
  uint64_t alreadyGeneratedCoins = expectedFirstBlockReward; //0.89406967 coins
  // use wolframalpha.com to calculate (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  uint64_t expectedBlockReward = 894069618; // 0.894069618 coins
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 3,750,000
TEST_F(TestCurrency1, 3)
{ 
  uint64_t alreadyGeneratedCoins = TEST_MONEY_SUPPLY / 4; //3,750,000 coins
  uint64_t expectedBlockReward = 670552253; //0.670552253 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 7,500,000
TEST_F(TestCurrency1, 4)
{ 
  uint64_t alreadyGeneratedCoins = TEST_MONEY_SUPPLY / 2; //7,500,000 coins
  uint64_t expectedBlockReward = 447034835; //0.447034835 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 11,250,000
TEST_F(TestCurrency1, 5)
{ 
  uint64_t alreadyGeneratedCoins = TEST_MONEY_SUPPLY / 3; //5,000,000 coins
  uint64_t expectedBlockReward = 596046447; //0.596046447 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 14,000,000
TEST_F(TestCurrency1, 6)
{ 
  uint64_t alreadyGeneratedCoins = 14000000000000000; //14,000,000 coins
  uint64_t expectedBlockReward = 59604644; //0.059604644 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 14,500,000
TEST_F(TestCurrency1, 7)
{ 
  uint64_t alreadyGeneratedCoins = 14500000000000000; //14,500,000 coins
  uint64_t expectedBlockReward = 29802322; //0.029802322 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 14,999,999
TEST_F(TestCurrency1, 8)
{ 
  uint64_t alreadyGeneratedCoins = 14999999000000000; //14,999,999 coins
  uint64_t expectedBlockReward = 59; //0.000000059 coins

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 14,999,999.99
TEST_F(TestCurrency1, 9)
{ 
  uint64_t alreadyGeneratedCoins = 14999999990000000; //14,999,999.99 coins
  uint64_t expectedBlockReward = 0;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// already generated coins = 15,000,000
TEST_F(TestCurrency1, 10)
{ 
  uint64_t alreadyGeneratedCoins = 15000000000000000; //15,000,000 coins
  uint64_t expectedBlockReward = 0;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(2)
TEST_F(TestCurrency1, 11)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(2) << emissionSpeedFactor()) + 1)] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(2) << emissionSpeedFactor) + 1)]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (2 << emissionSpeedFactor) + 1) >> emissionSpeedFactor
  // baseReward = ((2 << emissionSpeedFactor) + 1) >> emissionSpeedFactor
  // baseReward = 2

  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(2) << m_currency.emissionSpeedFactor()) + 1);
  uint64_t expectedBlockReward = 2;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(2)
TEST_F(TestCurrency1, 12)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(2) << emissionSpeedFactor()))] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(2) << emissionSpeedFactor))]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (2 << emissionSpeedFactor)) >> emissionSpeedFactor
  // baseReward = ((2 << emissionSpeedFactor)) >> emissionSpeedFactor
  // baseReward = 2
  
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(2) << m_currency.emissionSpeedFactor()));
  uint64_t expectedBlockReward = 2;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(2)
TEST_F(TestCurrency1, 13)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(2) << emissionSpeedFactor()) - 1)] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(2) << emissionSpeedFactor) - 1)]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (2 << emissionSpeedFactor) - 1) >> emissionSpeedFactor
  // baseReward = ((2 << emissionSpeedFactor) - 1) >> emissionSpeedFactor
  // baseReward = 1
  
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(2) << m_currency.emissionSpeedFactor()) - 1);
  uint64_t expectedBlockReward = 1;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(1)
TEST_F(TestCurrency1, 14)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(1) << emissionSpeedFactor()) + 1)] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(1) << emissionSpeedFactor) + 1)]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (1 << emissionSpeedFactor) + 1) >> emissionSpeedFactor
  // baseReward = ((1 << emissionSpeedFactor) + 1) >> emissionSpeedFactor
  // baseReward = 1
  
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(1) << m_currency.emissionSpeedFactor()) + 1);
  uint64_t expectedBlockReward = 1;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(1)
TEST_F(TestCurrency1, 15)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(1) << emissionSpeedFactor()))] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(1) << emissionSpeedFactor))]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (1 << emissionSpeedFactor)) >> emissionSpeedFactor
  // baseReward = ((1 << emissionSpeedFactor)) >> emissionSpeedFactor
  // baseReward = 1
  
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(1) << m_currency.emissionSpeedFactor()));
  uint64_t expectedBlockReward = 1;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// transition from a base reward of 2 coins down to 1 coin, UINT64_C(1)
TEST_F(TestCurrency1, 16)
{
  // baseReward = (moneySupply - alreadyGeneratedCoins) >> emissionSpeedFactor;
  // substitute [moneySupply() - ((UINT64_C(1) << emissionSpeedFactor()) - 1)] in for alreadyGeneratedCoins
  // baseReward = (moneySupply - [moneySupply - ((UINT64_C(1) << emissionSpeedFactor) - 1)]) >> emissionSpeedFactor;
  // baseReward = (moneySupply - moneySupply + (1 << emissionSpeedFactor) - 1) >> emissionSpeedFactor
  // baseReward = ((1 << emissionSpeedFactor) - 1) >> emissionSpeedFactor
  // baseReward = 0

  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(1) << m_currency.emissionSpeedFactor()) - 1);
  uint64_t expectedBlockReward = 0;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// max already generated coins
TEST_F(TestCurrency1, 17)
{
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply() - 1; // 14,999,999.99999999 coins have been generated
  uint64_t expectedBlockReward = 0;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}

// currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;
// medianBlockSize = 0;
// max already generated coins
TEST_F(TestCurrency1, 18)
{
  uint64_t alreadyGeneratedCoins = m_currency.moneySupply(); // 15,000,000 coins have been generated
  uint64_t expectedBlockReward = 0;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedBlockReward, blockReward);
  ASSERT_EQ(expectedBlockReward, emissionChange);
}


class TestCurrency2 : public ::testing::Test
{
public:
  TestCurrency2() :
    ::testing::Test(),
    m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency()) {
  }

protected:
  static const uint64_t alreadyGeneratedCoins = 0;
  static const uint64_t transactionFees = 0;

  Logging::LoggerGroup m_logger;
  CryptoNote::Currency m_currency;
};

// alreadyGeneratedCoins = 0
// median block size = 0
// current block size = TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big because it is not greater than 2X TEST_GRANTED_FULL_REWARD_ZONE
TEST_F(TestCurrency2, 1)
{
  size_t medianBlockSize = 0;
  size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;

  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
  ASSERT_EQ(emissionChange, expectedFirstBlockReward);
}

// alreadyGeneratedCoins = 0
// median block size is less than TEST_GRANTED_FULL_REWARD_ZONE
// median is set to 1 byte less than the full reward block size threshold
// current block size is still not greater than TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big because it is not greater than 2X TEST_GRANTED_FULL_REWARD_ZONE
TEST_F(TestCurrency2, 2)
{
  size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE - 1;
  size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
}

// alreadyGeneratedCoins = 0
// median block size is equal to TEST_GRANTED_FULL_REWARD_ZONE
// current block size is still not greater than TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big because it is not greater than 2X TEST_GRANTED_FULL_REWARD_ZONE
TEST_F(TestCurrency2, 3)
{
  size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
}

// alreadyGeneratedCoins = 0
// median block size is greater than TEST_GRANTED_FULL_REWARD_ZONE
// median is set to 1 byte greater than TEST_GRANTED_FULL_REWARD_ZONE
// current block size is still not greater than TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big because it is not greater than 2X median block size
TEST_F(TestCurrency2, 4)
{
  size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE + 1;
  size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
}

// alreadyGeneratedCoins = 0
// median block size is at its max of 4GB
// current block size is still not greater than TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big because it is not greater than 2X median block size
TEST_F(TestCurrency2, 5)
{
  size_t medianBlockSize = std::numeric_limits<uint32_t>::max();
  size_t currentBlockSize = 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
}

// alreadyGeneratedCoins = 0
// current block size is at its max of 4 GB
// current block size is over 2x the median block size
// median block size is less than 1/2 of current block size
// current block size is too big because it is greater than 2X median block size
// getBlockReward should return false
TEST_F(TestCurrency2, 6)
{
  size_t currentBlockSize = std::numeric_limits<uint32_t>::max();
  size_t medianBlockSize = (currentBlockSize / 2) - 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_TRUE(blockTooBig);
  ASSERT_EQ(blockReward, 0);
}

// alreadyGeneratedCoins = 0
// current block size is at its max of 4 GB
// median block size is at the max minus 1 byte
// current block size is less than 2x the median block size
// current block size is not too big because it is less than 2X median block size
TEST_F(TestCurrency2, 7)
{
  size_t currentBlockSize = std::numeric_limits<uint32_t>::max();
  size_t medianBlockSize = std::numeric_limits<uint32_t>::max() - 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;
  
  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedFirstBlockReward - 1, blockReward);
}

class TestCurrency3 : public ::testing::Test
{
public:
  TestCurrency3() :
    ::testing::Test(),
    m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency()) {
  }

protected:
  static const size_t medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
  static const uint64_t alreadyGeneratedCoins = 0;
  static const uint64_t transactionFees = 0;

  Logging::LoggerGroup m_logger;
  CryptoNote::Currency m_currency;
};

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is 0 bytes
// current block size is less than the median block size and TEST_GRANTED_FULL_REWARD_ZONE
// current block size is not too big
// miner should get full block reward
TEST_F(TestCurrency3, 1)
{
  size_t currentBlockSize = 0;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
  ASSERT_EQ(emissionChange, expectedFirstBlockReward);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is 1 byte less than the median block size
// current block size is not too big because it is not greater than 2x the median block size
// current block size is less than the median block size so miner should get full block reward
TEST_F(TestCurrency3, 2)
{
  size_t currentBlockSize = medianBlockSize - 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
  ASSERT_EQ(emissionChange, expectedFirstBlockReward);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is equal to the median block size
// current block size is not too big because it is not greater than 2x the median block size
// current block size is less than the median block size so miner should get full block reward
TEST_F(TestCurrency3, 3)
{
  size_t currentBlockSize = medianBlockSize;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(blockReward, expectedFirstBlockReward);
  ASSERT_EQ(emissionChange, expectedFirstBlockReward);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is greater than the median block size
// current block size is not too big because it is not greater than 2x the median block size
// current block size is more than the median block size so miner should get near full block reward
TEST_F(TestCurrency3, 4)
{
  size_t currentBlockSize = medianBlockSize + 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                            transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(expectedFirstBlockReward - 1, blockReward);
  ASSERT_EQ(expectedFirstBlockReward - 1, emissionChange);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is 1 byte less than 2x the median block size
// current block size is not too big because it is not greater than 2x the median block size
// current block size is almost at the max of 2x median block size so miner should get near 0 block reward
TEST_F(TestCurrency3, 5)
{
  size_t currentBlockSize = 2 * medianBlockSize - 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(2554, blockReward);
  ASSERT_EQ(2554, emissionChange);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is equal to 2x the median block size
// current block size is not too big because it is not greater than 2x the median block size
// current block size is almost at the max of 2x median block size so miner should get near 0 block reward
TEST_F(TestCurrency3, 6)
{
  size_t currentBlockSize = 2 * medianBlockSize;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_FALSE(blockTooBig);
  ASSERT_EQ(0, blockReward);
  ASSERT_EQ(0, emissionChange);
}

// medianBlockSize = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
// alreadyGeneratedCoins = 0;
// current block size is greater than 2x the median block size
// current block size is too big because it is greater than 2x the median block size
// getBlockReward will return false
TEST_F(TestCurrency3, 7)
{
  size_t currentBlockSize = 2 * medianBlockSize + 1;
  
  int64_t emissionChange = 0;
  uint64_t blockReward = 0;

  bool blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins,
                                                transactionFees, blockReward, emissionChange);
  ASSERT_TRUE(blockTooBig);
  ASSERT_EQ(blockReward, 0);
  ASSERT_EQ(emissionChange, 0);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
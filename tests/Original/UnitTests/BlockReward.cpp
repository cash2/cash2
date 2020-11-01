// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/LoggerGroup.h"

namespace
{
  TEST(getBlockReward1_and_already_generated_coins, handles_first_values) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t alreadyGeneratedCoins;
    uint64_t expectedReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;

    alreadyGeneratedCoins = 0;
    expectedReward = 70368744177663;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_blockReward;
    expectedReward = 70368475742208;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = UINT64_C(2756434948434199641);
    expectedReward = 59853779316998;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);
  }

  TEST(getBlockReward1_and_already_generated_coins, correctly_steps_from_reward_2_to_1) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t alreadyGeneratedCoins;
    uint64_t expectedReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;

    alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(2) << m_currency.emissionSpeedFactor()) + 1);
    expectedReward = 2;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply() -  (UINT64_C(2) << m_currency.emissionSpeedFactor());
    expectedReward = 2;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(2) << m_currency.emissionSpeedFactor()) - 1);
    expectedReward = 1;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);
  }

  TEST(getBlockReward1_and_already_generated_coins, handles_max_already_generaged_coins) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t alreadyGeneratedCoins;
    uint64_t expectedReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE / 2;

    alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(1) << m_currency.emissionSpeedFactor()) + 1);
    expectedReward = 1;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply() -  (UINT64_C(1) << m_currency.emissionSpeedFactor());
    expectedReward = 1;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply() - ((UINT64_C(1) << m_currency.emissionSpeedFactor()) - 1);
    expectedReward = 0;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply() - 1;
    expectedReward = 0;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);

    alreadyGeneratedCoins = m_currency.moneySupply();
    expectedReward = 0;
    m_blockTooBig = !m_currency.getBlockReward1(0, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);                                                                        \
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedReward, m_blockReward);
    ASSERT_EQ(expectedReward, m_emissionChange);
  }

//--------------------------------------------------------------------------------------------------------------------

  TEST(getBlockReward1_and_median_and_blockSize, handles_zero_median) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t medianBlockSize = 0;
    size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_median_lt_relevance_level) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE - 1;
    size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_median_eq_relevance_level) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
    size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE - 1;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_median_gt_relevance_level) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t medianBlockSize = TEST_GRANTED_FULL_REWARD_ZONE + 1;
    size_t currentBlockSize = TEST_GRANTED_FULL_REWARD_ZONE;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_big_median) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t medianBlockSize = std::numeric_limits<uint32_t>::max();
    size_t currentBlockSize = 1;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_big_block_size) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t currentBlockSize = std::numeric_limits<uint32_t>::max() - 1; // even
    size_t medianBlockSize = currentBlockSize / 2; // 2 * medianBlockSize == currentBlockSize
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(0, m_blockReward);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_big_block_size_fail) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t currentBlockSize = std::numeric_limits<uint32_t>::max();
    size_t medianBlockSize = currentBlockSize / 2 - 1;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_TRUE(m_blockTooBig);
  }

  TEST(getBlockReward1_and_median_and_blockSize, handles_big_median_and_block_size) {
    // currentBlockSize should be greater medianBlockSize

    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
        blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
        moneySupply(TEST_MONEY_SUPPLY).
        emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
        currency());

    const uint64_t alreadyGeneratedCoins = 0;
    uint64_t m_standardBlockReward;
    int64_t m_emissionChange;
    bool m_blockTooBig = !m_currency.getBlockReward1(0, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(70368744177663, m_standardBlockReward);

    size_t currentBlockSize = std::numeric_limits<uint32_t>::max();
    size_t medianBlockSize = std::numeric_limits<uint32_t>::max() - 1;
    uint64_t m_blockReward;
    m_blockTooBig = !m_currency.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_LT(m_blockReward, m_standardBlockReward);
  }

//--------------------------------------------------------------------------------------------------------------------
  
  TEST(getBlockReward1_and_currentBlockSize, handles_zero_block_size) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_less_median) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = testMedian - 1;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_eq_median) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = testMedian;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward, m_blockReward);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_gt_median) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = testMedian + 1;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_LT(m_blockReward, m_standardBlockReward);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_less_2_medians) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = 2 * testMedian - 1;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_LT(m_blockReward, m_standardBlockReward);
    ASSERT_GT(m_blockReward, 0);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_eq_2_medians) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = 2 * testMedian;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(0, m_blockReward);
  }

  TEST(getBlockReward1_and_currentBlockSize, handles_block_size_gt_2_medians) {
    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;
    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = 2 * testMedian + 1;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_TRUE(m_blockTooBig);
  }

  TEST(getBlockReward1_and_currentBlockSize, calculates_correctly) {
    // reward = 1 - (k - 1)^2
    // k = 9/8 => reward = 63/64

    const uint64_t TEST_GRANTED_FULL_REWARD_ZONE = 10000;
    const uint64_t TEST_MONEY_SUPPLY = static_cast<uint64_t>(-1);
    const uint64_t TEST_EMISSION_SPEED_FACTOR = 18;

    Logging::LoggerGroup m_logger;
    bool m_blockTooBig;
    int64_t m_emissionChange;
    uint64_t m_blockReward;
    uint64_t m_standardBlockReward;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(TEST_GRANTED_FULL_REWARD_ZONE).
      moneySupply(TEST_MONEY_SUPPLY).
      emissionSpeedFactor(TEST_EMISSION_SPEED_FACTOR).
      currency());

    const size_t testMedian = 7 * TEST_GRANTED_FULL_REWARD_ZONE;

    ASSERT_EQ(0, testMedian % 8);

    const uint64_t alreadyGeneratedCoins = 0;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, 0, alreadyGeneratedCoins, 0, m_standardBlockReward, m_emissionChange);
    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(UINT64_C(70368744177663), m_standardBlockReward);

    size_t currentBlockSize = testMedian * 9 / 8;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward * 63 / 64, m_blockReward);

    // 3/2 = 12/8
    currentBlockSize = testMedian * 3 / 2;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward * 3 / 4, m_blockReward);

    currentBlockSize = testMedian * 15 / 8;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, currentBlockSize, alreadyGeneratedCoins, 0, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(m_standardBlockReward * 15 / 64, m_blockReward);
  }

//--------------------------------------------------------------------------------------------------------------------

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_zero_fee_and_penalize_fee) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = 0;
    uint64_t fee = 0;
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, m_blockReward);
    ASSERT_EQ(expectedBlockReward, m_emissionChange);
    ASSERT_GT(m_emissionChange, 0);
  }

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_fee_lt_block_reward_and_penalize_fee) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = 0;
    uint64_t fee = expectedBlockReward / 2;
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward + fee - fee * testPenalty / 100, m_blockReward);
    ASSERT_EQ(expectedBlockReward - fee * testPenalty / 100, m_emissionChange);
    ASSERT_GT(m_emissionChange, 0);
  }

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_fee_eq_block_reward_and_penalize_fee) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = 0;
    uint64_t fee = expectedBlockReward;
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward + fee - fee * testPenalty / 100, m_blockReward);
    ASSERT_EQ(expectedBlockReward - fee * testPenalty / 100, m_emissionChange);
    ASSERT_GT(m_emissionChange, 0);
  }

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_fee_gt_block_reward_and_penalize_fee) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = 0;
    uint64_t fee = 2 * expectedBlockReward;
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward + fee - fee * testPenalty / 100, m_blockReward);
    ASSERT_EQ(expectedBlockReward - fee * testPenalty / 100, m_emissionChange);
    ASSERT_LT(m_emissionChange, 0);
  }

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_emission_change_eq_zero) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = 0;
    uint64_t fee = expectedBlockReward * 100 / testPenalty;
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward + fee - fee * testPenalty / 100, m_blockReward);
    ASSERT_EQ(0, m_emissionChange);
  }

  TEST(getBlockReward1_fee_and_penalizeFee_test, handles_fee_if_block_reward_is_zero_and_penalize_fee) {
    const unsigned int testEmissionSpeedFactor = 4;
    const size_t testGrantedFullRewardZone = 10000;
    const size_t testMedian = testGrantedFullRewardZone;
    const size_t testBlockSize = testMedian + testMedian * 8 / 10; // expected penalty 0.64 * reward
    const uint64_t testPenalty = 64; // percentage
    const uint64_t testMoneySupply = UINT64_C(1000000000);
    const uint64_t expectedBaseReward = 62500000;  // testMoneySupply >> testEmissionSpeedFactor
    const uint64_t expectedBlockReward = 22500000; // expectedBaseReward - expectedBaseReward * testPenalty / 100

    Logging::LoggerGroup m_logger;

    CryptoNote::Currency m_currency(CryptoNote::CurrencyBuilder(m_logger).
      blockGrantedFullRewardZone(testGrantedFullRewardZone).
      moneySupply(testMoneySupply).
      emissionSpeedFactor(testEmissionSpeedFactor).
      currency());

    uint64_t blockReward;
    int64_t emissionChange;

    bool m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, 0, 0, blockReward, emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(expectedBlockReward, blockReward);
    ASSERT_EQ(expectedBlockReward, emissionChange);

    uint64_t alreadyGeneratedCoins = m_currency.moneySupply();
    uint64_t fee = UINT64_C(100);
    uint64_t m_blockReward;
    int64_t m_emissionChange;
    m_blockTooBig = !m_currency.getBlockReward1(testMedian, testBlockSize, alreadyGeneratedCoins, fee, m_blockReward, m_emissionChange);

    ASSERT_FALSE(m_blockTooBig);
    ASSERT_EQ(fee - fee * testPenalty / 100, m_blockReward);
    ASSERT_EQ(-static_cast<int64_t>(fee * testPenalty / 100), m_emissionChange);
  }
}

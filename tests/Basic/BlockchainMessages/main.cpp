// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include <iostream>
#include <stdlib.h>
#include <random>

using namespace CryptoNote;

uint32_t loopCount = 1000;

// NewBlockMessage
// get()
TEST(blockchainMessages, 1)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  Crypto::Hash hashOutput;

  newBlockMessage.get(hashOutput);

  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

// NewAlternativeBlockMessage
// get()
TEST(blockchainMessages, 2)
{
  Crypto::Hash hashInput = getRandHash();

  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);

  Crypto::Hash hashOutput;

  newAlternativeBlockMessage.get(hashOutput);

  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

// ChainSwitchMessage
// get() 1
TEST(blockchainMessages, 3)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));

  std::vector<Crypto::Hash> hashesOutput;

  chainSwitchMessage.get(hashesOutput);

  ASSERT_TRUE(hashVectorsEqual(hashesInput, hashesOutput));
}

// ChainSwitchMessage
// get() 2
TEST(blockchainMessages, 4)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage1(std::move(hashesInputCopy));

  ChainSwitchMessage chainSwitchMessage2(chainSwitchMessage1);

  std::vector<Crypto::Hash> hashesOutput;

  chainSwitchMessage2.get(hashesOutput);

  ASSERT_TRUE(hashVectorsEqual(hashesInput, hashesOutput));
}

// BlockchainMessage
// NewBlockMessage
// getType()
TEST(blockchainMessages, 5)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newBlockMessage));

  BlockchainMessage::MessageType type = blockchainMessage.getType();

  ASSERT_EQ(type, BlockchainMessage::MessageType::NEW_BLOCK_MESSAGE);
}

// BlockchainMessage
// NewAlternativeBlockMessage
// getType()
TEST(blockchainMessages, 6)
{
  Crypto::Hash hashInput = getRandHash();

  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newAlternativeBlockMessage));

  BlockchainMessage::MessageType type = blockchainMessage.getType();

  ASSERT_EQ(type, BlockchainMessage::MessageType::NEW_ALTERNATIVE_BLOCK_MESSAGE);
}

// BlockchainMessage
// ChainSwitchMessage
// getType()
TEST(blockchainMessages, 7)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));

  BlockchainMessage blockchainMessage(std::move(chainSwitchMessage));

  BlockchainMessage::MessageType type = blockchainMessage.getType();

  ASSERT_EQ(type, BlockchainMessage::MessageType::CHAIN_SWITCH_MESSAGE);
}

// BlockchainMessage
// copy constructor
TEST(blockchainMessages, 8)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  BlockchainMessage blockchainMessage1(std::move(newBlockMessage));

  BlockchainMessage blockchainMessage2(blockchainMessage1);

  BlockchainMessage::MessageType type = blockchainMessage2.getType();

  ASSERT_EQ(type, BlockchainMessage::MessageType::NEW_BLOCK_MESSAGE);
}

// BlockchainMessage
// NewBlockMessage
// getNewBlockHash()
TEST(blockchainMessages, 9)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newBlockMessage));

  Crypto::Hash hashOutput;

  ASSERT_TRUE(blockchainMessage.getNewBlockHash(hashOutput));

  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

// BlockchainMessage
// NewAlternativeBlockMessage
// getNewAlternativeBlockHash()
TEST(blockchainMessages, 10)
{
  Crypto::Hash hashInput = getRandHash();

  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newAlternativeBlockMessage));

  Crypto::Hash hashOutput;

  ASSERT_TRUE(blockchainMessage.getNewAlternativeBlockHash(hashOutput));

  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

// BlockchainMessage
// ChainSwitchMessage
// getChainSwitch()
TEST(blockchainMessages, 11)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));

  BlockchainMessage blockchainMessage(std::move(chainSwitchMessage));

  std::vector<Crypto::Hash> hashesOutput;

  ASSERT_TRUE(blockchainMessage.getChainSwitch(hashesOutput));

  ASSERT_TRUE(hashVectorsEqual(hashesInput, hashesOutput));
}

// BlockchainMessage
// NewAlternativeBlockMessage
// getNewBlockHash() fail
TEST(blockchainMessages, 12)
{
  Crypto::Hash hashInput = getRandHash();

  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newAlternativeBlockMessage));

  Crypto::Hash hashOutput;

  ASSERT_FALSE(blockchainMessage.getNewBlockHash(hashOutput));
}

// BlockchainMessage
// ChainSwitchMessage
// getNewBlockHash() fail
TEST(blockchainMessages, 13)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));

  BlockchainMessage blockchainMessage(std::move(chainSwitchMessage));

  Crypto::Hash hashOutput;

  ASSERT_FALSE(blockchainMessage.getNewBlockHash(hashOutput));
}

// BlockchainMessage
// NewBlockMessage
// getNewAlternativeBlockHash() fail
TEST(blockchainMessages, 14)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newBlockMessage));

  Crypto::Hash hashOutput;

  ASSERT_FALSE(blockchainMessage.getNewAlternativeBlockHash(hashOutput));
}

// BlockchainMessage
// ChainSwitchMessage
// getNewAlternativeBlockHash() fail
TEST(blockchainMessages, 15)
{
  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; ++i)
  {
    hashesInput.push_back(getRandHash());
  }

  std::vector<Crypto::Hash> hashesInputCopy;
  hashesInputCopy = hashesInput;

  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));

  BlockchainMessage blockchainMessage(std::move(chainSwitchMessage));

  Crypto::Hash hashOutput;

  ASSERT_FALSE(blockchainMessage.getNewAlternativeBlockHash(hashOutput));
}

// BlockchainMessage
// NewBlockMessage
// getChainSwitch() fail
TEST(blockchainMessages, 16)
{
  Crypto::Hash hashInput = getRandHash();

  NewBlockMessage newBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newBlockMessage));

  std::vector<Crypto::Hash> hashesOutput;

  ASSERT_FALSE(blockchainMessage.getChainSwitch(hashesOutput));
}

// BlockchainMessage
// NewAlternativeBlockMessage
// getChainSwitch() fail
TEST(blockchainMessages, 17)
{
  Crypto::Hash hashInput = getRandHash();

  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);

  BlockchainMessage blockchainMessage(std::move(newAlternativeBlockMessage));

  std::vector<Crypto::Hash> hashesOutput;

  ASSERT_FALSE(blockchainMessage.getChainSwitch(hashesOutput));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
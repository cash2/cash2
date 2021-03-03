// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "Transfers/SynchronizationState.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "Logging/ConsoleLogger.h"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class SynchronizationState
{
public
  SynchronizationState()
  getShortHistory()
  checkInterval()
  detach()
  addBlocks()
  getHeight()
  getKnownBlockHashes()
  save()
  load()
  serialize()

private
  std::vector<Crypto::Hash> m_blockchain
}

*/

// constructor()
TEST(SynchronizationState, 1)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);
}

// getShortHistory()
TEST(SynchronizationState, 2)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  uint32_t localHeight = 0;
  SynchronizationState::ShortHistory shortHistory = state.getShortHistory(localHeight);
}

// checkInterval()
TEST(SynchronizationState, 3)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  BlockchainInterval interval;
  interval.startHeight = 0;
  interval.blocks.push_back(getRandHash());
  SynchronizationState::CheckResult check = state.checkInterval(interval);

  ASSERT_TRUE(check.detachRequired);
  ASSERT_EQ(0, check.detachHeight);
  ASSERT_FALSE(check.detachHeight);
  ASSERT_EQ(0, check.newBlockHeight);
}

// detach()
TEST(SynchronizationState, 4)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  uint32_t height = 0;
  ASSERT_NO_THROW(state.detach(height));
}

// addBlocks()
TEST(SynchronizationState, 5)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  Crypto::Hash blockHashes[5];
  blockHashes[0] = getRandHash();
  blockHashes[1] = getRandHash();
  blockHashes[2] = getRandHash();
  blockHashes[3] = getRandHash();
  blockHashes[4] = getRandHash();
  uint32_t height = state.getHeight();
  uint32_t count = sizeof(blockHashes) / sizeof(blockHashes[0]);
  ASSERT_NO_THROW(state.addBlocks(blockHashes, height, count));
}

// getHeight()
TEST(SynchronizationState, 6)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  uint32_t height = state.getHeight();
  ASSERT_EQ(1, height);

  Crypto::Hash blockHashes[5];
  blockHashes[0] = getRandHash();
  blockHashes[1] = getRandHash();
  blockHashes[2] = getRandHash();
  blockHashes[3] = getRandHash();
  blockHashes[4] = getRandHash();
  
  uint32_t count = sizeof(blockHashes) / sizeof(blockHashes[0]);
  ASSERT_NO_THROW(state.addBlocks(blockHashes, height, count));

  height = state.getHeight();
  ASSERT_EQ(6, height);
}

// getKnownBlockHashes()
TEST(SynchronizationState, 7)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  Crypto::Hash blockHashes[5];
  blockHashes[0] = getRandHash();
  blockHashes[1] = getRandHash();
  blockHashes[2] = getRandHash();
  blockHashes[3] = getRandHash();
  blockHashes[4] = getRandHash();
  
  uint32_t height = state.getHeight();
  uint32_t count = sizeof(blockHashes) / sizeof(blockHashes[0]);
  ASSERT_NO_THROW(state.addBlocks(blockHashes, height, count));

  std::vector<Crypto::Hash> blockHashesVect = state.getKnownBlockHashes();

  ASSERT_EQ(6, blockHashesVect.size());

  ASSERT_TRUE(hashesEqual(blockHashes[0], blockHashesVect[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[1], blockHashesVect[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[2], blockHashesVect[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[3], blockHashesVect[4]));
  ASSERT_TRUE(hashesEqual(blockHashes[4], blockHashesVect[5]));
}

// save()
TEST(TransfersContainer, 8)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  std::stringstream ss;

  state.save(ss);
}

// load()
TEST(TransfersContainer, 9)
{
  Crypto::Hash genesisBlockHash = getRandHash();
  SynchronizationState state = SynchronizationState (genesisBlockHash);

  std::stringstream ss;

  state.save(ss);

  state.load(ss);
}










































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
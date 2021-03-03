// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/BlockIndex.h"
#include <iostream>
#include <stdlib.h>
#include <random>

using namespace CryptoNote;

/*

My Notes

class BlockIndex {

public
  BlockIndex()
  pop()
  push()
  hasBlock()
  getBlockHeight()
  size()
  clear()
  getBlockId()
  getBlockIds()
  findSupplement()
  buildSparseChain()
  getTailId()
  serialize()

private
  typedef multi_index_container <
    Hash,
    indexed_by<
      random_access<>,
      hashed_unique<identity<Hash>>
    >
  > ContainerT;

  ContainerT m_container;
  ContainerT::nth_index<1>::type& m_index;

}

struct employee
{
  int id;
  std::string name;

  employee(int id, const std::string& name): id(id), name(name)
  {}

  bool operator<(const employee& e) const
  {
    return id < e.id;
  }
};

// define a multiple indexed set with indexes by id and name
typedef multi_index_container<
  employee,
  indexed_by<
    // sort by employee::operator<
    ordered_unique<identity<employee> >,
    
    // sort by less<string> on name
    ordered_non_unique<member<employee, std::string, &employee::name> >
  > 
> employee_set;

// Indexes are accessed via get<N>() where N ranges between 0 and the number of comparison predicates minus one

*/

// Helper functions

uint32_t loopCount = 100;

// BlockIndex
// push()
TEST(blockIndex, 1)
{
  BlockIndex blockIndex;

  Crypto::Hash hash = getRandHash();

  ASSERT_TRUE(blockIndex.push(hash));
}

// BlockIndex
// size()
TEST(blockIndex, 2)
{
  BlockIndex blockIndex;

  ASSERT_TRUE(blockIndex.size() == 0);

  Crypto::Hash hash = getRandHash();

  ASSERT_TRUE(blockIndex.push(hash));

  ASSERT_TRUE(blockIndex.size() == 1);
}

// BlockIndex
// hasBlock()
TEST(blockIndex, 3)
{
  BlockIndex blockIndex;

  Crypto::Hash hash = getRandHash();

  ASSERT_FALSE(blockIndex.hasBlock(hash));

  ASSERT_TRUE(blockIndex.push(hash));

  ASSERT_TRUE(blockIndex.hasBlock(hash));
}

// BlockIndex
// getBlockHeight()
TEST(blockIndex, 4)
{
  BlockIndex blockIndex;

  Crypto::Hash hash = getRandHash();

  uint32_t height;

  ASSERT_FALSE(blockIndex.getBlockHeight(hash, height));

  ASSERT_TRUE(blockIndex.push(hash));

  ASSERT_TRUE(blockIndex.getBlockHeight(hash, height));

  ASSERT_EQ(height, 0);
}

// BlockIndex
// pop()
TEST(blockIndex, 5)
{
  BlockIndex blockIndex;

  ASSERT_TRUE(blockIndex.size() == 0);

  Crypto::Hash hash = getRandHash();

  ASSERT_TRUE(blockIndex.push(hash));

  ASSERT_TRUE(blockIndex.size() == 1);

  blockIndex.pop();

  ASSERT_TRUE(blockIndex.size() == 0);
}

// BlockIndex
// clear()
TEST(blockIndex, 6)
{
  BlockIndex blockIndex;

  ASSERT_TRUE(blockIndex.size() == 0);

  Crypto::Hash hash = getRandHash();

  ASSERT_TRUE(blockIndex.push(hash));

  ASSERT_TRUE(blockIndex.size() == 1);

  blockIndex.clear();

  ASSERT_TRUE(blockIndex.size() == 0);
}

// BlockIndex
// getBlockId()
TEST(blockIndex, 7)
{
  BlockIndex blockIndex;

  Crypto::Hash hashInput = getRandHash();

  ASSERT_TRUE(blockIndex.push(hashInput));

  uint32_t height = 0;

  Crypto::Hash hashOutput = blockIndex.getBlockId(height);

  ASSERT_EQ(hashInput, hashOutput);
  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

// BlockIndex
// getBlockIds()
TEST(blockIndex, 8)
{
  BlockIndex blockIndex;

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; i++)
  {
    Crypto::Hash hash = getRandHash();

    hashesInput.push_back(hash);

    ASSERT_TRUE(blockIndex.push(hash));
  }

  uint32_t height = 0;

  std::vector<Crypto::Hash> hashesOutput = blockIndex.getBlockIds(height, loopCount);

  ASSERT_TRUE(hashVectorsEqual(hashesInput, hashesOutput));
}

// BlockIndex
// findSupplement()
TEST(blockIndex, 9)
{
  BlockIndex blockIndex;

  std::vector<Crypto::Hash> hashes;

  for (int i = 0; i < loopCount; i++)
  {
    Crypto::Hash hash = getRandHash();

    hashes.push_back(hash);

    ASSERT_TRUE(blockIndex.push(hash));
  }

  uint32_t randHeight = rand() % loopCount;

  // remove the first randHeight hashes from the hashes vector
  hashes.erase(hashes.begin(), hashes.begin() + randHeight);

  uint32_t height;

  ASSERT_TRUE(blockIndex.findSupplement(hashes, height));

  ASSERT_EQ(randHeight, height);
}

// BlockIndex
// buildSparseChain()
// returns a shortened version of the block indexes
// returns indexes that are powers of twos below the input height
TEST(blockIndex, 10)
{
  BlockIndex blockIndex;

  std::vector<Crypto::Hash> hashesInput;

  for (int i = 0; i < loopCount; i++)
  {
    Crypto::Hash hash = getRandHash();

    hashesInput.push_back(hash);

    ASSERT_TRUE(blockIndex.push(hash));
  }

  std::vector<Crypto::Hash> hashesOutput = blockIndex.buildSparseChain(hashesInput[loopCount - 1]);

  for (int i = 0; i < hashesOutput.size(); ++i)
  {
    ASSERT_NE(std::find(hashesInput.begin(), hashesInput.end(), hashesOutput[i]), hashesInput.end());
  }
}

// BlockIndex
// getTailId()
TEST(blockIndex, 11)
{
  BlockIndex blockIndex;

  Crypto::Hash hashInput;

  for (int i = 0; i < loopCount; i++)
  {
    hashInput = getRandHash();

    ASSERT_TRUE(blockIndex.push(hashInput));
  }

  Crypto::Hash hashOutput = blockIndex.getTailId();

  // hashInput contains the last hash pushed onto blockIndex
  ASSERT_EQ(hashInput, hashOutput);

  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
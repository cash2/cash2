// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/BlockingQueue.h"

/*

My Notes

class BlockingQueue
public
  BlockingQueue()
  push()
  pop()
  close()
  size()
  capacity()

*/

// constructor 1
TEST(BlockingQueue, 1)
{
  BlockingQueue<int>();
}

// constructor 2
TEST(BlockingQueue, 2)
{
  size_t queueSize = 10;
  BlockingQueue<int> blockcingQueue(queueSize);// for some reason need blockQueue here
}

// push()
TEST(BlockingQueue, 3)
{
  size_t queueSize = 1;
  BlockingQueue<int> blockingQueue(queueSize);

  int i = 5;
  ASSERT_TRUE(blockingQueue.push(i));
}

// pop()
TEST(BlockingQueue, 4)
{
  size_t queueSize = 1;
  BlockingQueue<int> blockingQueue(queueSize);

  int i = 5;
  ASSERT_TRUE(blockingQueue.push(i));

  ASSERT_TRUE(blockingQueue.pop(i));
}

// close
TEST(BlockingQueue, 5)
{
  size_t queueSize = 1;
  BlockingQueue<int> blockingQueue(queueSize);

  blockingQueue.close();

  int i = 5;
  ASSERT_FALSE(blockingQueue.push(i));

  ASSERT_FALSE(blockingQueue.pop(i));
}

// size()
TEST(BlockingQueue, 6)
{
  size_t queueSize = 1;
  BlockingQueue<int> blockingQueue(queueSize);

  ASSERT_EQ(0, blockingQueue.size());

  int i = 5;
  ASSERT_TRUE(blockingQueue.push(i));

  ASSERT_EQ(1, blockingQueue.size());

  ASSERT_TRUE(blockingQueue.pop(i));

  ASSERT_EQ(0, blockingQueue.size());
}

// capacity()
TEST(BlockingQueue, 7)
{
  size_t queueSize = 10;
  BlockingQueue<int> blockingQueue(queueSize);

  ASSERT_EQ(queueSize, blockingQueue.capacity());
}































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

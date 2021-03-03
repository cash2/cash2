// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/MemoryInputStream.h"

using namespace Common;

/*

MyNotes

class MemoryInputStream
public
  MemoryInputStream()
  getPosition()
  endOfStream()
  readSome()

*/

// MemoryInputStream()
TEST(MemoryInputStream, 1)
{
  std::string myStr = "Hello World";
  MemoryInputStream(myStr.data(), myStr.size());
}

// readSome()
TEST(MemoryInputStream, 2)
{
  std::string myStr = "Hello World";
  MemoryInputStream stream(myStr.data(), myStr.size());

  // pointer must not start at &myStr
  // size > 8 causes stack smashing error
  size_t read = stream.readSome(&myStr + 1, 8);

  ASSERT_EQ(8, read);
}

// getPosition()
TEST(MemoryInputStream, 3)
{
  std::string myStr = "Hello World";
  MemoryInputStream stream(myStr.data(), myStr.size());

  size_t position = stream.getPosition();
  ASSERT_EQ(0, position);

  stream.readSome(&myStr + 1, 1);
  ASSERT_EQ(1, stream.getPosition());

  stream.readSome(&myStr + 1, 1);
  ASSERT_EQ(2, stream.getPosition());

  stream.readSome(&myStr + 1, 1);
  ASSERT_EQ(3, stream.getPosition());

  stream.readSome(&myStr + 1, 1);
  ASSERT_EQ(4, stream.getPosition());

  stream.readSome(&myStr + 1, 1);
  ASSERT_EQ(5, stream.getPosition());
}

// endOfStream()
TEST(MemoryInputStream, 4)
{
  std::string myStr = "Hello World";
  MemoryInputStream stream(myStr.data(), myStr.size());

  stream.readSome(&myStr + 1, 8);
  ASSERT_FALSE(stream.endOfStream());

  stream.readSome(&myStr + 1, 3);
  ASSERT_TRUE(stream.endOfStream()); // true because 8 + 3 = 11
}





































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/VectorOutputStream.h>
#include <gtest/gtest.h>

using namespace Common;

// constructor
TEST(VectorOutputStream, 1)
{
  std::vector<uint8_t> out;
  VectorOutputStream stream(out);
}

// writeSome()
TEST(VectorOutputStream, 2)
{
  std::vector<uint8_t> out;
  VectorOutputStream stream(out);

  char data[] = "Hello World";
  size_t size = 12;
  size_t wrote = stream.writeSome(data, size);

  ASSERT_EQ(12, wrote);
}














































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
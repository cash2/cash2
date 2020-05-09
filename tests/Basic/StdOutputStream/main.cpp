// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/StdOutputStream.h>
#include <gtest/gtest.h>

using namespace Common;

// constructor
TEST(StdOutputStream, 1)
{
  std::string str = "Hello World";
  std::stringstream ss(str);
  StdOutputStream os(ss);
}

// writeSome
TEST(StdOutputStream, 2)
{
  std::string str = "Hello World";
  std::stringstream ss(str);
  StdOutputStream os(ss);

  size_t size = 1; // size 1 - 9300 works
  size_t wrote = os.writeSome(&ss, size);
  ASSERT_EQ(size, wrote);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
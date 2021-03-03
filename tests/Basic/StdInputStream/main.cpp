// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/StdInputStream.h>
#include <gtest/gtest.h>

using namespace Common;

// constructor
TEST(StdInputStream, 1)
{
  std::stringstream ss;
  StdInputStream is(ss);
}

// readSome()
TEST(StdInputStream, 2)
{
  std::string str = "Hello World";
  std::stringstream ss(str);
  StdInputStream is(ss);

  const size_t size = 1; // size can be 1 - 11
  size_t read = is.readSome(&ss, size); 
  ASSERT_EQ(size, read);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
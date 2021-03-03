// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/Math.h"

using namespace Common;

// median(int)
TEST(Math, 1)
{
  std::vector<int> intVect = {1, 2, 3, 4, 5};
  int median = medianValue(intVect);

  ASSERT_EQ(3, median);
}

// median(char)
TEST(Math, 2)
{
  std::vector<char> charVect = {'a', 'b', 'c', 'd', 'e'};
  char median = medianValue(charVect);

  ASSERT_EQ('c', median);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

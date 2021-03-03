// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/ConsoleTools.h"

using namespace Common;
using namespace Console;

// setTextColor()
TEST(ConsoleTools, 1)
{
  setTextColor(Color::Blue);
}

// isConsoleTty()
TEST(ConsoleTools, 2)
{
  ASSERT_TRUE(isConsoleTty());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

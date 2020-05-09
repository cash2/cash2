// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/ConsoleLogger.h"

using namespace Logging;

// constructor
TEST(ConsoleLogger, 1)
{
  ConsoleLogger logger1;

  Level level = Level::DEBUGGING;
  ConsoleLogger logger2(level);

  ConsoleLogger logger3(Level::FATAL);
  ConsoleLogger logger4(Level::ERROR);
  ConsoleLogger logger5(Level::WARNING);
  ConsoleLogger logger6(Level::INFO);
  ConsoleLogger logger7(Level::TRACE);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
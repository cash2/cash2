// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/LoggerMessage.h"
#include "Logging/ConsoleLogger.h"

using namespace Logging;

// constructor
TEST(LoggerMessage, 1)
{
  ConsoleLogger logger;
  std::string category = "myCategory";
  Level level = Level::DEBUGGING;
  std::string color = "green";
  LoggerMessage(logger, category, level, color);
}

// constructor
TEST(LoggerMessage, 2)
{
  ConsoleLogger logger;
  std::string category = "myCategory";
  Level level = Level::DEBUGGING;
  std::string color = "green";
  LoggerMessage loggerMessage1(logger, category, level, color);

  LoggerMessage loggerMessage2(std::move(loggerMessage1));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
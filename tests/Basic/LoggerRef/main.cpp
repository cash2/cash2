// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/LoggerRef.h"
#include "Logging/ConsoleLogger.h"

using namespace Logging;

// constructor
TEST(LoggerRef, 1)
{
  ConsoleLogger logger;
  std::string category = "myCategory";
  LoggerRef(logger, category);
}

// operator()
TEST(LoggerRef, 2)
{
  ConsoleLogger logger;
  std::string category = "myCategory";
  LoggerRef loggerRef(logger, category);

  Level level = Level::DEBUGGING;
  std::string color = "green";
  LoggerMessage loggerMessage = loggerRef(level, color);
}

// getLogger()
TEST(LoggerRef, 3)
{
  ConsoleLogger logger;
  std::string category = "myCategory";
  LoggerRef loggerRef(logger, category);

  ILogger& loggerRet = loggerRef.getLogger();
}


int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
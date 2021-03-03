// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/ConsoleLogger.h"
#include "Logging/FileLogger.h"
#include "Logging/LoggerGroup.h"
#include "boost/date_time/posix_time/posix_time.hpp"

using namespace Logging;

// constructor
TEST(LoggerGroup, 1)
{
  LoggerGroup logger1;

  Level level = Level::DEBUGGING;
  LoggerGroup logger2(level);

  LoggerGroup logger3(Level::FATAL);
  LoggerGroup logger4(Level::ERROR);
  LoggerGroup logger5(Level::WARNING);
  LoggerGroup logger6(Level::INFO);
  LoggerGroup logger7(Level::TRACE);
}

// addLogger
TEST(LoggerGroup, 2)
{
  FileLogger f;
  ConsoleLogger c;

  LoggerGroup loggerGroup;

  loggerGroup.addLogger(f);
  loggerGroup.addLogger(c);
}

// removeLogger
TEST(LoggerGroup, 3)
{
  FileLogger f;
  ConsoleLogger c;

  LoggerGroup loggerGroup;

  loggerGroup.addLogger(f);
  loggerGroup.addLogger(c);

  loggerGroup.removeLogger(f);
  loggerGroup.removeLogger(c);
}

// operator()
TEST(LoggerGroup, 4)
{
  FileLogger f;
  ConsoleLogger c;

  LoggerGroup loggerGroup(Level::TRACE);

  loggerGroup.addLogger(f);
  loggerGroup.addLogger(c);

  std::string category = "myCategory";
  Level level = Level::DEBUGGING;
  std::string ts("2002-01-20 23:59:59.000");
  boost::posix_time::ptime time(boost::posix_time::time_from_string(ts));
  std::string body = "myBody";
  loggerGroup(category, level, time, body);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
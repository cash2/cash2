// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/LoggerManager.h"
#include "Logging/ConsoleLogger.h"
#include "Logging/FileLogger.h"
#include "Logging/LoggerGroup.h"
#include "Common/JsonValue.h"
#include "boost/date_time/posix_time/posix_time.hpp"

using namespace Logging;
using namespace Common;

// constructor
TEST(LoggerManager, 1)
{
  LoggerManager();
}

// configure
TEST(LoggerManager, 2)
{
  LoggerManager loggerManager;

  JsonValue jsonValue1a = "console";

  JsonValue::Object object1;
  object1.emplace("type", jsonValue1a);

  JsonValue jsonValue1b(object1);
  JsonValue jsonValue1c(object1);
  JsonValue jsonValue1d(object1);

  JsonValue::Array arr = {jsonValue1b, jsonValue1c, jsonValue1d};
  
  JsonValue jsonValue1(arr);

  JsonValue::Object object2;
  object2.emplace("loggers", jsonValue1);

  JsonValue jsonValue2(object2);
  
  loggerManager.configure(jsonValue2);
}

// operator()
TEST(LoggerManager, 3)
{
  LoggerManager logger;

  std::string category = "myCategory";
  Level level = Level::DEBUGGING;
  std::string ts("2002-01-20 23:59:59.000");
  boost::posix_time::ptime time(boost::posix_time::time_from_string(ts));
  std::string body = "myBody";
  logger(category, level, time, body);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Logging/StreamLogger.h"

using namespace Logging;

// constructor
TEST(StreamLogger, 1)
{
  Level level = Level::DEBUGGING;
  StreamLogger logger2(level);

  StreamLogger logger3(Level::FATAL);
  StreamLogger logger4(Level::ERROR);
  StreamLogger logger5(Level::WARNING);
  StreamLogger logger6(Level::INFO);
  StreamLogger logger7(Level::TRACE);
}

// constructor
TEST(StreamLogger, 2)
{
  std::stringstream stream;

  Level level = Level::DEBUGGING;
  StreamLogger logger2(stream, level);

  StreamLogger logger3(stream, Level::FATAL);
  StreamLogger logger4(stream, Level::ERROR);
  StreamLogger logger5(stream, Level::WARNING);
  StreamLogger logger6(stream, Level::INFO);
  StreamLogger logger7(stream, Level::TRACE);
}

// attachToStream()
TEST(StreamLogger, 3)
{
  Level level = Level::DEBUGGING;
  StreamLogger logger(level);

  std::stringstream stream;

  logger.attachToStream(stream);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
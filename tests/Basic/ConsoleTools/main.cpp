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
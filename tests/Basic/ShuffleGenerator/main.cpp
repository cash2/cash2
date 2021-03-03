// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/ShuffleGenerator.h>
#include <gtest/gtest.h>

/*

MyNotes

class ShuffleGenerator
public
  ShuffleGenerator()
  operator()
  reset()

*/

// constructor
TEST(ShuffleGenerator, 1)
{
  int i = 5;
  std::default_random_engine engine;
  ShuffleGenerator<int, std::default_random_engine>(i, engine);
}

// operator()
TEST(ShuffleGenerator, 2)
{
  int i = 5;
  std::default_random_engine engine;
  ShuffleGenerator<int, std::default_random_engine> shuffleGenerator(i, engine);

  int result = shuffleGenerator();
  ASSERT_EQ(0, result);

  ASSERT_EQ(4, shuffleGenerator());
  ASSERT_EQ(2, shuffleGenerator());
  ASSERT_EQ(3, shuffleGenerator());
  ASSERT_EQ(1, shuffleGenerator());

}

// reset()
TEST(ShuffleGenerator, 3)
{
  int i = 5;
  std::default_random_engine engine;
  ShuffleGenerator<int, std::default_random_engine> shuffleGenerator(i, engine);

  ASSERT_EQ(0, shuffleGenerator());
  ASSERT_EQ(4, shuffleGenerator());
  ASSERT_EQ(2, shuffleGenerator());
  ASSERT_EQ(3, shuffleGenerator());
  ASSERT_EQ(1, shuffleGenerator());

  shuffleGenerator.reset();

  ASSERT_EQ(1, shuffleGenerator());
  ASSERT_EQ(0, shuffleGenerator());
  ASSERT_EQ(2, shuffleGenerator());
  ASSERT_EQ(4, shuffleGenerator());
  ASSERT_EQ(3, shuffleGenerator());

  shuffleGenerator.reset();

  ASSERT_EQ(1, shuffleGenerator());
  ASSERT_EQ(2, shuffleGenerator());
  ASSERT_EQ(3, shuffleGenerator());
  ASSERT_EQ(0, shuffleGenerator());
  ASSERT_EQ(4, shuffleGenerator());
}

























































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
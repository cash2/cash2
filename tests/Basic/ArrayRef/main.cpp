// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/ArrayRef.h>
#include <gtest/gtest.h>

/*

MyNotes

class ArrayRef
public
  ArrayRef()
  ArrayRef()
  ArrayRef()
  ArrayRef()
  operator=()
  operator()
  getData()
  getSize()
  isEmpty()
  isNil()
  operator[]()
  first()
  last()
  begin()
  end()
  operator==()
  operator!=()
  beginsWith()
  beginsWith()
  contains()
  contains()
  endsWith()
  endsWith()
  find()
  find()
  findLast()
  findLast()
  head()
  tail()
  unhead()
  untail()
  range()
  slice()
  fill()
  reverse()

*/

using namespace Common;

// ArrayRef()
TEST(ArrayRef, 1)
{
  ArrayRef<>();
}

// ArrayRef()
TEST(ArrayRef, 2)
{
  uint8_t data[4] = {1, 2, 3, 4};
  size_t dataSize = sizeof(data)/sizeof(data[0]);
  
  ArrayRef<>(data, dataSize);
}

// ArrayRef()
TEST(ArrayRef, 3)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref(data);
}

// ArrayRef()
TEST(ArrayRef, 4)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref1(data);

  ArrayRef<> ref2(ref1);
}

// operator=()
TEST(ArrayRef, 5)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1;
}

// ArrayView
TEST(ArrayRef, 6)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref(data);

  ArrayView<> view = ref;

  ASSERT_EQ(data, ref.getData());
  ASSERT_EQ(data, view.getData());
  ASSERT_EQ(4, ref.getSize());
  ASSERT_EQ(4, view.getSize());
}

// getData()
TEST(ArrayRef, 7)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref1(data);

  const unsigned char* dataRet = ref1.getData();

  ASSERT_EQ(data, dataRet);
}

// getSize()
TEST(ArrayRef, 8)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayRef<> ref1(data);

  size_t size = ref1.getSize();

  ASSERT_EQ(4, size);
}

// isEmpty()
TEST(ArrayRef, 9)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(data, 0);

  ASSERT_FALSE(ref1.isEmpty());
  ASSERT_TRUE(ref2.isEmpty());
}

// isNil()
TEST(ArrayRef, 10)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(nullptr, 0);

  ASSERT_FALSE(ref1.isNil());
  ASSERT_TRUE(ref2.isNil());
}

// operator[]()
TEST(ArrayRef, 11)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(1, ref[0]);
  ASSERT_EQ(2, ref[1]);
  ASSERT_EQ(3, ref[2]);
  ASSERT_EQ(4, ref[3]);
}

// first()
TEST(ArrayRef, 12)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(1, ref.first());
}

// last()
TEST(ArrayRef, 13)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(4, ref.last());
}

// begin()
TEST(ArrayRef, 14)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(data, ref.begin());
}

// end()
TEST(ArrayRef, 15)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(data + 4, ref.end());
}

// operator==()
TEST(ArrayRef, 16)
{
  uint8_t data1[4] = {1, 2, 3, 4};
  ArrayRef<> ref1a(data1);
  ArrayRef<> ref1b(data1);

  uint8_t data2[4] = {4, 3, 2, 1};
  ArrayRef<> ref2a(data2);
  ArrayRef<> ref2b(data2);

  ASSERT_TRUE(ref1a == ref1b);
  ASSERT_TRUE(ref2a == ref2b);
  ASSERT_FALSE(ref1a == ref2b);
  ASSERT_FALSE(ref2a == ref1b);
}

// operator!=()
TEST(ArrayRef, 17)
{
  uint8_t data1[4] = {1, 2, 3, 4};
  ArrayRef<> ref1a(data1);
  ArrayRef<> ref1b(data1);

  uint8_t data2[4] = {4, 3, 2, 1};
  ArrayRef<> ref2a(data2);
  ArrayRef<> ref2b(data2);

  ASSERT_FALSE(ref1a != ref1b);
  ASSERT_FALSE(ref2a != ref2b);
  ASSERT_TRUE(ref1a != ref2b);
  ASSERT_TRUE(ref2a != ref1b);
}

// beginsWith()
TEST(ArrayRef, 18)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_TRUE(ref.beginsWith(1));
  ASSERT_FALSE(ref.beginsWith(2));
  ASSERT_FALSE(ref.beginsWith(3));
  ASSERT_FALSE(ref.beginsWith(4));
}

// beginsWith()
TEST(ArrayRef, 19)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(data);

  ASSERT_TRUE(ref1.beginsWith(ref2));
}

// contains()
TEST(ArrayRef, 20)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_TRUE(ref.contains(1));
  ASSERT_TRUE(ref.contains(2));
  ASSERT_TRUE(ref.contains(3));
  ASSERT_TRUE(ref.contains(4));
}

// contains()
TEST(ArrayRef, 21)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(data);

  ASSERT_TRUE(ref1.contains(ref2));
}

// endsWith()
TEST(ArrayRef, 22)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_FALSE(ref.endsWith(1));
  ASSERT_FALSE(ref.endsWith(2));
  ASSERT_FALSE(ref.endsWith(3));
  ASSERT_TRUE(ref.endsWith(4));
}

// endsWith()
TEST(ArrayRef, 23)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(data);

  ASSERT_TRUE(ref1.endsWith(ref2));
}

// find()
TEST(ArrayRef, 24)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(0, ref.find(1));
  ASSERT_EQ(1, ref.find(2));
  ASSERT_EQ(2, ref.find(3));
  ASSERT_EQ(3, ref.find(4));
}

// find()
TEST(ArrayRef, 25)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);
  ArrayRef<> ref2(data);

  ASSERT_EQ(0, ref1.find(ref2));
}

// findLast()
TEST(ArrayRef, 26)
{
  uint8_t data[8] = {1, 2, 3, 4, 1, 2, 3, 4};
  ArrayRef<> ref(data);

  ASSERT_EQ(4, ref.findLast(1));
  ASSERT_EQ(5, ref.findLast(2));
  ASSERT_EQ(6, ref.findLast(3));
  ASSERT_EQ(7, ref.findLast(4));
}

// findLast()
TEST(ArrayRef, 27)
{
  uint8_t data1[8] = {1, 2, 3, 4, 1, 2, 3, 4};
  ArrayRef<> ref1(data1);

  uint8_t data2[4] = {1, 2, 3, 4};
  ArrayRef<> ref2(data2);

  ASSERT_EQ(4, ref1.findLast(ref2));
}

// head()
TEST(ArrayRef, 28)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.head(1);
  ASSERT_EQ(1, ref2.getSize());
  ASSERT_EQ(1, ref2[0]);

  ArrayRef<> ref3 = ref1.head(4);
  ASSERT_EQ(4, ref3.getSize());
  ASSERT_EQ(1, ref3[0]);
  ASSERT_EQ(2, ref3[1]);
  ASSERT_EQ(3, ref3[2]);
  ASSERT_EQ(4, ref3[3]);
}

// tail()
TEST(ArrayRef, 29)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.tail(1);
  ASSERT_EQ(1, ref2.getSize());
  ASSERT_EQ(4, ref2[0]);

  ArrayRef<> ref3 = ref1.head(3);
  ASSERT_EQ(3, ref3.getSize());
  ASSERT_EQ(1, ref3[0]);
  ASSERT_EQ(2, ref3[1]);
  ASSERT_EQ(3, ref3[2]);
}

// unhead()
TEST(ArrayRef, 30)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.unhead(1);
  ASSERT_EQ(3, ref2.getSize());
  ASSERT_EQ(2, ref2[0]);
  ASSERT_EQ(3, ref2[1]);
  ASSERT_EQ(4, ref2[2]);

  ArrayRef<> ref3 = ref1.unhead(4);
  ASSERT_EQ(0, ref3.getSize());
}

// untail()
TEST(ArrayRef, 31)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.untail(1);
  ASSERT_EQ(3, ref2.getSize());
  ASSERT_EQ(1, ref2[0]);
  ASSERT_EQ(2, ref2[1]);
  ASSERT_EQ(3, ref2[2]);

  ArrayRef<> ref3 = ref1.untail(3);
  ASSERT_EQ(1, ref3.getSize());
  ASSERT_EQ(1, ref3[0]);
}

// range()
TEST(ArrayRef, 32)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.range(1, 2);
  ASSERT_EQ(1, ref2.getSize());
  ASSERT_EQ(2, ref2[0]);

  ref2 = ref1.range(1, 4);
  ASSERT_EQ(3, ref2.getSize());
  ASSERT_EQ(2, ref2[0]);
  ASSERT_EQ(3, ref2[1]);
  ASSERT_EQ(4, ref2[2]);
}

// slice()
TEST(ArrayRef, 33)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref1(data);

  ArrayRef<> ref2 = ref1.slice(1, 2);
  ASSERT_EQ(2, ref2.getSize());
  ASSERT_EQ(2, ref2[0]);
  ASSERT_EQ(3, ref2[1]);

  ref2 = ref1.slice(1, 3);
  ASSERT_EQ(3, ref2.getSize());
  ASSERT_EQ(2, ref2[0]);
  ASSERT_EQ(3, ref2[1]);
  ASSERT_EQ(4, ref2[2]);
}

// fill()
TEST(ArrayRef, 34)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ref.fill(5);

  ASSERT_EQ(5, ref[0]);
  ASSERT_EQ(5, ref[1]);
  ASSERT_EQ(5, ref[2]);
  ASSERT_EQ(5, ref[3]);
}

// reverse()
TEST(ArrayRef, 35)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayRef<> ref(data);

  ref.reverse();

  ASSERT_EQ(4, ref[0]);
  ASSERT_EQ(3, ref[1]);
  ASSERT_EQ(2, ref[2]);
  ASSERT_EQ(1, ref[3]);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
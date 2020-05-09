// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/ArrayView.h>
#include <gtest/gtest.h>

/*

MyNotes

class ArrayView
public
  ArrayView()
  ArrayView()
  ArrayView()
  ArrayView()
  ~ArrayView()
  operator=()
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

*/

using namespace Common;

// ArrayView()
TEST(ArrayView, 1)
{
  ArrayView<>();
}

// ArrayView()
TEST(ArrayView, 2)
{
  uint8_t data[4] = {1, 2, 3, 4};
  size_t dataSize = sizeof(data)/sizeof(data[0]);
  
  ArrayView<>(data, dataSize);
}

// ArrayView()
TEST(ArrayView, 3)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayView<> view(data);
}

// ArrayView()
TEST(ArrayView, 4)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayView<> view1(data);

  ArrayView<> view2(view1);
}

// operator=()
TEST(ArrayView, 5)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayView<> view1(data);

  ArrayView<> view2 = view1;
}

// getData()
TEST(ArrayView, 6)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayView<> view1(data);

  const unsigned char* dataRet = view1.getData();

  ASSERT_EQ(data, dataRet);
}

// getSize()
TEST(ArrayView, 7)
{
  uint8_t data[4] = {1, 2, 3, 4};
  
  ArrayView<> view1(data);

  size_t size = view1.getSize();

  ASSERT_EQ(4, size);
}

// isEmpty()
TEST(ArrayView, 8)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(data, 0);

  ASSERT_FALSE(view1.isEmpty());
  ASSERT_TRUE(view2.isEmpty());
}

// isNil()
TEST(ArrayView, 9)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(nullptr, 0);

  ASSERT_FALSE(view1.isNil());
  ASSERT_TRUE(view2.isNil());
}

// operator[]()
TEST(ArrayView, 10)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(1, view[0]);
  ASSERT_EQ(2, view[1]);
  ASSERT_EQ(3, view[2]);
  ASSERT_EQ(4, view[3]);
}

// first()
TEST(ArrayView, 11)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(1, view.first());
}

// last()
TEST(ArrayView, 12)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(4, view.last());
}

// begin()
TEST(ArrayView, 13)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(data, view.begin());
}

// end()
TEST(ArrayView, 14)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(data + 4, view.end());
}

// operator==()
TEST(ArrayView, 15)
{
  uint8_t data1[4] = {1, 2, 3, 4};
  ArrayView<> view1a(data1);
  ArrayView<> view1b(data1);

  uint8_t data2[4] = {4, 3, 2, 1};
  ArrayView<> view2a(data2);
  ArrayView<> view2b(data2);

  ASSERT_TRUE(view1a == view1b);
  ASSERT_TRUE(view2a == view2b);
  ASSERT_FALSE(view1a == view2b);
  ASSERT_FALSE(view2a == view1b);
}

// operator!=()
TEST(ArrayView, 16)
{
  uint8_t data1[4] = {1, 2, 3, 4};
  ArrayView<> view1a(data1);
  ArrayView<> view1b(data1);

  uint8_t data2[4] = {4, 3, 2, 1};
  ArrayView<> view2a(data2);
  ArrayView<> view2b(data2);

  ASSERT_FALSE(view1a != view1b);
  ASSERT_FALSE(view2a != view2b);
  ASSERT_TRUE(view1a != view2b);
  ASSERT_TRUE(view2a != view1b);
}

// beginsWith()
TEST(ArrayView, 17)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_TRUE(view.beginsWith(1));
  ASSERT_FALSE(view.beginsWith(2));
  ASSERT_FALSE(view.beginsWith(3));
  ASSERT_FALSE(view.beginsWith(4));
}

// beginsWith()
TEST(ArrayView, 18)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(data);

  ASSERT_TRUE(view1.beginsWith(view2));
}

// contains()
TEST(ArrayView, 19)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_TRUE(view.contains(1));
  ASSERT_TRUE(view.contains(2));
  ASSERT_TRUE(view.contains(3));
  ASSERT_TRUE(view.contains(4));
}

// contains()
TEST(ArrayView, 20)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(data);

  ASSERT_TRUE(view1.contains(view2));
}

// endsWith()
TEST(ArrayView, 21)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_FALSE(view.endsWith(1));
  ASSERT_FALSE(view.endsWith(2));
  ASSERT_FALSE(view.endsWith(3));
  ASSERT_TRUE(view.endsWith(4));
}

// endsWith()
TEST(ArrayView, 22)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(data);

  ASSERT_TRUE(view1.endsWith(view2));
}

// find()
TEST(ArrayView, 23)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(0, view.find(1));
  ASSERT_EQ(1, view.find(2));
  ASSERT_EQ(2, view.find(3));
  ASSERT_EQ(3, view.find(4));
}

// find()
TEST(ArrayView, 24)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);
  ArrayView<> view2(data);

  ASSERT_EQ(0, view1.find(view2));
}

// findLast()
TEST(ArrayView, 25)
{
  uint8_t data[8] = {1, 2, 3, 4, 1, 2, 3, 4};
  ArrayView<> view(data);

  ASSERT_EQ(4, view.findLast(1));
  ASSERT_EQ(5, view.findLast(2));
  ASSERT_EQ(6, view.findLast(3));
  ASSERT_EQ(7, view.findLast(4));
}

// findLast()
TEST(ArrayView, 26)
{
  uint8_t data1[8] = {1, 2, 3, 4, 1, 2, 3, 4};
  ArrayView<> view1(data1);

  uint8_t data2[4] = {1, 2, 3, 4};
  ArrayView<> view2(data2);

  ASSERT_EQ(4, view1.findLast(view2));
}

// head()
TEST(ArrayView, 27)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.head(1);
  ASSERT_EQ(1, view2.getSize());
  ASSERT_EQ(1, view2[0]);

  ArrayView<> view3 = view1.head(4);
  ASSERT_EQ(4, view3.getSize());
  ASSERT_EQ(1, view3[0]);
  ASSERT_EQ(2, view3[1]);
  ASSERT_EQ(3, view3[2]);
  ASSERT_EQ(4, view3[3]);
}

// tail()
TEST(ArrayView, 28)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.tail(1);
  ASSERT_EQ(1, view2.getSize());
  ASSERT_EQ(4, view2[0]);

  ArrayView<> view3 = view1.head(3);
  ASSERT_EQ(3, view3.getSize());
  ASSERT_EQ(1, view3[0]);
  ASSERT_EQ(2, view3[1]);
  ASSERT_EQ(3, view3[2]);
}

// unhead()
TEST(ArrayView, 29)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.unhead(1);
  ASSERT_EQ(3, view2.getSize());
  ASSERT_EQ(2, view2[0]);
  ASSERT_EQ(3, view2[1]);
  ASSERT_EQ(4, view2[2]);

  ArrayView<> view3 = view1.unhead(4);
  ASSERT_EQ(0, view3.getSize());
}

// untail()
TEST(ArrayView, 30)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.untail(1);
  ASSERT_EQ(3, view2.getSize());
  ASSERT_EQ(1, view2[0]);
  ASSERT_EQ(2, view2[1]);
  ASSERT_EQ(3, view2[2]);

  ArrayView<> view3 = view1.untail(3);
  ASSERT_EQ(1, view3.getSize());
  ASSERT_EQ(1, view3[0]);
}

// range()
TEST(ArrayView, 31)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.range(1, 2);
  ASSERT_EQ(1, view2.getSize());
  ASSERT_EQ(2, view2[0]);

  view2 = view1.range(1, 4);
  ASSERT_EQ(3, view2.getSize());
  ASSERT_EQ(2, view2[0]);
  ASSERT_EQ(3, view2[1]);
  ASSERT_EQ(4, view2[2]);
}

// slice()
TEST(ArrayView, 32)
{
  uint8_t data[4] = {1, 2, 3, 4};
  ArrayView<> view1(data);

  ArrayView<> view2 = view1.slice(1, 2);
  ASSERT_EQ(2, view2.getSize());
  ASSERT_EQ(2, view2[0]);
  ASSERT_EQ(3, view2[1]);

  view2 = view1.slice(1, 3);
  ASSERT_EQ(3, view2.getSize());
  ASSERT_EQ(2, view2[0]);
  ASSERT_EQ(3, view2[1]);
  ASSERT_EQ(4, view2[2]);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
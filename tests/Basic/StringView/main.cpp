// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/StringView.h>
#include <gtest/gtest.h>

/*

MyNotes

class StringView
public
  StringView()
  StringView()
  StringView()
  StringView()
  StringView()
  ~StringView()
  operator=()
  std::string()
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
  operator<()
  operator<=()
  operator>()
  operator>=()
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

// StringView()
TEST(StringView, 1)
{
  StringView();
}

// StringView()
TEST(StringView, 2)
{
  char data[] = "Hello World";
  StringView(data, 12);
}

// StringView()
TEST(StringView, 3)
{
  char data[] = "Hello World";
  StringView stringView(data);
}

// StringView()
TEST(StringView, 4)
{
  std::string str = "Hello World";
  StringView stringView(str);
}

// StringView()
TEST(StringView, 5)
{
  StringView stringView1("Hello World"); 
  StringView stringView2(stringView1);
}

// operator=()
TEST(StringView, 6)
{
  StringView stringView1("Hello World");  
  StringView stringView2 = stringView1;
}

// operator=()
TEST(StringView, 7)
{
  std::string str1 = "Hello World";
  StringView stringView(str1);
  
  std::string str2 = (std::string)stringView;

  ASSERT_EQ(str1, str2);
}

// getData()
TEST(StringView, 8)
{
  char data[] = "Hello World";
  StringView stringView(data);
  const char* dataRet = stringView.getData();

  ASSERT_EQ(data, dataRet);
}

// getSize()
TEST(StringView, 9)
{
  StringView stringView("Hello World");
  size_t size = stringView.getSize();
  ASSERT_EQ(11, size);
}

// isEmpty()
TEST(StringView, 10)
{
  StringView stringView("Hello World");
  ASSERT_FALSE(stringView.isEmpty());
}

// isNil()
TEST(StringView, 11)
{
  StringView stringView("Hello World");
  ASSERT_FALSE(stringView.isNil());
}

// operator[]()
TEST(StringView, 12)
{
  StringView stringView("Hello World");

  ASSERT_EQ('H', stringView[0]);
  ASSERT_EQ('e', stringView[1]);
  ASSERT_EQ('l', stringView[2]);
  ASSERT_EQ('l', stringView[3]);
  ASSERT_EQ('o', stringView[4]);
  ASSERT_EQ(' ', stringView[5]);
  ASSERT_EQ('W', stringView[6]);
  ASSERT_EQ('o', stringView[7]);
  ASSERT_EQ('r', stringView[8]);
  ASSERT_EQ('l', stringView[9]);
  ASSERT_EQ('d', stringView[10]);
}

// first()
TEST(StringView, 13)
{
  StringView stringView("Hello World");
  ASSERT_EQ('H', stringView.first());
}

// last()
TEST(StringView, 14)
{
  StringView stringView("Hello World");
  ASSERT_EQ('d', stringView.last());
}

// begin()
TEST(StringView, 15)
{
  char data[] = "Hello World";
  StringView stringView(data);
  ASSERT_EQ(data, stringView.begin());
}

// end()
TEST(StringView, 16)
{
  char data[] = "Hello World";
  StringView stringView(data);
  ASSERT_EQ(data + 11, stringView.end());
}

// operator==()
TEST(StringView, 17)
{
  StringView stringView1("Hello World");
  StringView stringView2 = stringView1;
  ASSERT_TRUE(stringView1 == stringView2);
}

// operator!=()
TEST(StringView, 18)
{
  StringView stringView1("Hello World");
  StringView stringView2("Today Is A Great Day");
  ASSERT_TRUE(stringView1 != stringView2);
}

// operator<()
TEST(StringView, 19)
{
  StringView stringView1("Hello World");
  StringView stringView2("Today Is A Great Day");
  ASSERT_TRUE(stringView1 < stringView2);
}

// operator<=()
TEST(StringView, 20)
{
  StringView stringView1("Hello World");
  StringView stringView2("Today Is A Great Day");
  ASSERT_TRUE(stringView1 <= stringView2);
}

// operator>()
TEST(StringView, 21)
{
  StringView stringView1("Hello World");
  StringView stringView2("Today Is A Great Day");
  ASSERT_TRUE(stringView2 > stringView1);
}

// operator>=()
TEST(StringView, 22)
{
  StringView stringView1("Hello World");
  StringView stringView2("Today Is A Great Day");
  ASSERT_TRUE(stringView2 >= stringView1);
}

// beginsWith()
TEST(StringView, 23)
{
  StringView stringView("Hello World");
  ASSERT_TRUE(stringView.beginsWith('H'));
}

// beginsWith()
TEST(StringView, 24)
{
  StringView stringView1("Hello World");
  StringView stringView2 = stringView1;
  ASSERT_TRUE(stringView2.beginsWith(stringView1));
}

// contains()
TEST(StringView, 25)
{
  StringView stringView("Hello World");
  ASSERT_TRUE(stringView.contains('H'));
}

// contains()
TEST(StringView, 26)
{
  StringView stringView1("Hello World");
  StringView stringView2 = stringView1;
  ASSERT_TRUE(stringView2.contains(stringView1));
}

// endsWith()
TEST(StringView, 27)
{
  StringView stringView("Hello World");
  ASSERT_TRUE(stringView.endsWith('d'));
}

// endsWith()
TEST(StringView, 28)
{
  StringView stringView1("Hello World");
  StringView stringView2 = stringView1;
  ASSERT_TRUE(stringView2.endsWith(stringView1));
}

// find()
TEST(StringView, 29)
{
  StringView stringView("Hello World");
  ASSERT_EQ(4, stringView.find('o'));
}

// find()
TEST(StringView, 30)
{
  StringView stringView1("Hello World");
  StringView stringView2("World");
  ASSERT_EQ(6, stringView1.find(stringView2));
}

// findLast()
TEST(StringView, 31)
{
  StringView stringView("Hello World");
  ASSERT_EQ(7, stringView.findLast('o'));
}

// findLast()
TEST(StringView, 32)
{
  StringView stringView1("Hello World");
  StringView stringView2("World");
  ASSERT_EQ(6, stringView1.findLast(stringView2));
}

// head()
TEST(StringView, 33)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.head(5);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
}

// tail()
TEST(StringView, 34)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.tail(5);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ('W', dataRet[0]);
  ASSERT_EQ('o', dataRet[1]);
  ASSERT_EQ('r', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('d', dataRet[4]);
}

// unhead()
TEST(StringView, 35)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.unhead(5);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ(' ', dataRet[0]);
  ASSERT_EQ('W', dataRet[1]);
  ASSERT_EQ('o', dataRet[2]);
  ASSERT_EQ('r', dataRet[3]);
  ASSERT_EQ('l', dataRet[4]);
  ASSERT_EQ('d', dataRet[5]);
}

// untail()
TEST(StringView, 36)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.untail(5);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
  ASSERT_EQ(' ', dataRet[5]);
}

// range()
TEST(StringView, 37)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.range(3, 7);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ('l', dataRet[0]);
  ASSERT_EQ('o', dataRet[1]);
  ASSERT_EQ(' ', dataRet[2]);
  ASSERT_EQ('W', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
}

// slice()
TEST(StringView, 38)
{
  StringView stringView1("Hello World");

  StringView stringView2 = stringView1.slice(2, 6);

  const StringView::Object* dataRet = stringView2.getData();
  ASSERT_EQ('l', dataRet[0]);
  ASSERT_EQ('l', dataRet[1]);
  ASSERT_EQ('o', dataRet[2]);
  ASSERT_EQ(' ', dataRet[3]);
  ASSERT_EQ('W', dataRet[4]);
  ASSERT_EQ('o', dataRet[5]);
  ASSERT_EQ('r', dataRet[6]);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
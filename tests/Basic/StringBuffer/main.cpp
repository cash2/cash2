// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/StringBuffer.h>
#include <gtest/gtest.h>

/*

MyNotes

class StringBuffer
public
  StringBuffer()
  StringBuffer()
  StringBuffer()
  StringBuffer()
  StringBuffer()
  ~StringBuffer()
  operator=()
  operator=()
  operator StringView()
  operator std::string()
  getData()
  getData()
  getSize()
  isEmpty()
  operator[]()
  operator[]()
  first()
  first()
  last()
  last()
  begin()
  begin()
  end()
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
  append()
  append()
  clear()
  cut()
  fill()
  insert()
  insert()
  overwrite()
  resize()
  reverse()
  shrink()

*/

using namespace Common;

// StringBuffer()
TEST(StringBuffer, 1)
{
  StringBuffer<1>();
}

// StringBuffer()
TEST(StringBuffer, 2)
{
  char data[] = "Hello World";
  StringBuffer<11> stringBuffer(data, 11);
}

// StringBuffer()
TEST(StringBuffer, 3)
{
  char data[] = "Hello World";
  StringBuffer<11> stringBuffer(data);
}

// StringBuffer()
TEST(StringBuffer, 4)
{
  StringView stringView("Hello World");
  StringBuffer<11> stringBuffer(stringView);
}

// StringBuffer()
TEST(StringBuffer, 5)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<11> stringBuffer2(stringBuffer1);
}

// operator=()
TEST(StringBuffer, 6)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<11> stringBuffer2 = stringBuffer1;
}

// operator=()
TEST(StringBuffer, 7)
{
  StringView stringView("Hello World");
  StringBuffer<11> stringBuffer;
  stringBuffer = stringView;
}

// operator StringView()
TEST(StringBuffer, 8)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = (StringView)stringBuffer;
}

// getData()
TEST(StringBuffer, 9)
{
  StringBuffer<11> stringBuffer("Hello World");

  const char* dataRet = stringBuffer.getData();

  // ASSERT_EQ(data, dataRet); // for some reason this does not work

  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
  ASSERT_EQ(' ', dataRet[5]);
  ASSERT_EQ('W', dataRet[6]);
  ASSERT_EQ('o', dataRet[7]);
  ASSERT_EQ('r', dataRet[8]);
  ASSERT_EQ('l', dataRet[9]);
  ASSERT_EQ('d', dataRet[10]);
}

// getData const()
TEST(StringBuffer, 10)
{
  const StringBuffer<11> stringBuffer("Hello World");

  const char* dataRet = stringBuffer.getData();

  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
  ASSERT_EQ(' ', dataRet[5]);
  ASSERT_EQ('W', dataRet[6]);
  ASSERT_EQ('o', dataRet[7]);
  ASSERT_EQ('r', dataRet[8]);
  ASSERT_EQ('l', dataRet[9]);
  ASSERT_EQ('d', dataRet[10]);
}

// getSize()
TEST(StringBuffer, 11)
{
  const StringBuffer<11> stringBuffer("Hello World");

  size_t size = stringBuffer.getSize();
  ASSERT_EQ(11, size);
}

// isEmpty()
TEST(StringBuffer, 12)
{
  const StringBuffer<11> stringBuffer("Hello World");
  ASSERT_FALSE(stringBuffer.isEmpty());
}

// operator[]()
TEST(StringBuffer, 13)
{
  StringBuffer<11> stringBuffer("Hello World");

  ASSERT_EQ('H', stringBuffer[0]);
  ASSERT_EQ('e', stringBuffer[1]);
  ASSERT_EQ('l', stringBuffer[2]);
  ASSERT_EQ('l', stringBuffer[3]);
  ASSERT_EQ('o', stringBuffer[4]);
  ASSERT_EQ(' ', stringBuffer[5]);
  ASSERT_EQ('W', stringBuffer[6]);
  ASSERT_EQ('o', stringBuffer[7]);
  ASSERT_EQ('r', stringBuffer[8]);
  ASSERT_EQ('l', stringBuffer[9]);
  ASSERT_EQ('d', stringBuffer[10]);
}

// operator[]() const
TEST(StringBuffer, 14)
{
  const StringBuffer<11> stringBuffer("Hello World");

  ASSERT_EQ('H', stringBuffer[0]);
  ASSERT_EQ('e', stringBuffer[1]);
  ASSERT_EQ('l', stringBuffer[2]);
  ASSERT_EQ('l', stringBuffer[3]);
  ASSERT_EQ('o', stringBuffer[4]);
  ASSERT_EQ(' ', stringBuffer[5]);
  ASSERT_EQ('W', stringBuffer[6]);
  ASSERT_EQ('o', stringBuffer[7]);
  ASSERT_EQ('r', stringBuffer[8]);
  ASSERT_EQ('l', stringBuffer[9]);
  ASSERT_EQ('d', stringBuffer[10]);
}

// first()
TEST(StringBuffer, 15)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ('H', stringBuffer.first());
}

// first() const
TEST(StringBuffer, 16)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ('H', stringBuffer.first());
}

// last()
TEST(StringBuffer, 17)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ('d', stringBuffer.last());
}

// last() const
TEST(StringBuffer, 18)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ('d', stringBuffer.last());
}

// begin()
TEST(StringBuffer, 19)
{
  char data[] = "Hello World";
  StringBuffer<11> stringBuffer(data);
  // ASSERT_EQ(data, stringBuffer.begin()); // for some reason this does not work

  ASSERT_EQ('H', stringBuffer.begin()[0]);
  ASSERT_EQ('e', stringBuffer.begin()[1]);
  ASSERT_EQ('l', stringBuffer.begin()[2]);
  ASSERT_EQ('l', stringBuffer.begin()[3]);
  ASSERT_EQ('o', stringBuffer.begin()[4]);
  ASSERT_EQ(' ', stringBuffer.begin()[5]);
  ASSERT_EQ('W', stringBuffer.begin()[6]);
  ASSERT_EQ('o', stringBuffer.begin()[7]);
  ASSERT_EQ('r', stringBuffer.begin()[8]);
  ASSERT_EQ('l', stringBuffer.begin()[9]);
  ASSERT_EQ('d', stringBuffer.begin()[10]);
}

// begin() const
TEST(StringBuffer, 20)
{
  char data[] = "Hello World";
  const StringBuffer<11> stringBuffer(data);
  
  ASSERT_EQ('H', stringBuffer.begin()[0]);
  ASSERT_EQ('e', stringBuffer.begin()[1]);
  ASSERT_EQ('l', stringBuffer.begin()[2]);
  ASSERT_EQ('l', stringBuffer.begin()[3]);
  ASSERT_EQ('o', stringBuffer.begin()[4]);
  ASSERT_EQ(' ', stringBuffer.begin()[5]);
  ASSERT_EQ('W', stringBuffer.begin()[6]);
  ASSERT_EQ('o', stringBuffer.begin()[7]);
  ASSERT_EQ('r', stringBuffer.begin()[8]);
  ASSERT_EQ('l', stringBuffer.begin()[9]);
  ASSERT_EQ('d', stringBuffer.begin()[10]);
}

// end()
TEST(StringBuffer, 21)
{
  char data[] = "Hello World";
  StringBuffer<11> stringBuffer(data);
  ASSERT_EQ(stringBuffer.getData() + 11, stringBuffer.end());
}

// end() const
TEST(StringBuffer, 22)
{
  char data[] = "Hello World";
  const StringBuffer<11> stringBuffer(data);
  ASSERT_EQ(stringBuffer.getData() + 11, stringBuffer.end());
}

// operator==()
TEST(StringBuffer, 23)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<11> stringBuffer2 = stringBuffer1;
  ASSERT_TRUE(stringBuffer1 == stringBuffer2);
}

// operator!=()
TEST(StringBuffer, 24)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<20> stringBuffer2("Today Is A Great Day");
  ASSERT_TRUE(stringBuffer1 != stringBuffer2);
}

// operator<()
TEST(StringBuffer, 25)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<20> stringBuffer2("Today Is A Great Day");
  ASSERT_TRUE(stringBuffer1 < stringBuffer2);
}

// operator<=()
TEST(StringBuffer, 26)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<20> stringBuffer2("Today Is A Great Day");
  ASSERT_TRUE(stringBuffer1 <= stringBuffer2);
}

// operator>()
TEST(StringBuffer, 27)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<20> stringBuffer2("Today Is A Great Day");
  ASSERT_TRUE(stringBuffer2 > stringBuffer1);
}

// operator>=()
TEST(StringBuffer, 28)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<20> stringBuffer2("Today Is A Great Day");
  ASSERT_TRUE(stringBuffer2 >= stringBuffer1);
}

// beginsWith()
TEST(StringBuffer, 29)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_TRUE(stringBuffer.beginsWith('H'));
}

// beginsWith() const
TEST(StringBuffer, 30)
{
  const StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = (StringView)stringBuffer;
  ASSERT_TRUE(stringBuffer.beginsWith(stringView));
}

// contains()
TEST(StringBuffer, 31)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_TRUE(stringBuffer.contains('H'));
}

// contains() const
TEST(StringBuffer, 32)
{
  const StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = (StringView)stringBuffer;
  ASSERT_TRUE(stringBuffer.contains(stringView));
}

// endsWith()
TEST(StringBuffer, 33)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_TRUE(stringBuffer.endsWith('d'));
}

// endsWith() const
TEST(StringBuffer, 34)
{
  const StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = (StringView)stringBuffer;
  ASSERT_TRUE(stringBuffer.contains(stringView));
}

// find()
TEST(StringBuffer, 35)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ(4, stringBuffer.find('o'));
}

// find() const
TEST(StringBuffer, 36)
{
  const StringBuffer<11> stringBuffer("Hello World");
  StringView stringView("World");
  ASSERT_EQ(6, stringBuffer.find(stringView));
}

// findLast()
TEST(StringBuffer, 37)
{
  StringBuffer<11> stringBuffer("Hello World");
  ASSERT_EQ(7, stringBuffer.findLast('o'));
}

// findLast() const
TEST(StringBuffer, 38)
{
  const StringBuffer<11> stringBuffer("Hello World");
  StringView stringView("World");
  ASSERT_EQ(6, stringBuffer.findLast(stringView));
}

// head()
TEST(StringBuffer, 39)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.head(5);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
}

// tail()
TEST(StringBuffer, 40)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.tail(5);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('W', dataRet[0]);
  ASSERT_EQ('o', dataRet[1]);
  ASSERT_EQ('r', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('d', dataRet[4]);
}

// unhead()
TEST(StringBuffer, 41)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.unhead(6);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('W', dataRet[0]);
  ASSERT_EQ('o', dataRet[1]);
  ASSERT_EQ('r', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('d', dataRet[4]);
}

// untail()
TEST(StringBuffer, 42)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.untail(6);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
}

// range()
TEST(StringBuffer, 43)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.range(3, 7);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('l', dataRet[0]);
  ASSERT_EQ('o', dataRet[1]);
  ASSERT_EQ(' ', dataRet[2]);
  ASSERT_EQ('W', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
}

// slice()
TEST(StringBuffer, 44)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView = stringBuffer.slice(2, 6);

  const StringView::Object* dataRet = stringView.getData();
  ASSERT_EQ('l', dataRet[0]);
  ASSERT_EQ('l', dataRet[1]);
  ASSERT_EQ('o', dataRet[2]);
  ASSERT_EQ(' ', dataRet[3]);
  ASSERT_EQ('W', dataRet[4]);
  ASSERT_EQ('o', dataRet[5]);
  ASSERT_EQ('r', dataRet[6]);
}

// append()
TEST(StringBuffer, 45)
{
  StringBuffer<32> stringBuffer1("Hello World");
  StringBuffer<32> stringBuffer2 = stringBuffer1.append(" Today Is A Great Day");

  char* dataRet = stringBuffer2.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
  ASSERT_EQ(' ', dataRet[5]);
  ASSERT_EQ('W', dataRet[6]);
  ASSERT_EQ('o', dataRet[7]);
  ASSERT_EQ('r', dataRet[8]);
  ASSERT_EQ('l', dataRet[9]);
  ASSERT_EQ('d', dataRet[10]);
  ASSERT_EQ(' ', dataRet[11]);
  ASSERT_EQ('T', dataRet[12]);
  ASSERT_EQ('o', dataRet[13]);
  ASSERT_EQ('d', dataRet[14]);
  ASSERT_EQ('a', dataRet[15]);
  ASSERT_EQ('y', dataRet[16]);
  ASSERT_EQ(' ', dataRet[17]);
  ASSERT_EQ('I', dataRet[18]);
  ASSERT_EQ('s', dataRet[19]);
  ASSERT_EQ(' ', dataRet[20]);
  ASSERT_EQ('A', dataRet[21]);
  ASSERT_EQ(' ', dataRet[22]);
  ASSERT_EQ('G', dataRet[23]);
  ASSERT_EQ('r', dataRet[24]);
  ASSERT_EQ('e', dataRet[25]);
  ASSERT_EQ('a', dataRet[26]);
  ASSERT_EQ('t', dataRet[27]);
  ASSERT_EQ(' ', dataRet[28]);
  ASSERT_EQ('D', dataRet[29]);
  ASSERT_EQ('a', dataRet[30]);
  ASSERT_EQ('y', dataRet[31]);
}

// append()
TEST(StringBuffer, 46)
{
  StringBuffer<32> stringBuffer1("Hello World");
  StringView stringView(" Today Is A Great Day");

  StringBuffer<32> stringBuffer2 = stringBuffer1.append(stringView);

  char* dataRet = stringBuffer2.getData();
  ASSERT_EQ('H', dataRet[0]);
  ASSERT_EQ('e', dataRet[1]);
  ASSERT_EQ('l', dataRet[2]);
  ASSERT_EQ('l', dataRet[3]);
  ASSERT_EQ('o', dataRet[4]);
  ASSERT_EQ(' ', dataRet[5]);
  ASSERT_EQ('W', dataRet[6]);
  ASSERT_EQ('o', dataRet[7]);
  ASSERT_EQ('r', dataRet[8]);
  ASSERT_EQ('l', dataRet[9]);
  ASSERT_EQ('d', dataRet[10]);
  ASSERT_EQ(' ', dataRet[11]);
  ASSERT_EQ('T', dataRet[12]);
  ASSERT_EQ('o', dataRet[13]);
  ASSERT_EQ('d', dataRet[14]);
  ASSERT_EQ('a', dataRet[15]);
  ASSERT_EQ('y', dataRet[16]);
  ASSERT_EQ(' ', dataRet[17]);
  ASSERT_EQ('I', dataRet[18]);
  ASSERT_EQ('s', dataRet[19]);
  ASSERT_EQ(' ', dataRet[20]);
  ASSERT_EQ('A', dataRet[21]);
  ASSERT_EQ(' ', dataRet[22]);
  ASSERT_EQ('G', dataRet[23]);
  ASSERT_EQ('r', dataRet[24]);
  ASSERT_EQ('e', dataRet[25]);
  ASSERT_EQ('a', dataRet[26]);
  ASSERT_EQ('t', dataRet[27]);
  ASSERT_EQ(' ', dataRet[28]);
  ASSERT_EQ('D', dataRet[29]);
  ASSERT_EQ('a', dataRet[30]);
  ASSERT_EQ('y', dataRet[31]);
}

// clear()
TEST(StringBuffer, 47)
{
  StringBuffer<11> stringBuffer("Hello World");
  stringBuffer.clear();
  ASSERT_EQ(0, stringBuffer.getSize());
}

// cut()
TEST(StringBuffer, 48)
{
  StringBuffer<11> stringBuffer1("Hello World");
  StringBuffer<11> stringBuffer2 = stringBuffer1.cut(2, 6); // remove 6 characters starting at position 2

  ASSERT_EQ(5, stringBuffer2.getSize());
  ASSERT_EQ('H', stringBuffer2.getData()[0]);
  ASSERT_EQ('e', stringBuffer2.getData()[1]);
  ASSERT_EQ('r', stringBuffer2.getData()[2]);
  ASSERT_EQ('l', stringBuffer2.getData()[3]);
  ASSERT_EQ('d', stringBuffer2.getData()[4]);
}

// fill()
TEST(StringBuffer, 49)
{
  StringBuffer<11> stringBuffer("Hello World");
  stringBuffer.fill('A');
  ASSERT_EQ('A', stringBuffer.getData()[0]);
  ASSERT_EQ('A', stringBuffer.getData()[1]);
  ASSERT_EQ('A', stringBuffer.getData()[2]);
  ASSERT_EQ('A', stringBuffer.getData()[3]);
  ASSERT_EQ('A', stringBuffer.getData()[4]);
  ASSERT_EQ('A', stringBuffer.getData()[5]);
  ASSERT_EQ('A', stringBuffer.getData()[6]);
  ASSERT_EQ('A', stringBuffer.getData()[7]);
  ASSERT_EQ('A', stringBuffer.getData()[8]);
  ASSERT_EQ('A', stringBuffer.getData()[9]);
  ASSERT_EQ('A', stringBuffer.getData()[10]);
}

// insert()
TEST(StringBuffer, 50)
{
  StringBuffer<12> stringBuffer("Hello World");
  stringBuffer.insert(11, 's');
  ASSERT_EQ(12, stringBuffer.getSize());
  ASSERT_EQ('H', stringBuffer.getData()[0]);
  ASSERT_EQ('e', stringBuffer.getData()[1]);
  ASSERT_EQ('l', stringBuffer.getData()[2]);
  ASSERT_EQ('l', stringBuffer.getData()[3]);
  ASSERT_EQ('o', stringBuffer.getData()[4]);
  ASSERT_EQ(' ', stringBuffer.getData()[5]);
  ASSERT_EQ('W', stringBuffer.getData()[6]);
  ASSERT_EQ('o', stringBuffer.getData()[7]);
  ASSERT_EQ('r', stringBuffer.getData()[8]);
  ASSERT_EQ('l', stringBuffer.getData()[9]);
  ASSERT_EQ('d', stringBuffer.getData()[10]);
  ASSERT_EQ('s', stringBuffer.getData()[11]);
}

// insert()
TEST(StringBuffer, 51)
{
  StringBuffer<15> stringBuffer1("Hello World");
  StringView stringView(" My");
  StringBuffer<15> stringBuffer2 = stringBuffer1.insert(5, stringView);

  ASSERT_EQ(14, stringBuffer2.getSize());
  ASSERT_EQ('H', stringBuffer2.getData()[0]);
  ASSERT_EQ('e', stringBuffer2.getData()[1]);
  ASSERT_EQ('l', stringBuffer2.getData()[2]);
  ASSERT_EQ('l', stringBuffer2.getData()[3]);
  ASSERT_EQ('o', stringBuffer2.getData()[4]);
  ASSERT_EQ(' ', stringBuffer2.getData()[5]);
  ASSERT_EQ('M', stringBuffer2.getData()[6]);
  ASSERT_EQ('y', stringBuffer2.getData()[7]);
  ASSERT_EQ(' ', stringBuffer2.getData()[8]);
  ASSERT_EQ('W', stringBuffer2.getData()[9]);
  ASSERT_EQ('o', stringBuffer2.getData()[10]);
  ASSERT_EQ('r', stringBuffer2.getData()[11]);
  ASSERT_EQ('l', stringBuffer2.getData()[12]);
  ASSERT_EQ('d', stringBuffer2.getData()[13]);
}

// overwrite()
TEST(StringBuffer, 52)
{
  StringBuffer<11> stringBuffer("Hello World");
  StringView stringView("J");
  stringBuffer.overwrite(0, stringView);

  ASSERT_EQ(11, stringBuffer.getSize());
  ASSERT_EQ('J', stringBuffer.getData()[0]);
  ASSERT_EQ('e', stringBuffer.getData()[1]);
  ASSERT_EQ('l', stringBuffer.getData()[2]);
  ASSERT_EQ('l', stringBuffer.getData()[3]);
  ASSERT_EQ('o', stringBuffer.getData()[4]);
  ASSERT_EQ(' ', stringBuffer.getData()[5]);
  ASSERT_EQ('W', stringBuffer.getData()[6]);
  ASSERT_EQ('o', stringBuffer.getData()[7]);
  ASSERT_EQ('r', stringBuffer.getData()[8]);
  ASSERT_EQ('l', stringBuffer.getData()[9]);
  ASSERT_EQ('d', stringBuffer.getData()[10]);
}

// resize()
TEST(StringBuffer, 53)
{
  StringBuffer<11> stringBuffer("Hello World");
  stringBuffer.resize(5);

  ASSERT_EQ('H', stringBuffer.getData()[0]);
  ASSERT_EQ('e', stringBuffer.getData()[1]);
  ASSERT_EQ('l', stringBuffer.getData()[2]);
  ASSERT_EQ('l', stringBuffer.getData()[3]);
  ASSERT_EQ('o', stringBuffer.getData()[4]);
}

// reverse()
TEST(StringBuffer, 54)
{
  StringBuffer<11> stringBuffer("Hello World");
  stringBuffer.reverse();

  ASSERT_EQ('d', stringBuffer.getData()[0]);
  ASSERT_EQ('l', stringBuffer.getData()[1]);
  ASSERT_EQ('r', stringBuffer.getData()[2]);
  ASSERT_EQ('o', stringBuffer.getData()[3]);
  ASSERT_EQ('W', stringBuffer.getData()[4]);
  ASSERT_EQ(' ', stringBuffer.getData()[5]);
  ASSERT_EQ('o', stringBuffer.getData()[6]);
  ASSERT_EQ('l', stringBuffer.getData()[7]);
  ASSERT_EQ('l', stringBuffer.getData()[8]);
  ASSERT_EQ('e', stringBuffer.getData()[9]);
  ASSERT_EQ('H', stringBuffer.getData()[10]);
}

// shrink()
TEST(StringBuffer, 55)
{
  StringBuffer<11> stringBuffer("Hello World");
  stringBuffer.shrink(5);

  ASSERT_EQ(5, stringBuffer.getSize());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
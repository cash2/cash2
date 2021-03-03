// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/StringTools.h>
#include <gtest/gtest.h>

/*

MyNotes

asString()
asString()
asBinaryArray()
fromHex()
fromHex()
fromHex()
fromHex()
fromHex()
fromHex()
podFromHex()
toHex()
toHex()
toHex()
toHex()
podToHex()
extract()
extract()
fromString()
fromString()
toString()
toString()
loadFileToString()
saveStringToFile()
base64Decode()
ipAddressToString()
parseIpAddressAndPort()
timeIntervalToString()

*/

using namespace Common;

// asString()
TEST(StringTools, 1)
{
  char data[] = "Hello World";
  std::string str = asString(data, 11);
  ASSERT_EQ("Hello World", str);
}

// asString()
TEST(StringTools, 2)
{
  std::vector<uint8_t> data;
  data.push_back('H');
  data.push_back('e');
  data.push_back('l');
  data.push_back('l');
  data.push_back('o');
  data.push_back(' ');
  data.push_back('W');
  data.push_back('o');
  data.push_back('r');
  data.push_back('l');
  data.push_back('d');

  std::string str = asString(data);
  ASSERT_EQ("Hello World", str);
}

// asBinaryArray()
TEST(StringTools, 3)
{
  std::string str = "Hello World";
  std::vector<uint8_t> ba = asBinaryArray(str);

  ASSERT_EQ(11, ba.size());
  ASSERT_EQ('H', ba[0]);
  ASSERT_EQ('e', ba[1]);
  ASSERT_EQ('l', ba[2]);
  ASSERT_EQ('l', ba[3]);
  ASSERT_EQ('o', ba[4]);
  ASSERT_EQ(' ', ba[5]);
  ASSERT_EQ('W', ba[6]);
  ASSERT_EQ('o', ba[7]);
  ASSERT_EQ('r', ba[8]);
  ASSERT_EQ('l', ba[9]);
  ASSERT_EQ('d', ba[10]);
}

// fromHex()
TEST(StringTools, 4)
{
  char character = '0';
  uint8_t val = fromHex(character);
  ASSERT_EQ(0, val);

  ASSERT_EQ(1, fromHex('1'));
  ASSERT_EQ(2, fromHex('2'));
  ASSERT_EQ(3, fromHex('3'));
  ASSERT_EQ(4, fromHex('4'));
  ASSERT_EQ(5, fromHex('5'));
  ASSERT_EQ(6, fromHex('6'));
  ASSERT_EQ(7, fromHex('7'));
  ASSERT_EQ(8, fromHex('8'));
  ASSERT_EQ(9, fromHex('9'));
  ASSERT_EQ(10, fromHex('A'));
  ASSERT_EQ(11, fromHex('B'));
  ASSERT_EQ(12, fromHex('C'));
  ASSERT_EQ(13, fromHex('D'));
  ASSERT_EQ(14, fromHex('E'));
  ASSERT_EQ(15, fromHex('F'));

  ASSERT_ANY_THROW(fromHex('G'));
  ASSERT_ANY_THROW(fromHex('H'));
  ASSERT_ANY_THROW(fromHex('I'));
  ASSERT_ANY_THROW(fromHex('J'));
  ASSERT_ANY_THROW(fromHex('K'));
  ASSERT_ANY_THROW(fromHex('L'));
  ASSERT_ANY_THROW(fromHex('M'));
}

// fromHex()
TEST(StringTools, 5)
{
  char character = '0';
  uint8_t value;
  ASSERT_TRUE(fromHex(character, value));
  ASSERT_EQ(0, value);

  ASSERT_TRUE(fromHex('1', value));
  ASSERT_EQ(1, value);
  ASSERT_TRUE(fromHex('2', value));
  ASSERT_EQ(2, value);
  ASSERT_TRUE(fromHex('3', value));
  ASSERT_EQ(3, value);
  ASSERT_TRUE(fromHex('4', value));
  ASSERT_EQ(4, value);
  ASSERT_TRUE(fromHex('5', value));
  ASSERT_EQ(5, value);
  ASSERT_TRUE(fromHex('6', value));
  ASSERT_EQ(6, value);
  ASSERT_TRUE(fromHex('7', value));
  ASSERT_EQ(7, value);
  ASSERT_TRUE(fromHex('8', value));
  ASSERT_EQ(8, value);
  ASSERT_TRUE(fromHex('9', value));
  ASSERT_EQ(9, value);
  ASSERT_TRUE(fromHex('A', value));
  ASSERT_EQ(10, value);
  ASSERT_TRUE(fromHex('B', value));
  ASSERT_EQ(11, value);
  ASSERT_TRUE(fromHex('C', value));
  ASSERT_EQ(12, value);
  ASSERT_TRUE(fromHex('D', value));
  ASSERT_EQ(13, value);
  ASSERT_TRUE(fromHex('E', value));
  ASSERT_EQ(14, value);
  ASSERT_TRUE(fromHex('F', value));
  ASSERT_EQ(15, value);

  ASSERT_FALSE(fromHex('G', value));
  ASSERT_FALSE(fromHex('H', value));
  ASSERT_FALSE(fromHex('I', value));
  ASSERT_FALSE(fromHex('J', value));
}

// fromHex()
TEST(StringTools, 6)
{
  std::string text = "0123456789ABCDEF"; // string length must be greater than 15
  uint8_t data[8]; // size must be at least half of string length
  size_t size = fromHex(text, data, 8);

  ASSERT_EQ(8, size);

  // breaks text into hex values
  ASSERT_EQ(0x01, data[0]);
  ASSERT_EQ(0x23, data[1]);
  ASSERT_EQ(0x45, data[2]);
  ASSERT_EQ(0x67, data[3]);
  ASSERT_EQ(0x89, data[4]);
  ASSERT_EQ(0xAB, data[5]);
  ASSERT_EQ(0xCD, data[6]);
  ASSERT_EQ(0xEF, data[7]);
}

// fromHex()
TEST(StringTools, 7)
{
  std::string text = "0123456789ABCDEF";
  uint8_t data[8];
  size_t size;

  ASSERT_TRUE(fromHex(text, data, 8, size));

  ASSERT_EQ(8, size);

  ASSERT_EQ(0x01, data[0]);
  ASSERT_EQ(0x23, data[1]);
  ASSERT_EQ(0x45, data[2]);
  ASSERT_EQ(0x67, data[3]);
  ASSERT_EQ(0x89, data[4]);
  ASSERT_EQ(0xAB, data[5]);
  ASSERT_EQ(0xCD, data[6]);
  ASSERT_EQ(0xEF, data[7]);
}

// fromHex()
TEST(StringTools, 8)
{
  std::string text = "0123456789ABCDEF";
  
  std::vector<uint8_t> result = fromHex(text);

  ASSERT_EQ(8, result.size());

  ASSERT_EQ(0x01, result[0]);
  ASSERT_EQ(0x23, result[1]);
  ASSERT_EQ(0x45, result[2]);
  ASSERT_EQ(0x67, result[3]);
  ASSERT_EQ(0x89, result[4]);
  ASSERT_EQ(0xAB, result[5]);
  ASSERT_EQ(0xCD, result[6]);
  ASSERT_EQ(0xEF, result[7]);
}

// fromHex()
TEST(StringTools, 9)
{
  std::string text = "0123456789ABCDEF";
  std::vector<uint8_t> data;

  ASSERT_TRUE(fromHex(text, data));

  ASSERT_EQ(8, data.size());

  ASSERT_EQ(0x01, data[0]);
  ASSERT_EQ(0x23, data[1]);
  ASSERT_EQ(0x45, data[2]);
  ASSERT_EQ(0x67, data[3]);
  ASSERT_EQ(0x89, data[4]);
  ASSERT_EQ(0xAB, data[5]);
  ASSERT_EQ(0xCD, data[6]);
  ASSERT_EQ(0xEF, data[7]);
}

// podFromHex()
TEST(StringTools, 10)
{
  std::string text = "0123456789ABCDEF";
  uint8_t data[8];

  ASSERT_TRUE(podFromHex(text, data));

  ASSERT_EQ(0x01, data[0]);
  ASSERT_EQ(0x23, data[1]);
  ASSERT_EQ(0x45, data[2]);
  ASSERT_EQ(0x67, data[3]);
  ASSERT_EQ(0x89, data[4]);
  ASSERT_EQ(0xAB, data[5]);
  ASSERT_EQ(0xCD, data[6]);
  ASSERT_EQ(0xEF, data[7]);
}

// toHex()
TEST(StringTools, 11)
{
  uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  std::string str = toHex(data, 16);

  ASSERT_EQ(32, str.size());

  // 0x00
  ASSERT_EQ('0', str[0]);
  ASSERT_EQ('0', str[1]);

  // 0x01
  ASSERT_EQ('0', str[2]);
  ASSERT_EQ('1', str[3]);

  // 0x02
  ASSERT_EQ('0', str[4]);
  ASSERT_EQ('2', str[5]);

  // 0x03
  ASSERT_EQ('0', str[6]);
  ASSERT_EQ('3', str[7]);

  // 0x04
  ASSERT_EQ('0', str[8]);
  ASSERT_EQ('4', str[9]);

  // 0x05
  ASSERT_EQ('0', str[10]);
  ASSERT_EQ('5', str[11]);

  // 0x06
  ASSERT_EQ('0', str[12]);
  ASSERT_EQ('6', str[13]);

  // 0x07
  ASSERT_EQ('0', str[14]);
  ASSERT_EQ('7', str[15]);

  // 0x08
  ASSERT_EQ('0', str[16]);
  ASSERT_EQ('8', str[17]);

  // 0x09
  ASSERT_EQ('0', str[18]);
  ASSERT_EQ('9', str[19]);

  // 0x0A
  ASSERT_EQ('0', str[20]);
  ASSERT_EQ('a', str[21]);

  // 0x0B
  ASSERT_EQ('0', str[22]);
  ASSERT_EQ('b', str[23]);

  // 0x0C
  ASSERT_EQ('0', str[24]);
  ASSERT_EQ('c', str[25]);

  // 0x0D
  ASSERT_EQ('0', str[26]);
  ASSERT_EQ('d', str[27]);

  // 0x0E
  ASSERT_EQ('0', str[28]);
  ASSERT_EQ('e', str[29]);

  // 0x0F
  ASSERT_EQ('0', str[30]);
  ASSERT_EQ('f', str[31]);
}

// toHex()
TEST(StringTools, 12)
{
  uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  size_t size = 16;
  std::string str;

  toHex(data, size, str);

  ASSERT_EQ(32, str.size());

  // 0x00
  ASSERT_EQ('0', str[0]);
  ASSERT_EQ('0', str[1]);

  // 0x01
  ASSERT_EQ('0', str[2]);
  ASSERT_EQ('1', str[3]);

  // 0x02
  ASSERT_EQ('0', str[4]);
  ASSERT_EQ('2', str[5]);

  // 0x03
  ASSERT_EQ('0', str[6]);
  ASSERT_EQ('3', str[7]);

  // 0x04
  ASSERT_EQ('0', str[8]);
  ASSERT_EQ('4', str[9]);

  // 0x05
  ASSERT_EQ('0', str[10]);
  ASSERT_EQ('5', str[11]);

  // 0x06
  ASSERT_EQ('0', str[12]);
  ASSERT_EQ('6', str[13]);

  // 0x07
  ASSERT_EQ('0', str[14]);
  ASSERT_EQ('7', str[15]);

  // 0x08
  ASSERT_EQ('0', str[16]);
  ASSERT_EQ('8', str[17]);

  // 0x09
  ASSERT_EQ('0', str[18]);
  ASSERT_EQ('9', str[19]);

  // 0x0A
  ASSERT_EQ('0', str[20]);
  ASSERT_EQ('a', str[21]);

  // 0x0B
  ASSERT_EQ('0', str[22]);
  ASSERT_EQ('b', str[23]);

  // 0x0C
  ASSERT_EQ('0', str[24]);
  ASSERT_EQ('c', str[25]);

  // 0x0D
  ASSERT_EQ('0', str[26]);
  ASSERT_EQ('d', str[27]);

  // 0x0E
  ASSERT_EQ('0', str[28]);
  ASSERT_EQ('e', str[29]);

  // 0x0F
  ASSERT_EQ('0', str[30]);
  ASSERT_EQ('f', str[31]);
}

// toHex()
TEST(StringTools, 13)
{
  std::vector<uint8_t> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  std::string str = toHex(data);

  ASSERT_EQ(32, str.size());

  // 0x00
  ASSERT_EQ('0', str[0]);
  ASSERT_EQ('0', str[1]);

  // 0x01
  ASSERT_EQ('0', str[2]);
  ASSERT_EQ('1', str[3]);

  // 0x02
  ASSERT_EQ('0', str[4]);
  ASSERT_EQ('2', str[5]);

  // 0x03
  ASSERT_EQ('0', str[6]);
  ASSERT_EQ('3', str[7]);

  // 0x04
  ASSERT_EQ('0', str[8]);
  ASSERT_EQ('4', str[9]);

  // 0x05
  ASSERT_EQ('0', str[10]);
  ASSERT_EQ('5', str[11]);

  // 0x06
  ASSERT_EQ('0', str[12]);
  ASSERT_EQ('6', str[13]);

  // 0x07
  ASSERT_EQ('0', str[14]);
  ASSERT_EQ('7', str[15]);

  // 0x08
  ASSERT_EQ('0', str[16]);
  ASSERT_EQ('8', str[17]);

  // 0x09
  ASSERT_EQ('0', str[18]);
  ASSERT_EQ('9', str[19]);

  // 0x0A
  ASSERT_EQ('0', str[20]);
  ASSERT_EQ('a', str[21]);

  // 0x0B
  ASSERT_EQ('0', str[22]);
  ASSERT_EQ('b', str[23]);

  // 0x0C
  ASSERT_EQ('0', str[24]);
  ASSERT_EQ('c', str[25]);

  // 0x0D
  ASSERT_EQ('0', str[26]);
  ASSERT_EQ('d', str[27]);

  // 0x0E
  ASSERT_EQ('0', str[28]);
  ASSERT_EQ('e', str[29]);

  // 0x0F
  ASSERT_EQ('0', str[30]);
  ASSERT_EQ('f', str[31]);
}

// toHex()
TEST(StringTools, 14)
{
  std::vector<uint8_t> data = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  std::string str;

  toHex(data, str);

  ASSERT_EQ(32, str.size());

  // 0x00
  ASSERT_EQ('0', str[0]);
  ASSERT_EQ('0', str[1]);

  // 0x01
  ASSERT_EQ('0', str[2]);
  ASSERT_EQ('1', str[3]);

  // 0x02
  ASSERT_EQ('0', str[4]);
  ASSERT_EQ('2', str[5]);

  // 0x03
  ASSERT_EQ('0', str[6]);
  ASSERT_EQ('3', str[7]);

  // 0x04
  ASSERT_EQ('0', str[8]);
  ASSERT_EQ('4', str[9]);

  // 0x05
  ASSERT_EQ('0', str[10]);
  ASSERT_EQ('5', str[11]);

  // 0x06
  ASSERT_EQ('0', str[12]);
  ASSERT_EQ('6', str[13]);

  // 0x07
  ASSERT_EQ('0', str[14]);
  ASSERT_EQ('7', str[15]);

  // 0x08
  ASSERT_EQ('0', str[16]);
  ASSERT_EQ('8', str[17]);

  // 0x09
  ASSERT_EQ('0', str[18]);
  ASSERT_EQ('9', str[19]);

  // 0x0A
  ASSERT_EQ('0', str[20]);
  ASSERT_EQ('a', str[21]);

  // 0x0B
  ASSERT_EQ('0', str[22]);
  ASSERT_EQ('b', str[23]);

  // 0x0C
  ASSERT_EQ('0', str[24]);
  ASSERT_EQ('c', str[25]);

  // 0x0D
  ASSERT_EQ('0', str[26]);
  ASSERT_EQ('d', str[27]);

  // 0x0E
  ASSERT_EQ('0', str[28]);
  ASSERT_EQ('e', str[29]);

  // 0x0F
  ASSERT_EQ('0', str[30]);
  ASSERT_EQ('f', str[31]);
}

// podToHex()
TEST(StringTools, 15)
{
  uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  std::string str = podToHex(data);

  ASSERT_EQ(32, str.size());

  // 0x00
  ASSERT_EQ('0', str[0]);
  ASSERT_EQ('0', str[1]);

  // 0x01
  ASSERT_EQ('0', str[2]);
  ASSERT_EQ('1', str[3]);

  // 0x02
  ASSERT_EQ('0', str[4]);
  ASSERT_EQ('2', str[5]);

  // 0x03
  ASSERT_EQ('0', str[6]);
  ASSERT_EQ('3', str[7]);

  // 0x04
  ASSERT_EQ('0', str[8]);
  ASSERT_EQ('4', str[9]);

  // 0x05
  ASSERT_EQ('0', str[10]);
  ASSERT_EQ('5', str[11]);

  // 0x06
  ASSERT_EQ('0', str[12]);
  ASSERT_EQ('6', str[13]);

  // 0x07
  ASSERT_EQ('0', str[14]);
  ASSERT_EQ('7', str[15]);

  // 0x08
  ASSERT_EQ('0', str[16]);
  ASSERT_EQ('8', str[17]);

  // 0x09
  ASSERT_EQ('0', str[18]);
  ASSERT_EQ('9', str[19]);

  // 0x0A
  ASSERT_EQ('0', str[20]);
  ASSERT_EQ('a', str[21]);

  // 0x0B
  ASSERT_EQ('0', str[22]);
  ASSERT_EQ('b', str[23]);

  // 0x0C
  ASSERT_EQ('0', str[24]);
  ASSERT_EQ('c', str[25]);

  // 0x0D
  ASSERT_EQ('0', str[26]);
  ASSERT_EQ('d', str[27]);

  // 0x0E
  ASSERT_EQ('0', str[28]);
  ASSERT_EQ('e', str[29]);

  // 0x0F
  ASSERT_EQ('0', str[30]);
  ASSERT_EQ('f', str[31]);
}

// extract()
TEST(StringTools, 16)
{
  char delimiter = ' ';

  std::string src1 = "Hello World";
  std::string result1 = extract(src1, delimiter);
  ASSERT_EQ("World", src1);
  ASSERT_EQ("Hello", result1);

  std::string src2 = "Hello World My Name Is";
  std::string result2 = extract(src2, delimiter);
  ASSERT_EQ("World My Name Is", src2);
  ASSERT_EQ("Hello", result2);
}

// extract()
TEST(StringTools, 17)
{
  const char delimiter = ' ';
  size_t offset = 0; // offset is the position in the string to start

  const std::string src = "Hello World Today Is A Great Day";
  std::string result = extract(src, delimiter, offset);
  ASSERT_EQ("World", result);
  ASSERT_EQ(6, offset);

  result = extract(src, delimiter, offset);
  ASSERT_EQ("Today Is A ", result);
  ASSERT_EQ(12, offset);

  result = extract(src, delimiter, offset);
  ASSERT_EQ("Is A Great Day", result);
  ASSERT_EQ(18, offset);
}

// fromString()
TEST(StringTools, 18)
{
  std::string str = "123456789";
  uint64_t amount = fromString<uint64_t>(str);
  ASSERT_EQ(123456789, amount);
}

// fromString()
TEST(StringTools, 19)
{
  std::string str = "123456789";
  uint64_t amount;
  ASSERT_TRUE(fromString<uint64_t>(str, amount));
  ASSERT_EQ(123456789, amount);
}

// toString()
TEST(StringTools, 20)
{
  uint64_t amount = 123456789;
  std::string str = toString(amount);
  ASSERT_EQ("123456789", str);
}

// toString()
TEST(StringTools, 21)
{
  uint64_t amount = 123456789;
  std::string str;
  toString(amount, str);
  ASSERT_EQ("123456789", str);
}

// saveStringToFile()
TEST(StringTools, 22)
{
  const std::string filepath = "helloWorld.txt";
  const std::string str = "Hello World";
  ASSERT_TRUE(saveStringToFile(filepath, str));
}

// loadFileToString()
TEST(StringTools, 23)
{
  const std::string filepath = "helloWorld.txt";
  std::string str;
  ASSERT_TRUE(loadFileToString(filepath, str));

  ASSERT_EQ("Hello World", str);
}

// base64Decode()
TEST(StringTools, 24)
{
  // from wikipedia Base64
  std::string enc = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";
  std::string dec = base64Decode(enc);
  std::string expected = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
  ASSERT_EQ(expected, dec);
}

// ipAddressToString()
TEST(StringTools, 25)
{
  // 192.168.100.1
  // 192 = 11000000
  // 168 = 10101000
  // 100 = 01100100
  // 1   = 00000001
  // ip address has 32 total bits
  // 00000001 01100100 10101000 11000000 = 23374016
  uint32_t ip = 23374016;
  std::string str = ipAddressToString(ip);
  ASSERT_EQ("192.168.100.1", str);
}

// parseIpAddressAndPort()
TEST(StringTools, 26)
{
  const std::string& addr = "192.168.100.1:8080";
  uint32_t ip;
  uint32_t port;
  ASSERT_TRUE(parseIpAddressAndPort(ip, port, addr));
  ASSERT_EQ(23374016, ip); // 00000001 01100100 10101000 11000000
  ASSERT_EQ(8080, port);
}

// timeIntervalToString()
TEST(StringTools, 27)
{
  uint64_t intervalInSeconds = 10;
  std::string str = timeIntervalToString(intervalInSeconds);
  ASSERT_EQ("d0.h0.m0.s10", str);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
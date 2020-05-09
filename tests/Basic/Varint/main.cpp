// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/Varint.h>
#include <gtest/gtest.h>

/*

My Notes

write_varint()
get_varint_data()
read_varint()
read_varint()

From monero's github
The representation of varints is rather odd. The first bit of each
octet is significant, it represents wheter there is another part
waiting to be read. For example 0x8002 would return 0x200, even
though 0x02 does not have its msb set. The actual way they are read
is as follows: Strip the msb of each byte, then from left to right,
read in what remains, placing it in reverse, into the buffer. Thus,
the following bit stream: 0xff02 would return 0x027f. 0xff turns
into 0x7f, is placed on the beginning of the buffer, then 0x02 is
unchanged, since its msb is not set, and placed at the end of the
buffer.

0x8002 = 1000 0000 0000 0010
         0000 0000 0000 0010 remove msb of each byte
0x200  = 0000 0010 0000 0000 reverse the bytes

0xFF02 = 1111 1111 0000 0010
         0111 1111 0000 0010 remove msb of each byte
0x027F = 0000 0010 0111 1111 reverse the bytes


*/

using namespace Tools;

// get_varint_data()
TEST(Varint, 1)
{
  uint64_t varint = 639; // 0x027F
  std::string str = get_varint_data(varint);
  ASSERT_EQ("\xFF\x4", str); // 0xFF04 = 65284

  varint = 512; // 0x200
  str = get_varint_data(varint);
  ASSERT_EQ("\x80\x4", str); // 0x8004 = 32772
}

// read_varint()
TEST(Varint, 2)
{
  uint64_t varint;
  std::string varintData = "\xFF\x4"; // 0xFF04 = 65284
  read_varint(varintData.begin(), varintData.end(), varint);
  ASSERT_EQ(639, varint);

  varintData = "\x80\x4"; // 0x8004 = 32772
  read_varint(varintData.begin(), varintData.end(), varint);
  ASSERT_EQ(512, varint);
}















































int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
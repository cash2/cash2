// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include "Common/int-util.h"


// mul128 multiply by zero
TEST(mulDiv, 1)
{

  uint64_t product_low;
  uint64_t product_high;

  product_low = mul128(0, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(2, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(3, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(4, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(5, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(6, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(7, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(8, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(9, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(10, 0, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 1, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 2, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 3, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 4, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 5, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 6, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 7, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 8, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0, 9, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);
  
  product_low = mul128(0, 10, &product_high);
  ASSERT_EQ(product_low, 0);
  ASSERT_EQ(product_high, 0);

}

// mul128 multiply by zero random
TEST(mulDiv, 2)
{

  int loopCount = 100;
  
  uint64_t product_low;
  uint64_t product_high;

  for (int i = 0; i < loopCount; i++)
  {
    product_low = mul128(rand(), 0, &product_high);
    ASSERT_EQ(product_low, 0);
    ASSERT_EQ(product_high, 0);
  }

  for (int i = 0; i < loopCount; i++)
  {
    product_low = mul128(0, rand(), &product_high);
    ASSERT_EQ(product_low, 0);
    ASSERT_EQ(product_high, 0);
  }

}

// mul128 multiply by 1
TEST(mulDiv, 3)
{

  uint64_t product_low;
  uint64_t product_high;

  product_low = mul128(1, 1, &product_high);
  ASSERT_EQ(product_low, 1);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 2, &product_high);
  ASSERT_EQ(product_low, 2);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 3, &product_high);
  ASSERT_EQ(product_low, 3);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 4, &product_high);
  ASSERT_EQ(product_low, 4);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 5, &product_high);
  ASSERT_EQ(product_low, 5);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 6, &product_high);
  ASSERT_EQ(product_low, 6);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 7, &product_high);
  ASSERT_EQ(product_low, 7);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 8, &product_high);
  ASSERT_EQ(product_low, 8);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 9, &product_high);
  ASSERT_EQ(product_low, 9);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(1, 10, &product_high);
  ASSERT_EQ(product_low, 10);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(2, 1, &product_high);
  ASSERT_EQ(product_low, 2);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(3, 1, &product_high);
  ASSERT_EQ(product_low, 3);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(4, 1, &product_high);
  ASSERT_EQ(product_low, 4);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(5, 1, &product_high);
  ASSERT_EQ(product_low, 5);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(6, 1, &product_high);
  ASSERT_EQ(product_low, 6);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(7, 1, &product_high);
  ASSERT_EQ(product_low, 7);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(8, 1, &product_high);
  ASSERT_EQ(product_low, 8);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(9, 1, &product_high);
  ASSERT_EQ(product_low, 9);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(10, 1, &product_high);
  ASSERT_EQ(product_low, 10);
  ASSERT_EQ(product_high, 0);

}

// mul128 multiply by 1 random
TEST(mulDiv, 4)
{

  int loopCount = 100;
  
  uint64_t product_low;
  uint64_t product_high;

  for (int i = 0; i < loopCount; i++)
  {
    // randomNumber will be between 0 and 0xFFFF
    uint64_t randomNumber = rand() % 0x10000;
    product_low = mul128(randomNumber, 1, &product_high);
    ASSERT_EQ(product_low, randomNumber);
    ASSERT_EQ(product_high, 0);
  }

  for (int i = 0; i < loopCount; i++)
  {
    // randomNumber will be between 0 and 0xFFFF
    uint64_t randomNumber = rand() % 0x10000;
    product_low = mul128(1, randomNumber, &product_high);
    ASSERT_EQ(product_low, randomNumber);
    ASSERT_EQ(product_high, 0);
  }

}

// mult128 without carry
TEST(mulDiv, 5)
{

  uint64_t product_high;
  uint64_t product_low;

  product_low = mul128(0x3333333333333333, 5, &product_high);
  ASSERT_EQ(product_low, 0xFFFFFFFFFFFFFFFF);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(5, 0x3333333333333333, &product_high);
  ASSERT_EQ(product_low, 0xFFFFFFFFFFFFFFFF);
  ASSERT_EQ(product_high, 0);

  product_low = mul128(0x1111111111111111, 0x1111111111111111, &product_high);
  ASSERT_EQ(product_low, 0x0fedcba987654321);
  ASSERT_EQ(product_high, 0x0123456789abcdf0);

}

// mul128 with carry 1 only
TEST(mulDiv, 6)
{

  uint64_t product_high;
  uint64_t product_low;

  product_low = mul128(0xe0000000e0000000, 0xe0000000e0000000, &product_high);
  ASSERT_EQ(product_low, 0xc400000000000000);
  ASSERT_EQ(product_high, 0xc400000188000000);

}

// mul128 with carry 2 only
TEST(mulDiv, 7)
{

  uint64_t product_high, product_low;

  product_low = mul128(0x10000000ffffffff, 0x10000000ffffffff, &product_high);
  ASSERT_EQ(product_low, 0xdffffffe00000001);
  ASSERT_EQ(product_high, 0x0100000020000000);

}

// mul128 with carry 1 and carry 2
TEST(mulDiv, 8)
{

  uint64_t product_high, product_low;

  product_low = mul128(0xf1f2f3f4f5f6f7f8, 0xf9f0fafbfcfdfeff, &product_high);
  ASSERT_EQ(product_low, 0x52118e5f3b211008);
  ASSERT_EQ(product_high, 0xec39104363716e59);

  product_low = mul128(0xffffffffffffffff, 0xffffffffffffffff, &product_high);
  ASSERT_EQ(product_low, 0x0000000000000001);
  ASSERT_EQ(product_high, 0xfffffffffffffffe);

}

// div128_32 divide 0
TEST(mulDiv, 9)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;
  
  uint64_t dividend_high = 0;
  uint64_t dividend_low = 0;

  // dividend / divisor = quotient + remainder
  
  uint64_t divisor = 1;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);
  
  divisor = 2;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 3;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 4;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 5;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 6;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 7;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 8;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 9;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  divisor = 10;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);

  // Division by zero is UB, so can be tested correctly
}

// div128_32 divide 0 random
TEST(mulDiv, 10)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;
  
  uint64_t dividend_high = 0;
  uint64_t dividend_low = 0;

  // dividend / divisor = quotient + remainder
  
  for (int i = 0; i < 100; i++)
  {
    uint64_t divisor = rand();
    reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
    ASSERT_EQ(reminder, 0);
    ASSERT_EQ(quotient_high, 0);
    ASSERT_EQ(quotient_low, 0);
  }

}

// divide by 1
TEST(mulDiv, 11)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  uint64_t divisor = 1;

  // dividend / divisor = quotient + remainder
  
  uint64_t dividend_high = 0;
  uint64_t dividend_low = 1;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 2;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 3;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 4;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 5;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 6;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 7;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 8;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 9;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 0;
  dividend_low = 10;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, dividend_low);

  dividend_high = 1;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 2;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 3;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 4;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 5;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 6;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 7;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 8;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 9;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 10;
  dividend_low = 0;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, dividend_high);
  ASSERT_EQ(quotient_low, 0);
}

// divide by 1 random
TEST(mulDiv, 12)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  uint64_t divisor = 1;

  for (int i = 0; i < 100; i++)
  {
    uint64_t dividend_high = 0;
    uint64_t dividend_low = rand();
    reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
    ASSERT_EQ(reminder, 0);
    ASSERT_EQ(quotient_high, 0);
    ASSERT_EQ(quotient_low, dividend_low);
  }

  for (int i = 0; i < 100; i++)
  {
    uint64_t dividend_high = rand();
    uint64_t dividend_low = 0;
    reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
    ASSERT_EQ(reminder, 0);
    ASSERT_EQ(quotient_high, dividend_high);
    ASSERT_EQ(quotient_low, 0);
  }

}

// dividend less than divisor
TEST(mulDiv, 13)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  reminder = div128_32(0, 1383746, 1645825, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 1383746);
  ASSERT_EQ(quotient_high, 0);
  ASSERT_EQ(quotient_low, 0);
}

// dividend less than divisor random
TEST(mulDiv, 14)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  for (int i = 0; i < 10000; i++)
  {
    // get random number between 1 and RAND_MAX - 1
    uint64_t dividend_low = rand() % (RAND_MAX) + 1;

    // get random number between dividend_low + 1 and RAND_MAX
    uint64_t divisor = rand() % (RAND_MAX - dividend_low) + dividend_low + 1;

    reminder = div128_32(0, dividend_low, divisor, &quotient_high, &quotient_low);
    ASSERT_EQ(reminder, dividend_low);
    ASSERT_EQ(quotient_high, 0);
    ASSERT_EQ(quotient_low, 0);
  }
}

// div128_32 all dividend's dwords (32-bit unit of data) are less than the divisor?
// TEST(div128_32, handles_if_dividend_dwords_less_divider)
TEST(mulDiv, 15)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  reminder = div128_32(0x5AD629E441074F28, 0x0DBCAB2B231081F1, 0xFE735CD6, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0xB9C924E9);
  ASSERT_EQ(quotient_high, 0x000000005B63C274);
  ASSERT_EQ(quotient_low, 0x9084FC024383E48C);
}

// div128 random tests
TEST(mulDiv, 16)
{
  uint32_t reminder;
  uint64_t quotient_high;
  uint64_t quotient_low;

  uint64_t dividend_high;
  uint64_t dividend_low;
  uint64_t divisor;

  dividend_high = 2;
  dividend_low = 0;
  divisor = 2;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 1);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 0xFFFFFFFFFFFFFFFF;
  dividend_low = 0;
  divisor = 0xFFFFFFFF;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0);
  ASSERT_EQ(quotient_high, 0x0000000100000001);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 0xFFFFFFFFFFFFFFFF;
  dividend_low = 5846;
  divisor = 0xFFFFFFFF;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 5846);
  ASSERT_EQ(quotient_high, 0x0000000100000001);
  ASSERT_EQ(quotient_low, 0);

  dividend_high = 0xFFFFFFFFFFFFFFFF - 1;
  dividend_low = 0;
  divisor = 0xFFFFFFFF;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0xFFFFFFFE);
  ASSERT_EQ(quotient_high, 0x0000000100000000);
  ASSERT_EQ(quotient_low, 0xFFFFFFFEFFFFFFFE);

  dividend_high = 0x2649372534875028;
  dividend_low = 0xAEDBFEDC5ADBC739;
  divisor = 0x27826534;
  reminder = div128_32(dividend_high, dividend_low, divisor, &quotient_high, &quotient_low);
  ASSERT_EQ(reminder, 0x1A6DC2E5);
  ASSERT_EQ(quotient_high, 0x00000000F812C1F8);
  ASSERT_EQ(quotient_low, 0xDDF2FDB09BC2E2E9);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

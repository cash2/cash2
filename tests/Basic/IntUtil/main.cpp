// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/int-util.h>
#include <gtest/gtest.h>

/*

MyNotes

rol32()
rol64()
hi_dword()
lo_dword()
mul128()
div_with_reminder()
div128_32()
ident32()
ident64()
swap32()
swap64()
mem_inplace_ident()
mem_inplace_swap32()
mem_inplace_swap64()
memcpy_ident32()
memcpy_ident64()
memcpy_swap32()
memcpy_swap64()

*/

// rol32
TEST(intUtil, 1)
{
  uint32_t x = 11; // 1011
  int r = 1;
  uint32_t result = rol32(x, r);

  ASSERT_EQ(22, result); // 0001 0110

  ASSERT_EQ(44, rol32(x, 2)); // 0010 1100
  ASSERT_EQ(88, rol32(x, 3)); // 0101 1000
  ASSERT_EQ(176, rol32(x, 4)); // 1011 0000
  ASSERT_EQ(352, rol32(x, 5)); // 0001 0110 0000
  ASSERT_EQ(704, rol32(x, 6)); // 0010 1100 0000
  ASSERT_EQ(1408, rol32(x, 7)); // 0101 1000 0000
  ASSERT_EQ(2816, rol32(x, 8)); // 1011 0000 0000

  ASSERT_EQ(45056, rol32(x, 12)); // 1011 0000 0000 0000
  ASSERT_EQ(720896, rol32(x, 16)); // 1011 0000 0000 0000 0000
  ASSERT_EQ(11534336, rol32(x, 20)); // 1011 0000 0000 0000 0000 0000
  ASSERT_EQ(184549376, rol32(x, 24)); // 1011 0000 0000 0000 0000 0000 0000

  ASSERT_EQ(2952790016, rol32(x, 28)); // 1011 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(1610612737, rol32(x, 29)); // 0110 0000 0000 0000 0000 0000 0000 0001
  ASSERT_EQ(3221225474, rol32(x, 30)); // 1100 0000 0000 0000 0000 0000 0000 0010
}

// rol64
TEST(intUtil, 2)
{
  uint32_t x = 11; // 1011
  int r = 1;
  uint32_t result = rol64(x, r);

  ASSERT_EQ(22, result); // 0001 0110

  ASSERT_EQ(44, rol64(x, 2)); // 0010 1100
  ASSERT_EQ(88, rol64(x, 3)); // 0101 1000
  ASSERT_EQ(176, rol64(x, 4)); // 1011 0000
  ASSERT_EQ(352, rol64(x, 5)); // 0001 0110 0000
  ASSERT_EQ(704, rol64(x, 6)); // 0010 1100 0000
  ASSERT_EQ(1408, rol64(x, 7)); // 0101 1000 0000
  ASSERT_EQ(2816, rol64(x, 8)); // 1011 0000 0000

  ASSERT_EQ(45056, rol64(x, 12)); // 1011 0000 0000 0000
  ASSERT_EQ(720896, rol64(x, 16)); // 1011 0000 0000 0000 0000
  ASSERT_EQ(11534336, rol64(x, 20)); // 1011 0000 0000 0000 0000 0000
  ASSERT_EQ(184549376, rol64(x, 24)); // 1011 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(2952790016, rol64(x, 28)); // 1011 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(47244640256, rol64(x, 32)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(755914244096, rol64(x, 36)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(12094627905536, rol64(x, 40)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(193514046488576, rol64(x, 44)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(3096224743817216, rol64(x, 48)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(49539595901075456, rol64(x, 52)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(792633534417207296, rol64(x, 56)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000

  ASSERT_EQ(1585267068834414592, rol64(x, 57)); // 0001 0110 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(3170534137668829184, rol64(x, 58)); // 0010 1100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(6341068275337658368, rol64(x, 59)); // 0101 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(12682136550675316736U, rol64(x, 60)); // 1011 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000

}

// hi_dword()
TEST(intUtil, 3)
{
  uint64_t val = 4294967296; // 0001 0000 0000 0000 0000 0000 0000 0000 0000 
  uint64_t result = hi_dword(val);

  ASSERT_EQ(1, result); // 0001

  val = 4294967296; // 0001 0001 0001 0001 0001 0001 0001 0001 0001 
  ASSERT_EQ(1, hi_dword(val)); 
}

// lo_dword()
TEST(intUtil, 4)
{
  uint64_t val = 1; // 0001
  uint64_t result = lo_dword(val);

  ASSERT_EQ(1 ,result);

  ASSERT_EQ(16 ,lo_dword(16)); // 0001 0000
  ASSERT_EQ(256 ,lo_dword(256)); // 0001 0000 0000
  ASSERT_EQ(4096 ,lo_dword(4096)); // 0001 0000 0000 0000
  ASSERT_EQ(65536 ,lo_dword(65536)); // 0001 0000 0000 0000 0000
  ASSERT_EQ(1048576 ,lo_dword(1048576)); // 0001 0000 0000 0000 0000 0000
  ASSERT_EQ(16777216 ,lo_dword(16777216)); // 0001 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(268435456 ,lo_dword(268435456)); // 0001 0000 0000 0000 0000 0000 0000 0000

  ASSERT_EQ(0 ,lo_dword(9223372032559808512)); // 0111 1111 1111 1111 1111 1111 1111 1111 0000 0000 0000 0000 0000 0000 0000 0000
  
  val = 9223372032846139665; // 0111 1111 1111 1111 1111 1111 1111 1111 0001 0001 0001 0001 0001 0001 0001 0001
  ASSERT_EQ(286331153 ,lo_dword(val)); // 0001 0001 0001 0001 0001 0001 0001 0001
}

// mul128()
// product_hi is everything that overflows 2^64
TEST(intUtil, 5)
{
  uint64_t multiplier = 1; // 0001
  uint64_t multiplicand = 1; // 0001
  uint64_t product_hi;
  uint64_t product_lo = mul128(multiplier, multiplicand, &product_hi);
  ASSERT_EQ(1, product_lo);
  ASSERT_EQ(0, product_hi);

  multiplier = 4611686018427387904; // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  multiplicand = 4;
  product_lo = mul128(multiplier, multiplicand, &product_hi);
  ASSERT_EQ(0, product_lo);     // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(1, product_hi);  // 0001

  multiplier = 4611686018427387904; // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  multiplicand = 8;
  product_lo = mul128(multiplier, multiplicand, &product_hi);
  ASSERT_EQ(0, product_lo);     // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(2, product_hi);  // 0010

  multiplier = 4611686018427387904; // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  multiplicand = 64;
  product_lo = mul128(multiplier, multiplicand, &product_hi);
  ASSERT_EQ(0, product_lo);     // 0100 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  ASSERT_EQ(16, product_hi);  // 0001 0000
}

// div_with_reminder()
TEST(intUtil, 6)
{
  uint64_t dividend = 5;
  uint32_t divisor = 10;
  uint32_t remainder = 0;
  uint64_t result = div_with_reminder(dividend, divisor, &remainder);
  ASSERT_EQ(5, remainder);
  ASSERT_EQ(0, result);

  dividend = 4293988625; // 1111 1111 1111 0001 0001 0001 0001 0001
  divisor = 1048576; // 0001 0000 0000 0000 0000
  remainder = 0;
  result = div_with_reminder(dividend, divisor, &remainder);
  ASSERT_EQ(4095, result); // 1111 1111 1111
  ASSERT_EQ(69905, remainder); // 0001 0001 0001 0001 0001
}

// div128_32()
// divisor is 128 bits
// dividend is 128 bits
TEST(intUtil, 7)
{
  uint64_t dividend_hi = 8;
  uint64_t dividend_lo = 0;
  // dividend equals 1000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
  uint32_t divisor = 2;
  uint64_t quotient_hi;
  uint64_t quotient_lo;
  uint32_t remainder = div128_32(dividend_hi, dividend_lo, divisor, &quotient_hi, &quotient_lo);
  ASSERT_EQ(4, quotient_hi);
  ASSERT_EQ(0, quotient_lo);
  ASSERT_EQ(0, remainder);
}

// ident32()
TEST(intUtil, 8)
{
  uint32_t x = 10;
  uint32_t result = ident32(x);
  ASSERT_EQ(x, result);
}

// ident64()
TEST(intUtil, 9)
{
  uint64_t x = 10;
  uint64_t result = ident64(x);
  ASSERT_EQ(x, result);
}

// swap32()
// big endian <-> little endian
TEST(intUtil, 10)
{
  uint32_t x = 305419896; // 0001 0010 0011 0100 0101 0110 0111 1000
  uint32_t result = swap32(x);
  ASSERT_EQ(2018915346, result); // 0111 1000 0101 0110 0011 0100 0001 0010
}

// swap64()
// big endian <-> little endian
TEST(intUtil, 11)
{
  uint64_t x = 1311768467463790095;       // 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 0000 1111
  uint64_t result = swap64(x);
  ASSERT_EQ(1143558727028585490, result); // 0000 1111 1101 1110 1011 1100 1001 1010 0111 1000 0101 0110 0011 0100 0001 0010
}

// mem_inplace_swap32()
TEST(intUtil, 12)
{
  uint32_t x = 305419896; // 0001 0010 0011 0100 0101 0110 0111 1000
  size_t n = sizeof(x);
  mem_inplace_swap32(&x, n);
  ASSERT_EQ(2018915346, x); // 0111 1000 0101 0110 0011 0100 0001 0010
}

// mem_inplace_swap64()
TEST(intUtil, 13)
{
  uint64_t x = 1311768467463790095;  // 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 0000 1111
  size_t n = 1;  // greater than 5 causes stack smashing; n = 1-5 returns same result, not sure what n is for
  mem_inplace_swap64(&x, n);
  ASSERT_EQ(1143558727028585490, x); // 0000 1111 1101 1110 1011 1100 1001 1010 0111 1000 0101 0110 0011 0100 0001 0010
}

// memcpy_ident32()
TEST(intUtil, 14)
{
  const uint32_t a = 305419896;
  uint32_t b = 0;
  size_t n = 1; // greater than 2 causes stack smashing; n = 1-2 returns same result, not sure what n is for
  memcpy_ident32(&b, &a, n);

  ASSERT_EQ(305419896, b);
}

// memcpy_ident64()
TEST(intUtil, 15)
{
  const uint64_t a = 1311768467463790095; // 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 0000 1111
  uint64_t b = 0;
  size_t n = 1; // n is chunks of 32 bits
  memcpy_ident32(&b, &a, n);
  ASSERT_EQ(2596068879, b); // 1001 1010 1011 1100 1101 1110 0000 1111

  n = 2;
  memcpy_ident32(&b, &a, n);
  ASSERT_EQ(1311768467463790095, b); // 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 0000 1111
}

// memcpy_swap32()
TEST(intUtil, 16)
{
  const uint32_t a = 305419896; // 0001 0010 0011 0100 0101 0110 0111 1000
  uint32_t b = 0;
  size_t n = 1;
  memcpy_swap32(&b, &a, n);

  ASSERT_EQ(2018915346, b); // 0111 1000 0101 0110 0011 0100 0001 0010
}

// memcpy_swap64()
TEST(intUtil, 17)
{
  const uint64_t a = 1311768467463790095; // 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 0000 1111
  uint64_t b = 0;
  size_t n = 1; // n = 1-6 returns the same results, n > 6 causes stack smashing
  memcpy_swap64(&b, &a, n);
  ASSERT_EQ(1143558727028585490, b); // 0000 1111 1101 1110 1011 1100 1001 1010 0111 1000 0101 0110 0011 0100 0001 0010
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
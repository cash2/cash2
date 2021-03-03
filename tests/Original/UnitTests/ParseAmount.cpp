// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include <Logging/LoggerGroup.h>

using namespace CryptoNote;

namespace
{
  const size_t TEST_NUMBER_OF_DECIMAL_PLACES = 8;

  void pos_test(uint64_t expected, const std::string& str)
  {
    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    uint64_t val;
    std::string number_str = str;
    std::replace(number_str.begin(), number_str.end(), '_', '.');
    number_str.erase(std::remove(number_str.begin(), number_str.end(), '~'), number_str.end());
    ASSERT_TRUE(currency.parseAmount(number_str, val));
    ASSERT_EQ(expected, val);
  }

  void neg_test(const std::string& str)
  {
    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    uint64_t val;
    std::string number_str = str;
    std::replace(number_str.begin(), number_str.end(), '_', '.');
    number_str.erase(std::remove(number_str.begin(), number_str.end(), '~'), number_str.end());
    ASSERT_FALSE(currency.parseAmount(number_str, val));
  }
}

TEST(parse_amount, handles_pos_0)
{
  pos_test(0, "0");
}

TEST(parse_amount, handles_pos_00)
{
  pos_test(0, "00");
}

TEST(parse_amount, handles_pos_00000000)
{
  pos_test(0, "00000000");
}

TEST(parse_amount, handles_pos_000000000)
{
  pos_test(0, "000000000");
}

TEST(parse_amount, handles_pos_00000000000000000000000000000000)
{
  pos_test(0, "00000000000000000000000000000000");
}

TEST(parse_amount, handles_pos__0)
{
  pos_test(0, "_0");
}

TEST(parse_amount, handles_pos__00)
{
  pos_test(0, "_00");
}

TEST(parse_amount, handles_pos__00000000)
{
  pos_test(0, "_00000000");
}

TEST(parse_amount, handles_pos__000000000)
{
  pos_test(0, "_000000000");
}

TEST(parse_amount, handles_pos__00000000000000000000000000000000)
{
  pos_test(0, "_00000000000000000000000000000000");
}

TEST(parse_amount, handles_pos_00000000_)
{
	pos_test(UINT64_C(0), "00000000_");
}

TEST(parse_amount, handles_pos_000000000_)
{
	pos_test(UINT64_C(0), "000000000_");
}

TEST(parse_amount, handles_pos_00000000000000000000000000000000_)
{
	pos_test(UINT64_C(0), "00000000000000000000000000000000_");
}

TEST(parse_amount, handles_pos_0_)
{
	pos_test(UINT64_C(0), "0_");
}

TEST(parse_amount, handles_pos_0_0)
{
	pos_test(UINT64_C(0), "0_0");
}

TEST(parse_amount, handles_pos_0_00)
{
	pos_test(UINT64_C(0), "0_00");
}

TEST(parse_amount, handles_pos_0_00000000)
{
	pos_test(UINT64_C(0), "0_00000000");
}

TEST(parse_amount, handles_pos_0_000000000)
{
	pos_test(UINT64_C(0), "0_000000000");
}

TEST(parse_amount, handles_pos_0_00000000000000000000000000000000)
{
	pos_test(UINT64_C(0), "0_00000000000000000000000000000000");
}

TEST(parse_amount, handles_pos_00_)
{
	pos_test(UINT64_C(0), "00_");
}

TEST(parse_amount, handles_pos_00_0)
{
	pos_test(UINT64_C(0), "00_0");
}

TEST(parse_amount, handles_pos_00_00)
{
	pos_test(UINT64_C(0), "00_00");
}

TEST(parse_amount, handles_pos_00_00000000)
{
	pos_test(UINT64_C(0), "00_00000000");
}

TEST(parse_amount, handles_pos_00_000000000)
{
	pos_test(UINT64_C(0), "00_000000000");
}

TEST(parse_amount, handles_pos_00_00000000000000000000000000000000)
{
	pos_test(UINT64_C(0), "00_00000000000000000000000000000000");
}

TEST(parse_amount, handles_pos_0_00000001)
{
	pos_test(UINT64_C(1), "0_00000001");
}

TEST(parse_amount, handles_pos_0_000000010)
{
	pos_test(UINT64_C(1), "0_000000010");
}

TEST(parse_amount, handles_pos_0_000000010000000000000000000000000)
{
	pos_test(UINT64_C(1), "0_000000010000000000000000000000000");
}

TEST(parse_amount, handles_pos_0_00000009)
{
	pos_test(UINT64_C(9), "0_00000009");
}

TEST(parse_amount, handles_pos_0_000000090)
{
	pos_test(UINT64_C(9), "0_000000090");
}

TEST(parse_amount, handles_pos_0_000000090000000000000000000000000)
{
	pos_test(UINT64_C(9), "0_000000090000000000000000000000000");
}

TEST(parse_amount, handles_pos_1)
{
	pos_test(UINT64_C(100000000), "1");
}

TEST(parse_amount, handles_pos_65535)
{
	pos_test(UINT64_C(6553500000000), "65535");
}

TEST(parse_amount, handles_pos_4294967295)
{
	pos_test(UINT64_C(429496729500000000), "4294967295");
}

TEST(parse_amount, handles_pos_184467440737_)
{
	pos_test(UINT64_C(18446744073700000000), "184467440737_");
}

TEST(parse_amount, handles_pos_184467440737_0)
{
	pos_test(UINT64_C(18446744073700000000), "184467440737_0");
}

TEST(parse_amount, handles_pos_184467440737_00000000)
{
	pos_test(UINT64_C(18446744073700000000), "184467440737_00000000");
}

TEST(parse_amount, handles_pos_184467440737_000000000)
{
	pos_test(UINT64_C(18446744073700000000), "184467440737_000000000");
}

TEST(parse_amount, handles_pos_184467440737_0000000000000000000)
{
	pos_test(UINT64_C(18446744073700000000), "184467440737_000000000");
}

TEST(parse_amount, handles_pos_184467440737_09551615)
{
	pos_test(UINT64_C(18446744073709551615), "184467440737_09551615");
}

// Invalid numbers
TEST(parse_amount, handles_neg_empty_string)
{
	neg_test("~");
}

TEST(parse_amount, handles_neg_minus_0)
{
	neg_test("-0");
}

TEST(parse_amount, handles_neg_plus_0)
{
	neg_test("+0");
}

TEST(parse_amount, handles_neg_minus_1)
{
	neg_test("-1");
}

TEST(parse_amount, handles_neg_plus_1)
{
	neg_test("+1");
}

TEST(parse_amount, handles_neg_only_point)
{
	neg_test("_");
}

// A lot of fraction digits
TEST(parse_amount, handles_neg_0_000000001)
{
	neg_test("0_000000001");
}

TEST(parse_amount, handles_neg_0_000000009)
{
	neg_test("0_000000009");
}

TEST(parse_amount, handles_neg_184467440737_000000001)
{
	neg_test("184467440737_000000001");
}

// Overflow
TEST(parse_amount, handles_neg_184467440737_09551616)
{
	neg_test("184467440737_09551616");
}

TEST(parse_amount, handles_neg_184467440738)
{
	neg_test("184467440738");
}

TEST(parse_amount, handles_neg_18446744073709551616)
{
	neg_test("18446744073709551616l");
}

// Two or more points
TEST(parse_amount, handles_neg___)
{
	neg_test("__");
}

TEST(parse_amount, handles_neg_0__)
{
	neg_test("0__");
}

TEST(parse_amount, handles_neg___0)
{
	neg_test("__0");
}

TEST(parse_amount, handles_neg_0__0)
{
	neg_test("0__0");
}

TEST(parse_amount, handles_neg_0_0_)
{
	neg_test("0_0_");
}

TEST(parse_amount, handles_neg__0_0)
{
	neg_test("_0_0");
}

TEST(parse_amount, handles_neg_0_0_0)
{
	neg_test("0_0_0");
}

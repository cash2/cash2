// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include <math.h>

#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Currency.h"
#include <Logging/LoggerGroup.h>

using namespace CryptoNote;

const size_t TEST_NUMBER_OF_DECIMAL_PLACES = 8;

// turns dollar amount in the form of a string into an int

// string of zeros, no decimal, 1
TEST(parse_amount, 1)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 2
TEST(parse_amount, 2)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 3
TEST(parse_amount, 3)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 4
TEST(parse_amount, 4)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 5
TEST(parse_amount, 5)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 6
TEST(parse_amount, 6)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, 7
TEST(parse_amount, 7)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00000000000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal, random, 8
TEST(parse_amount, 8)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 10; i++)
  {
    std::string string = "";
    int stringLength = rand() % 100;
    
    for (int j = 0; j < stringLength; j++)
    {
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

//////////////////////////////////////////////////////////////////////////

// string of zeros, one decimal at beginning, 1
TEST(parse_amount, 9)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 2
TEST(parse_amount, 10)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".00";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 3
TEST(parse_amount, 11)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 4
TEST(parse_amount, 12)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".0000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 5
TEST(parse_amount, 13)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".00000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 6
TEST(parse_amount, 14)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, 7
TEST(parse_amount, 15)
{
  uint64_t expected = UINT64_C(0);
  std::string string = ".00000000000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at beginning, random, 8
TEST(parse_amount, 16)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 10; i++)
  {
    std::string string = ".";
    int stringLength = rand() % 100;
    
    for (int j = 0; j < stringLength; j++)
    {
      string += "0";
    }
    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

//////////////////////////////////////////////////////////////////////////

// string of zeros, one decimal at end, 1
TEST(parse_amount, 17)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 2
TEST(parse_amount, 18)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 3
TEST(parse_amount, 19)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "000.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 4
TEST(parse_amount, 20)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0000.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 5
TEST(parse_amount, 21)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00000000.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 6
TEST(parse_amount, 22)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "000000000.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, one decimal at end, 7
TEST(parse_amount, 23)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00000000000000000000000000000000.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, no decimal at end, random, 8
TEST(parse_amount, 24)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 10; i++)
  {
    std::string string = "";
    int stringLength = rand() % 100;
    
    for (int j = 0; j < stringLength; j++)
    {
      string += "0";
    }

    // add ending decimal
    string += ".";

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

//////////////////////////////////////////////////////////////////////////

// string of zeros, zero and one decimal at beginning, 1
TEST(parse_amount, 25)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 2
TEST(parse_amount, 26)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 3
TEST(parse_amount, 27)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.00";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 4
TEST(parse_amount, 28)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 5
TEST(parse_amount, 29)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.0000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 6
TEST(parse_amount, 30)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.00000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 7
TEST(parse_amount, 31)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, 8
TEST(parse_amount, 32)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "0.00000000000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, zero and one decimal at beginning, random, 9
TEST(parse_amount, 33)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 10; i++)
  {
    std::string string = "0.";
    int stringLength = rand() % 100;
    
    for (int j = 0; j < stringLength; j++)
    {
      string += "0";
    }
    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

//////////////////////////////////////////////////////////////////////////

// string of zeros, 2 zeros and one decimal at beginning, 1
TEST(parse_amount, 34)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 2
TEST(parse_amount, 35)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 3
TEST(parse_amount, 36)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.00";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 4
TEST(parse_amount, 37)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 5
TEST(parse_amount, 38)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.0000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 6
TEST(parse_amount, 39)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.00000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 7
TEST(parse_amount, 40)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, 8
TEST(parse_amount, 41)
{
  uint64_t expected = UINT64_C(0);
  std::string string = "00.00000000000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros, 2 zeros and one decimal at beginning, random, 9
TEST(parse_amount, 42)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 10; i++)
  {
    std::string string = "00.";
    int stringLength = rand() % 100;
    
    for (int j = 0; j < stringLength; j++)
    {
        string += "0";
    }
    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// string of zeros, 1 decimal at random position, random length 10
TEST(parse_amount, 43)
{
  uint64_t expected = UINT64_C(0);
  
  for (int i = 0; i < 100; i++)
  {
    std::string string = "";

    // add 2 to protect against empty string and "."
    // "0" was already tested previously
    int stringLength = rand() % 100 + 2;
    int decimalPosition = rand() % stringLength;

    for (int j = 0; j < stringLength; j++)
    {      
      if (j == decimalPosition)  
      {
        string += ".";
      }
      else
      {
        string += "0";
      }
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

//////////////////////////////////////////////////////////////////////////

// 0.1
TEST(parse_amount, 44)
{
  uint64_t expected = UINT64_C(10000000);
  std::string string = "0.1";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.1 and random number of zeros following it
TEST(parse_amount, 45)
{
  uint64_t expected = UINT64_C(10000000);
  std::string string = "0.1";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.01
TEST(parse_amount, 46)
{
  uint64_t expected = UINT64_C(1000000);
  std::string string = "0.01";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.01 and random number of zeros following it
TEST(parse_amount, 47)
{
  uint64_t expected = UINT64_C(1000000);
  std::string string = "0.01";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.001
TEST(parse_amount, 48)
{
  uint64_t expected = UINT64_C(100000);
  std::string string = "0.001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.001 and random number of zeros following it
TEST(parse_amount, 49)
{
  uint64_t expected = UINT64_C(100000);
  std::string string = "0.001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.0001
TEST(parse_amount, 50)
{
  uint64_t expected = UINT64_C(10000);
  std::string string = "0.0001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.0001 and random number of zeros following it
TEST(parse_amount, 51)
{
  uint64_t expected = UINT64_C(10000);
  std::string string = "0.0001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.00001
TEST(parse_amount, 52)
{
  uint64_t expected = UINT64_C(1000);
  std::string string = "0.00001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.00001 and random number of zeros following it
TEST(parse_amount, 53)
{
  uint64_t expected = UINT64_C(1000);
  std::string string = "0.00001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.000001
TEST(parse_amount, 54)
{
  uint64_t expected = UINT64_C(100);
  std::string string = "0.000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.000001 and random number of zeros following it
TEST(parse_amount, 55)
{
  uint64_t expected = UINT64_C(100);
  std::string string = "0.000001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.0000001
TEST(parse_amount, 56)
{
  uint64_t expected = UINT64_C(10);
  std::string string = "0.0000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.0000001 and random number of zeros following it
TEST(parse_amount, 57)
{
  uint64_t expected = UINT64_C(10);
  std::string string = "0.0000001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.00000001
TEST(parse_amount, 58)
{
  uint64_t expected = UINT64_C(1);
  std::string string = "0.00000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.00000001 and random number of zeros following it
TEST(parse_amount, 59)
{
  uint64_t expected = UINT64_C(1);
  std::string string = "0.00000001";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.000000001
TEST(parse_amount, 60)
{
  std::string string = "0.000000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// string of zeros and a one, zero and one decimal at beginning, 2
TEST(parse_amount, 61)
{
  uint64_t expected = UINT64_C(1);
  std::string string = "0.000000010";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros and a one, zero and one decimal at beginning, 3
TEST(parse_amount, 62)
{
  uint64_t expected = UINT64_C(1);
  std::string string = "0.000000010000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 8 or more leading zeros and then a one
TEST(parse_amount, 63)
{
  int numLeadZeros = rand() % 100 + 8;
  int numTrailZeros = rand() % 100;

  std::string string = "0.";

  for (int i = 0; i < numLeadZeros; i++)
  {
    string += "0";
  }

  string += "1";

  for (int i = 0; i < numTrailZeros; i++)
  {
    string += "0";
  }

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

//////////////////////////////////////////////////////////////////////////

// 0.2
TEST(parse_amount, 64)
{
  uint64_t expected = UINT64_C(20000000);
  std::string string = "0.2";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.2 and random number of zeros following it
TEST(parse_amount, 65)
{
  uint64_t expected = UINT64_C(20000000);
  std::string string = "0.2";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.02
TEST(parse_amount, 66)
{
  uint64_t expected = UINT64_C(2000000);
  std::string string = "0.02";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.02 and random number of zeros following it
TEST(parse_amount, 67)
{
  uint64_t expected = UINT64_C(2000000);
  std::string string = "0.02";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.002
TEST(parse_amount, 68)
{
  uint64_t expected = UINT64_C(200000);
  std::string string = "0.002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.002 and random number of zeros following it
TEST(parse_amount, 69)
{
  uint64_t expected = UINT64_C(200000);
  std::string string = "0.002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 200;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.0002
TEST(parse_amount, 70)
{
  uint64_t expected = UINT64_C(20000);
  std::string string = "0.0002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.0002 and random number of zeros following it
TEST(parse_amount, 71)
{
  uint64_t expected = UINT64_C(20000);
  std::string string = "0.0002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.00002
TEST(parse_amount, 72)
{
  uint64_t expected = UINT64_C(2000);
  std::string string = "0.00002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.00002 and random number of zeros following it
TEST(parse_amount, 73)
{
  uint64_t expected = UINT64_C(2000);
  std::string string = "0.00002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.000002
TEST(parse_amount, 74)
{
  uint64_t expected = UINT64_C(200);
  std::string string = "0.000002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.000002 and random number of zeros following it
TEST(parse_amount, 75)
{
  uint64_t expected = UINT64_C(200);
  std::string string = "0.000002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.0000002
TEST(parse_amount, 76)
{
  uint64_t expected = UINT64_C(20);
  std::string string = "0.0000002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.0000002 and random number of zeros following it
TEST(parse_amount, 77)
{
  uint64_t expected = UINT64_C(20);
  std::string string = "0.0000002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.00000002
TEST(parse_amount, 78)
{
  uint64_t expected = UINT64_C(2);
  std::string string = "0.00000002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 0.00000002 and random number of zeros following it
TEST(parse_amount, 79)
{
  uint64_t expected = UINT64_C(2);
  std::string string = "0.00000002";

  for (int i = 0; i < 100; i++)
  {
    int numZeros = rand() % 100;

    for (int j = 0; j < numZeros; j++)
    {      
      string += "0";
    }

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// 0.000000002
TEST(parse_amount, 80)
{
  std::string string = "0.000000002";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// string of zeros and a two, zero and one decimal at beginning, 2
TEST(parse_amount, 81)
{
  uint64_t expected = UINT64_C(2);
  std::string string = "0.000000020";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// string of zeros and a two, zero and one decimal at beginning, 3
TEST(parse_amount, 82)
{
  uint64_t expected = UINT64_C(2);
  std::string string = "0.000000020000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// 8 or more leading zeros and then a two
TEST(parse_amount, 83)
{
  int numLeadZeros = rand() % 100 + 8;
  int numTrailZeros = rand() % 100;

  std::string string = "0.";

  for (int i = 0; i < numLeadZeros; i++)
  {
    string += "0";
  }

  string += "2";

  for (int i = 0; i < numTrailZeros; i++)
  {
    string += "0";
  }

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

TEST(parse_amount, 84)
{
  uint64_t expected = UINT64_C(9);
  std::string string = "0.00000009";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 85)
{
  uint64_t expected = UINT64_C(9);
  std::string string = "0.000000090";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 86)
{
  uint64_t expected = UINT64_C(9);
  std::string string = "0.000000090000000000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 87)
{
  uint64_t expected = UINT64_C(12345678);
  std::string string = "0.12345678";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 88)
{
  uint64_t expected = UINT64_C(100000000);
  std::string string = "1";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 89)
{
  uint64_t expected = UINT64_C(6553500000000);
  std::string string = "65535";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 90)
{
  uint64_t expected = UINT64_C(429496729500000000);
  std::string string = "4294967295";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 91)
{
  uint64_t expected = UINT64_C(18446744073700000000);
  std::string string = "184467440737.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 92)
{
  uint64_t expected = UINT64_C(18446744073700000000);
  std::string string = "184467440737.0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 93)
{
  uint64_t expected = UINT64_C(18446744073700000000);
  std::string string = "184467440737.00000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 94)
{
  uint64_t expected = UINT64_C(18446744073700000000);
  std::string string = "184467440737.000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 95)
{
  uint64_t expected = UINT64_C(18446744073700000000);
  std::string string = "184467440737.0000000000000000000";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 96)
{
  uint64_t expected = UINT64_C(18446744073709551615);
  std::string string = "184467440737.09551615";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

TEST(parse_amount, 97)
{
  for(int i = 0; i < 100; i++ )
  {
    // get random amount that does not overflow
    uint64_t randAmount = rand() % 184467440738;

    // add 8 zeros to the end of the number
    uint64_t expected = randAmount * 100000000;

    std::string string = std::to_string(randAmount);

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

// random amount after decimal
// example: "0.12345678" produces 12345678, "0.002" produces 200000
TEST(parse_amount, 98)
{
  for(int i = 0; i < 100; i++ )
  {
    // get random amount between 0 and 99999999
    uint64_t randAmount = rand() % 100000000;

    std::string string = std::to_string(randAmount);

    int randAmountLength = string.length();

    int numZeros = TEST_NUMBER_OF_DECIMAL_PLACES - randAmountLength;

    uint64_t expected = randAmount * pow(10, numZeros);

    string = "0." + string;

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}

/*
// random amount before and after decimal
// example: "111222333444.12345678" produces 111222333444.12345678
TEST(parse_amount, 988)
{
  for(int i = 0; i < 100; i++ )
  {
    // get random amount that does not overflow
    uint64_t randAmountBeforeDecimal = rand() % 184467440738;

    // get random amount between 0 and 99999999
    uint64_t randAmountAfterDecimal = rand() % 100000000;

    std::string randAmountBeforeDecimalStr = std::to_string(randAmountBeforeDecimal);
    std::string randAmountAfterDecimalStr = std::to_string(randAmountAfterDecimal);

    int randAmountAfterDecimalStrLength = randAmountAfterDecimalStr.length();

    int numZeros = TEST_NUMBER_OF_DECIMAL_PLACES - randAmountAfterDecimalStrLength;

    uint64_t expected = randAmountBeforeDecimal * pow(10, TEST_NUMBER_OF_DECIMAL_PLACES) + randAmountAfterDecimal * pow(10, numZeros);

    std::string string = randAmountBeforeDecimalStr + "." + randAmountAfterDecimalStr;

    Logging::LoggerGroup logger;
    CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
    
    uint64_t val;

    ASSERT_TRUE(currency.parseAmount(string, val));
    ASSERT_EQ(expected, val);
  }
}
*/

TEST(parse_amount, 99)
{
  uint64_t expected = UINT64_C(18446744073709551615);
  std::string string = "184467440737.09551615";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_TRUE(currency.parseAmount(string, val));
  ASSERT_EQ(expected, val);
}

// Invalid numbers 1
TEST(parse_amount, 100)
{
  std::string string = "";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// Invalid numbers 2
TEST(parse_amount, 101)
{
  std::string string = "-0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// Invalid numbers 3
TEST(parse_amount, 102)
{
  std::string string = "+0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// Invalid numbers 4
TEST(parse_amount, 103)
{
  std::string string = "-1";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// Invalid numbers 5
TEST(parse_amount, 104)
{
  std::string string = "+1";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// Invalid numbers 6
TEST(parse_amount, 105)
{
  std::string string = ".";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// more than 8 zeros after the decimal 1
TEST(parse_amount, 106)
{
  std::string string = "0.000000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// more than 8 zeros after the decimal 2
TEST(parse_amount, 107)
{
  std::string string = "0.000000009";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// more than 8 zeros after the decimal 2
TEST(parse_amount, 108)
{
  std::string string = "184467440737.000000001";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// overflow 1
TEST(parse_amount, 109)
{
  std::string string = "184467440737.09551616";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// overflow 2
TEST(parse_amount, 110)
{
  std::string string = "184467440738";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// overflow 3
TEST(parse_amount, 111)
{
  std::string string = "18446744073709551616";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 1
TEST(parse_amount, 112)
{
  std::string string = "..";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 2
TEST(parse_amount, 113)
{
  std::string string = "0..";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 3
TEST(parse_amount, 114)
{
  std::string string = "..0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 4
TEST(parse_amount, 115)
{
  std::string string = "0..0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 5
TEST(parse_amount, 116)
{
  std::string string = "0.0.";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 6
TEST(parse_amount, 117)
{
  std::string string = ".0.0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

// two or more decimals 7
TEST(parse_amount, 118)
{
  std::string string = "0.0.0";

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).numberOfDecimalPlaces(TEST_NUMBER_OF_DECIMAL_PLACES).currency();
  
  uint64_t val;

  ASSERT_FALSE(currency.parseAmount(string, val));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"

#include <cstdint>
#include <vector>

#include "CryptoNoteCore/CryptoNoteFormatUtils.h"

struct chunk_handler_t
{
  void operator()(uint64_t chunk) const
  {
    m_chunks.push_back(chunk);
  }

  void clear()
  {
    m_chunks.clear();
  }

  mutable std::vector<uint64_t> m_chunks;
};

struct dust_handler_t
{
  dust_handler_t()
    : m_dust(0)
    , m_has_dust(false)
  {
  }

  void operator()(uint64_t dust) const
  {
    m_dust = dust;
    m_has_dust = true;
  }

  void clear()
  {
    m_dust = 0;
    m_has_dust = false;
  }

  mutable uint64_t m_dust;
  mutable bool m_has_dust;
};

class decompose_amount_into_digits_test : public ::testing::Test
{
protected:
  chunk_handler_t m_chunk_handler;
  dust_handler_t m_dust_handler;
};

// amount equals zero 1
TEST_F(decompose_amount_into_digits_test, 1)
{
  uint64_t amount = 0;
  uint64_t dust = 0;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equals zero 2
TEST_F(decompose_amount_into_digits_test, 2)
{
  uint64_t amount = 0;
  uint64_t dust = 1;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equals zero 3
TEST_F(decompose_amount_into_digits_test, 3)
{
  uint64_t amount = 0;
  uint64_t dust = 3;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equals zero 4
TEST_F(decompose_amount_into_digits_test, 4)
{
  uint64_t amount = 0;
  uint64_t dust = 4;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equals zero 5
TEST_F(decompose_amount_into_digits_test, 5)
{
  uint64_t amount = 0;
  uint64_t dust = 5;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equals zero random 6
TEST_F(decompose_amount_into_digits_test, 6)
{
  uint64_t amount = 0;

  for (int i = 0; i < 100; i++)
  {
    uint64_t dust = rand();

    CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
    
    ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
    
    ASSERT_FALSE(m_dust_handler.m_has_dust);
    ASSERT_EQ(m_dust_handler.m_dust, 0);

    m_chunk_handler.clear();
    m_dust_handler.clear();
  }
}

// amount less than dust 1
TEST_F(decompose_amount_into_digits_test, 7)
{
  uint64_t amount = 1;
  uint64_t dust = 2;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 1);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount less than dust 2
TEST_F(decompose_amount_into_digits_test, 8)
{
  uint64_t amount = 2;
  uint64_t dust = 3;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 2);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount less than dust 3
TEST_F(decompose_amount_into_digits_test, 9)
{
  uint64_t amount = 3;
  uint64_t dust = 4;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 3);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount less than dust 4
TEST_F(decompose_amount_into_digits_test, 10)
{
  uint64_t amount = 4;
  uint64_t dust = 5;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 4);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount less than dust 5
TEST_F(decompose_amount_into_digits_test, 11)
{
  uint64_t amount = 8100;
  uint64_t dust = 1000000;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
  
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 8100);
}

// amount less than dust 6
TEST_F(decompose_amount_into_digits_test, 12)
{
  for (int i = 0; i < 100; i++)
  {
    uint64_t dust = rand();
    uint64_t amount = dust - 1;

    CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
    
    ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
   
    ASSERT_TRUE(m_dust_handler.m_has_dust);
    ASSERT_EQ(m_dust_handler.m_dust, amount);

    m_chunk_handler.clear();
    m_dust_handler.clear();
  }
}

// amount equal to dust 1
TEST_F(decompose_amount_into_digits_test, 13)
{
  uint64_t amount = 1;
  uint64_t dust = 1;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 1);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equal to dust 2
TEST_F(decompose_amount_into_digits_test, 14)
{
  uint64_t amount = 2;
  uint64_t dust = 2;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 2);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equal to dust 3
TEST_F(decompose_amount_into_digits_test, 15)
{
  uint64_t amount = 3;
  uint64_t dust = 3;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 3);

  m_chunk_handler.clear();
  m_dust_handler.clear();
}

// amount equal to dust 4
TEST_F(decompose_amount_into_digits_test, 16)
{
  uint64_t amount = 10;
  uint64_t dust = 10;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  // amount must be greater than dust to be included in chunk
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
 
  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 10);
}

// amount equal to dust random 5
TEST_F(decompose_amount_into_digits_test, 17)
{
  for (int i = 0; i < 100; i++)
  {
    uint64_t dust = rand();
    uint64_t amount = dust;

    CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
    
    ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 0);
   
    ASSERT_TRUE(m_dust_handler.m_has_dust);
    ASSERT_EQ(m_dust_handler.m_dust, amount);

    m_chunk_handler.clear();
    m_dust_handler.clear();
  }
}

// amount greater than dust 1
TEST_F(decompose_amount_into_digits_test, 18)
{
  uint64_t amount = 10;
  uint64_t dust = 0;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);

  ASSERT_EQ(m_chunk_handler.m_chunks[0], 10);
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 1);
  
  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);
}

// amount greater than dust 2
TEST_F(decompose_amount_into_digits_test, 19)
{ 
  uint64_t amount = 8900100;
  uint64_t dust = 10;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);
  
  ASSERT_EQ(m_chunk_handler.m_chunks[0], 100);
  ASSERT_EQ(m_chunk_handler.m_chunks[1], 900000);
  ASSERT_EQ(m_chunk_handler.m_chunks[2], 8000000);
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 3);

  ASSERT_FALSE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 0);
}

// amount greater than dust 3
TEST_F(decompose_amount_into_digits_test, 20)
{
  uint64_t amount = 8900100;
  uint64_t dust = 1000;

  CryptoNote::decompose_amount_into_digits(amount, dust, m_chunk_handler, m_dust_handler);

  ASSERT_EQ(m_chunk_handler.m_chunks[0], 900000);
  ASSERT_EQ(m_chunk_handler.m_chunks[1], 8000000);
  ASSERT_TRUE(m_chunk_handler.m_chunks.size() == 2);

  ASSERT_TRUE(m_dust_handler.m_has_dust);
  ASSERT_EQ(m_dust_handler.m_dust, 100);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <string>
#include <cstdint>
#include <vector>
#include <bitset>
#include "crypto/blake2.h"
#include "Common/StringTools.h"
#include "CryptoNote.h"
#include "gtest/gtest.h"
#include "CryptoNoteCore/CryptoNoteTools.h"

bool blake2b32(CryptoNote::BinaryArray ba, Crypto::Hash& hash)
{
  size_t hashLength = 32;
  int result = blake2b(&hash, hashLength, ba.data(), ba.size(), nullptr, 0);

  if (result == -1)
  {
    return false;
  }

  return true;
}

bool hash_arbtx(std::string arbtx, Crypto::Hash& arbtx_hash_bin)
{

  uint8_t data[121];

  // prepend byte with value of 0 to follow Siacoin stratum protocol
  data[0] = 0;

  Common::fromHex(arbtx, data + 1, 120);

  CryptoNote::BinaryArray ba(std::begin(data), std::end(data));

  return blake2b32(ba, arbtx_hash_bin);
}

void build_merkle_root(const std::vector<std::string>& merkle_branch, const Crypto::Hash& arbtx_hash_bin, Crypto::Hash& merkle_root)
{
  merkle_root = arbtx_hash_bin;

  CryptoNote::BinaryArray ba;

  for (std::size_t h = 0; h < merkle_branch.size(); h++)
  {
    // prepend byte with value of 1 to follow Siacoin stratum protocol
    ba.push_back(1);

    // append merkle leaf hash string to binary array
    uint8_t data[32];
    Common::fromHex(merkle_branch[h], data, 32);
    ba.insert(std::end(ba), std::begin(data), std::end(data));

    // append merkle root to binary array
    ba.insert(std::end(ba), std::begin(merkle_root.data), std::end(merkle_root.data));

    // hash the binary array to get the merkle root
    blake2b32(ba, merkle_root);

    // reset binary array for next loop
    ba.clear();
  }
}

TEST(Stratum, 1)
{
  // Block 86011
  // Hash 000000000000007384ca7ba61a988d14f9a9d731a981c186e8904f1e1d82e6f5

  std::string prevhash = "0000000000000079039da6f4d7790d54d774812f92e459387846524f4024afe3";
  std::string coinb1 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020000000000000004e6f6e536961000000000000000000006aba4dfb5df01095";
  std::string coinb2 = "0000000000000000";
  std::vector<std::string> merkle_branch =
  {
    "25cc1c464ed8f0a13da6c14098c2cd47526dcd64d3594a2ace794b9bc0ab704d",
    "2c162ebd012c0044cd34808a0dc9e5790f428cba73ce7b848a6f63ddd845c80e",
    "20283c26aa6cf99c126fe74021f2c5fb39baffd81814d725c57c883e16676c5d",
  };
  std::string ntime = "2ed1705800000000";
  std::string extranonce1 = "99cfbade";
  std::string extranonce2 = "ef7488b3";
  std::string nonce = "40371d049700e893";

  std::string arbtx = coinb1 + extranonce1 + extranonce2 + coinb2;

  ASSERT_EQ(arbtx, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000020000000000000004e6f6e536961000000000000000000006aba4dfb5df0109599cfbadeef7488b30000000000000000");

  Crypto::Hash arbtx_hash_bin;
  hash_arbtx(arbtx, arbtx_hash_bin);

  // goal arbtx_hash_bin = #d995219bcc23497f6e7d44db94aeb9e15482d8c2466088c0bf7d4ded0792ef23

  ASSERT_EQ(0xd9, arbtx_hash_bin.data[0]);
  ASSERT_EQ(0x95, arbtx_hash_bin.data[1]);
  ASSERT_EQ(0x21, arbtx_hash_bin.data[2]);
  ASSERT_EQ(0x9b, arbtx_hash_bin.data[3]);
  ASSERT_EQ(0xcc, arbtx_hash_bin.data[4]);
  ASSERT_EQ(0x23, arbtx_hash_bin.data[5]);
  ASSERT_EQ(0x49, arbtx_hash_bin.data[6]);
  ASSERT_EQ(0x7f, arbtx_hash_bin.data[7]);
  ASSERT_EQ(0x6e, arbtx_hash_bin.data[8]);
  ASSERT_EQ(0x7d, arbtx_hash_bin.data[9]);
  ASSERT_EQ(0x44, arbtx_hash_bin.data[10]);
  ASSERT_EQ(0xdb, arbtx_hash_bin.data[11]);
  ASSERT_EQ(0x94, arbtx_hash_bin.data[12]);
  ASSERT_EQ(0xae, arbtx_hash_bin.data[13]);
  ASSERT_EQ(0xb9, arbtx_hash_bin.data[14]);
  ASSERT_EQ(0xe1, arbtx_hash_bin.data[15]);
  ASSERT_EQ(0x54, arbtx_hash_bin.data[16]);
  ASSERT_EQ(0x82, arbtx_hash_bin.data[17]);
  ASSERT_EQ(0xd8, arbtx_hash_bin.data[18]);
  ASSERT_EQ(0xc2, arbtx_hash_bin.data[19]);
  ASSERT_EQ(0x46, arbtx_hash_bin.data[20]);
  ASSERT_EQ(0x60, arbtx_hash_bin.data[21]);
  ASSERT_EQ(0x88, arbtx_hash_bin.data[22]);
  ASSERT_EQ(0xc0, arbtx_hash_bin.data[23]);
  ASSERT_EQ(0xbf, arbtx_hash_bin.data[24]);
  ASSERT_EQ(0x7d, arbtx_hash_bin.data[25]);
  ASSERT_EQ(0x4d, arbtx_hash_bin.data[26]);
  ASSERT_EQ(0xed, arbtx_hash_bin.data[27]);
  ASSERT_EQ(0x07, arbtx_hash_bin.data[28]);
  ASSERT_EQ(0x92, arbtx_hash_bin.data[29]);
  ASSERT_EQ(0xef, arbtx_hash_bin.data[30]);
  ASSERT_EQ(0x23, arbtx_hash_bin.data[31]);

  Crypto::Hash merkle_root_bin;

  // convert merkle branch array into vector
  std::vector<std::string> merkle_branch_vector(std::begin(merkle_branch), std::end(merkle_branch));

  build_merkle_root(merkle_branch_vector, arbtx_hash_bin, merkle_root_bin);

  // merkle_root_bin =
  // {
  //    0x74, 0xe5, 0xfe, 0xbb, 0x35, 0x2c, 0xd3, 0x3e, 0xe2, 0xf1,
  //    0xb0, 0x4f, 0xfa, 0xb6, 0x3b, 0xda, 0xeb, 0x53, 0xbc, 0xc7,
  //    0xbf, 0x16, 0x77, 0x96, 0x18, 0x5a, 0xca, 0xd2, 0x61, 0xec,
  //    0x10, 0x7b
  //    }

  // goal merkle_root_bin = 74e5febb352cd33ee2f1b04ffab63bdaeb53bcc7bf167796185acad261ec107b

  ASSERT_EQ(0x74, merkle_root_bin.data[0]);
  ASSERT_EQ(0xe5, merkle_root_bin.data[1]);
  ASSERT_EQ(0xfe, merkle_root_bin.data[2]);
  ASSERT_EQ(0xbb, merkle_root_bin.data[3]);
  ASSERT_EQ(0x35, merkle_root_bin.data[4]);
  ASSERT_EQ(0x2c, merkle_root_bin.data[5]);
  ASSERT_EQ(0xd3, merkle_root_bin.data[6]);
  ASSERT_EQ(0x3e, merkle_root_bin.data[7]);
  ASSERT_EQ(0xe2, merkle_root_bin.data[8]);
  ASSERT_EQ(0xf1, merkle_root_bin.data[9]);
  ASSERT_EQ(0xb0, merkle_root_bin.data[10]);
  ASSERT_EQ(0x4f, merkle_root_bin.data[11]);
  ASSERT_EQ(0xfa, merkle_root_bin.data[12]);
  ASSERT_EQ(0xb6, merkle_root_bin.data[13]);
  ASSERT_EQ(0x3b, merkle_root_bin.data[14]);
  ASSERT_EQ(0xda, merkle_root_bin.data[15]);
  ASSERT_EQ(0xeb, merkle_root_bin.data[16]);
  ASSERT_EQ(0x53, merkle_root_bin.data[17]);
  ASSERT_EQ(0xbc, merkle_root_bin.data[18]);
  ASSERT_EQ(0xc7, merkle_root_bin.data[19]);
  ASSERT_EQ(0xbf, merkle_root_bin.data[20]);
  ASSERT_EQ(0x16, merkle_root_bin.data[21]);
  ASSERT_EQ(0x77, merkle_root_bin.data[22]);
  ASSERT_EQ(0x96, merkle_root_bin.data[23]);
  ASSERT_EQ(0x18, merkle_root_bin.data[24]);
  ASSERT_EQ(0x5a, merkle_root_bin.data[25]);
  ASSERT_EQ(0xca, merkle_root_bin.data[26]);
  ASSERT_EQ(0xd2, merkle_root_bin.data[27]);
  ASSERT_EQ(0x61, merkle_root_bin.data[28]);
  ASSERT_EQ(0xec, merkle_root_bin.data[29]);
  ASSERT_EQ(0x10, merkle_root_bin.data[30]);
  ASSERT_EQ(0x7b, merkle_root_bin.data[31]);

  // merkle_root = hexlify(merkle_root_bin).decode("ascii")

  std::string merkle_root = Common::toHex(merkle_root_bin.data, 32);

  ASSERT_EQ(merkle_root, "74e5febb352cd33ee2f1b04ffab63bdaeb53bcc7bf167796185acad261ec107b");

  std::string header = prevhash + nonce + ntime + merkle_root;

  ASSERT_EQ(header, "0000000000000079039da6f4d7790d54d774812f92e459387846524f4024afe340371d049700e8932ed170580000000074e5febb352cd33ee2f1b04ffab63bdaeb53bcc7bf167796185acad261ec107b");

  // convert header string to binary array
  uint8_t headerData[80];
  Common::podFromHex(header, headerData);
  CryptoNote::BinaryArray header_bin(std::begin(headerData), std::end(headerData));

  ASSERT_EQ(0x00, header_bin[0]);
  ASSERT_EQ(0x00, header_bin[1]);
  ASSERT_EQ(0x00, header_bin[2]);
  ASSERT_EQ(0x00, header_bin[3]);
  ASSERT_EQ(0x00, header_bin[4]);
  ASSERT_EQ(0x00, header_bin[5]);
  ASSERT_EQ(0x00, header_bin[6]);
  ASSERT_EQ(0x79, header_bin[7]);
  ASSERT_EQ(0x03, header_bin[8]);
  ASSERT_EQ(0x9d, header_bin[9]);
  ASSERT_EQ(0xa6, header_bin[10]);
  ASSERT_EQ(0xf4, header_bin[11]);
  ASSERT_EQ(0xd7, header_bin[12]);
  ASSERT_EQ(0x79, header_bin[13]);
  ASSERT_EQ(0x0d, header_bin[14]);
  ASSERT_EQ(0x54, header_bin[15]);
  ASSERT_EQ(0xd7, header_bin[16]);
  ASSERT_EQ(0x74, header_bin[17]);
  ASSERT_EQ(0x81, header_bin[18]);
  ASSERT_EQ(0x2f, header_bin[19]);
  ASSERT_EQ(0x92, header_bin[20]);
  ASSERT_EQ(0xe4, header_bin[21]);
  ASSERT_EQ(0x59, header_bin[22]);
  ASSERT_EQ(0x38, header_bin[23]);
  ASSERT_EQ(0x78, header_bin[24]);
  ASSERT_EQ(0x46, header_bin[25]);
  ASSERT_EQ(0x52, header_bin[26]);
  ASSERT_EQ(0x4f, header_bin[27]);
  ASSERT_EQ(0x40, header_bin[28]);
  ASSERT_EQ(0x24, header_bin[29]);
  ASSERT_EQ(0xaf, header_bin[30]);
  ASSERT_EQ(0xe3, header_bin[31]);
  ASSERT_EQ(0x40, header_bin[32]);
  ASSERT_EQ(0x37, header_bin[33]);
  ASSERT_EQ(0x1d, header_bin[34]);
  ASSERT_EQ(0x04, header_bin[35]);
  ASSERT_EQ(0x97, header_bin[36]);
  ASSERT_EQ(0x00, header_bin[37]);
  ASSERT_EQ(0xe8, header_bin[38]);
  ASSERT_EQ(0x93, header_bin[39]);
  ASSERT_EQ(0x2e, header_bin[40]);
  ASSERT_EQ(0xd1, header_bin[41]);
  ASSERT_EQ(0x70, header_bin[42]);
  ASSERT_EQ(0x58, header_bin[43]);
  ASSERT_EQ(0x00, header_bin[44]);
  ASSERT_EQ(0x00, header_bin[45]);
  ASSERT_EQ(0x00, header_bin[46]);
  ASSERT_EQ(0x00, header_bin[47]);
  ASSERT_EQ(0x74, header_bin[48]);
  ASSERT_EQ(0xe5, header_bin[49]);
  ASSERT_EQ(0xfe, header_bin[50]);
  ASSERT_EQ(0xbb, header_bin[51]);
  ASSERT_EQ(0x35, header_bin[52]);
  ASSERT_EQ(0x2c, header_bin[53]);
  ASSERT_EQ(0xd3, header_bin[54]);
  ASSERT_EQ(0x3e, header_bin[55]);
  ASSERT_EQ(0xe2, header_bin[56]);
  ASSERT_EQ(0xf1, header_bin[57]);
  ASSERT_EQ(0xb0, header_bin[58]);
  ASSERT_EQ(0x4f, header_bin[59]);
  ASSERT_EQ(0xfa, header_bin[60]);
  ASSERT_EQ(0xb6, header_bin[61]);
  ASSERT_EQ(0x3b, header_bin[62]);
  ASSERT_EQ(0xda, header_bin[63]);
  ASSERT_EQ(0xeb, header_bin[64]);
  ASSERT_EQ(0x53, header_bin[65]);
  ASSERT_EQ(0xbc, header_bin[66]);
  ASSERT_EQ(0xc7, header_bin[67]);
  ASSERT_EQ(0xbf, header_bin[68]);
  ASSERT_EQ(0x16, header_bin[69]);
  ASSERT_EQ(0x77, header_bin[70]);
  ASSERT_EQ(0x96, header_bin[71]);
  ASSERT_EQ(0x18, header_bin[72]);
  ASSERT_EQ(0x5a, header_bin[73]);
  ASSERT_EQ(0xca, header_bin[74]);
  ASSERT_EQ(0xd2, header_bin[75]);
  ASSERT_EQ(0x61, header_bin[76]);
  ASSERT_EQ(0xec, header_bin[77]);
  ASSERT_EQ(0x10, header_bin[78]);
  ASSERT_EQ(0x7b, header_bin[79]);

  Crypto::Hash block_header_hash;
  blake2b32(header_bin, block_header_hash);

  // goal block_header_hash = 000000000000007384ca7ba61a988d14f9a9d731a981c186e8904f1e1d82e6f5

  ASSERT_EQ(0x00, block_header_hash.data[0]);
  ASSERT_EQ(0x00, block_header_hash.data[1]);
  ASSERT_EQ(0x00, block_header_hash.data[2]);
  ASSERT_EQ(0x00, block_header_hash.data[3]);
  ASSERT_EQ(0x00, block_header_hash.data[4]);
  ASSERT_EQ(0x00, block_header_hash.data[5]);
  ASSERT_EQ(0x00, block_header_hash.data[6]);
  ASSERT_EQ(0x73, block_header_hash.data[7]);
  ASSERT_EQ(0x84, block_header_hash.data[8]);
  ASSERT_EQ(0xca, block_header_hash.data[9]);
  ASSERT_EQ(0x7b, block_header_hash.data[10]);
  ASSERT_EQ(0xa6, block_header_hash.data[11]);
  ASSERT_EQ(0x1a, block_header_hash.data[12]);
  ASSERT_EQ(0x98, block_header_hash.data[13]);
  ASSERT_EQ(0x8d, block_header_hash.data[14]);
  ASSERT_EQ(0x14, block_header_hash.data[15]);
  ASSERT_EQ(0xf9, block_header_hash.data[16]);
  ASSERT_EQ(0xa9, block_header_hash.data[17]);
  ASSERT_EQ(0xd7, block_header_hash.data[18]);
  ASSERT_EQ(0x31, block_header_hash.data[19]);
  ASSERT_EQ(0xa9, block_header_hash.data[20]);
  ASSERT_EQ(0x81, block_header_hash.data[21]);
  ASSERT_EQ(0xc1, block_header_hash.data[22]);
  ASSERT_EQ(0x86, block_header_hash.data[23]);
  ASSERT_EQ(0xe8, block_header_hash.data[24]);
  ASSERT_EQ(0x90, block_header_hash.data[25]);
  ASSERT_EQ(0x4f, block_header_hash.data[26]);
  ASSERT_EQ(0x1e, block_header_hash.data[27]);
  ASSERT_EQ(0x1d, block_header_hash.data[28]);
  ASSERT_EQ(0x82, block_header_hash.data[29]);
  ASSERT_EQ(0xe6, block_header_hash.data[30]);
  ASSERT_EQ(0xf5, block_header_hash.data[31]);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
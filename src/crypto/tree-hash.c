// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <alloca.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "hash-ops.h"

void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash)
{
  
  assert(count > 0);

  // first hash in hashes should be the coinbase transaction hash
  memcpy(root_hash, hashes[0], HASH_SIZE);

  for (size_t h = 1; h < count; h++)
  {
    char binaryArray[2 * HASH_SIZE + 1];

    // prepend byte with value of 1 to follow Siacoin stratum protocol
    binaryArray[0] = 1;

    // append transaction hash to binary array
    memcpy(binaryArray + 1, hashes[h], HASH_SIZE);

    // append merkle root to binary array
    memcpy(binaryArray + 1 + HASH_SIZE, root_hash, HASH_SIZE);

    // hash the binary array to get the merkle root
    cn_fast_hash(binaryArray, 2 * HASH_SIZE + 1, root_hash);
  }
}
// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <initializer_list>

namespace CryptoNote {
namespace parameters {

const uint64_t DIFFICULTY_TARGET                             = 9; // seconds

const uint64_t CRYPTONOTE_MAX_BLOCK_NUMBER                   = 500000000;
const size_t   CRYPTONOTE_MAX_BLOCK_BLOB_SIZE                = 500000000;
const size_t   CRYPTONOTE_MAX_TX_SIZE                        = 1000000000;
const uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX       = 0x6; // all Cash2 addresses start with a '2'

const size_t   CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_1        = 60;
const size_t   CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_2        = 400;
const size_t   CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW          = CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_2;

const uint64_t CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT            = 60 * 60 * 2;
const size_t   BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW             = 60;
const uint64_t MONEY_SUPPLY                                  = UINT64_C(15000000000000000); // 15,000,000.000000000 total coins
const unsigned EMISSION_SPEED_FACTOR                         = 24;

static_assert(EMISSION_SPEED_FACTOR <= 8 * sizeof(uint64_t), "Bad EMISSION_SPEED_FACTOR");

const size_t   CRYPTONOTE_REWARD_BLOCKS_WINDOW               = 60 * 24 * 60 * 60 / DIFFICULTY_TARGET; // number of blocks produced in 60 days
const size_t   CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE     = 200 * 1024; //size of block (bytes) after which reward for block calculated using block size, 200 kb
const size_t   CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE        = 600;
const size_t   CRYPTONOTE_DISPLAY_DECIMAL_POINT              = 9; // number of digits after decimal point

const uint64_t MINIMUM_FEE_1                                 = UINT64_C(0); // free transactions
const uint64_t MINIMUM_FEE_2                                 = UINT64_C(10000000); // 0.01
const uint64_t MINIMUM_FEE                                   = MINIMUM_FEE_2;

const uint64_t DEFAULT_DUST_THRESHOLD_1                      = MINIMUM_FEE_1;
const uint64_t DEFAULT_DUST_THRESHOLD_2                      = MINIMUM_FEE_2;
const uint64_t DEFAULT_DUST_THRESHOLD_3                      = UINT64_C(0);
const uint64_t DEFAULT_DUST_THRESHOLD                        = DEFAULT_DUST_THRESHOLD_3;

const uint64_t MAX_MIXIN                                     = 3;
const size_t   DIFFICULTY_WINDOW                             = 3600; // blocks, number of blocks expected in 9 hours
const size_t   DIFFICULTY_CUT                                = 60;  // timestamps to cut after sorting
const size_t   DIFFICULTY_LAG                                = 15;

static_assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2, "Bad DIFFICULTY_WINDOW or DIFFICULTY_CUT");

const size_t   MAX_BLOCK_SIZE_INITIAL                        = 400 * 1024; // 400 kb
const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR         = 100 * 1024;
const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR       = 365 * 24 * 60 * 60 / DIFFICULTY_TARGET;
const uint64_t MAX_TX_EXTRA_SIZE                             = 256;
const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS     = 1;
const uint64_t CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS    = DIFFICULTY_TARGET * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;
const uint64_t CRYPTONOTE_MEMPOOL_TX_LIVETIME                = 60 * 60; //seconds, 1 hour
const uint64_t CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 60 * 60; //seconds, 1 hour
const uint64_t CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL = 1;  // CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL * CRYPTONOTE_MEMPOOL_TX_LIVETIME = time to forget tx
const size_t   FUSION_TX_MAX_SIZE                            = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE * 30 / 100;
const size_t   FUSION_TX_MIN_INPUT_COUNT                     = 12;
const size_t   FUSION_TX_MIN_IN_OUT_COUNT_RATIO              = 4;
const char     CRYPTONOTE_BLOCKS_FILENAME[]                  = "blocks.dat";
const char     CRYPTONOTE_BLOCKINDEXES_FILENAME[]            = "blockindexes.dat";
const char     CRYPTONOTE_BLOCKSCACHE_FILENAME[]             = "blockscache.dat";
const char     CRYPTONOTE_POOLDATA_FILENAME[]                = "poolstate.bin";
const char     P2P_NET_DATA_FILENAME[]                       = "p2pstate.bin";
const char     CRYPTONOTE_BLOCKCHAIN_INDEXES_FILENAME[]      = "blockchainindexes.dat";
const char     MINER_CONFIG_FILE_NAME[]                      = "miner_conf.json";

// HARD_FORK_HEIGHT_1 was originally set to height 230,500 but was later removed from the code because
// all blocks prior to height 230,500 followed the new consensus rules implemented
// Therefore, a hard fork did not really occur at height 230,500
// const uint64_t HARD_FORK_HEIGHT_1                            = 230500;

// HARD_FORK_HEIGHT_2 fixes integer overflow problem with calculating the next block diffiuclty using cummulative difficulties
const uint64_t HARD_FORK_HEIGHT_2                            = 420016;

// SOFT_FORK_HEIGHT_1 increases the minimum fee from 0 to 0.01 and also adds other measures to prevent blockchain spamming
const uint64_t SOFT_FORK_HEIGHT_1                            = 1100000;

// HARD_FORK_HEIGHT_3 increases the time needed to unlock a mined block from 60 blocks to 400 blocks
// Also fixes missed default dust threshold calculations based on blockchain height in constructMinerTx1(), constructMinerTx2(), isFusionTransaction() and isAmountApplicableInFusionTransactionInput() in Currency.cpp
const uint64_t HARD_FORK_HEIGHT_3                            = 1700000;

} // end namespace parameters

const char     CRYPTONOTE_NAME[]                             = "cash2";
const char     GENESIS_COINBASE_TX_HEX[]                     = "013c01ff0001a7d7a9aa03028037deeee59fb526b6474696bd4246c21b2e7dbd4fc17a02a6037ca6835e3a4f2101f6632c8a6d6102c85597eaccb5c0be3880b7220aee0d0e4c5b852d8757f5b67f";
const uint8_t  CURRENT_TRANSACTION_VERSION                   = 1;
const size_t   BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT        = 10000;  //by default, blocks ids count in synchronizing
const size_t   BLOCKS_SYNCHRONIZING_DEFAULT_COUNT            = 20;    //by default, blocks count in blocks downloading
const size_t   COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT         = 1000;
const int      P2P_DEFAULT_PORT                              = 12275;
const int      RPC_DEFAULT_PORT                              = 12276;
const int      WALLETD_DEFAULT_PORT                          = 12277;
const size_t   P2P_LOCAL_WHITE_PEERLIST_LIMIT                = 1000;
const size_t   P2P_LOCAL_GRAY_PEERLIST_LIMIT                 = 5000;
const size_t   P2P_CONNECTION_MAX_WRITE_BUFFER_SIZE          = 16 * 1024 * 1024; // 16 MB
const uint32_t P2P_DEFAULT_CONNECTIONS_COUNT                 = 8;
const size_t   P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT     = 70;
const uint32_t P2P_DEFAULT_HANDSHAKE_INTERVAL                = 60;            // seconds
const uint32_t P2P_DEFAULT_PACKET_MAX_SIZE                   = 50000000;      // 50000000 bytes maximum packet size
const uint32_t P2P_DEFAULT_PEERS_IN_HANDSHAKE                = 250;
const uint32_t P2P_DEFAULT_CONNECTION_TIMEOUT                = 5000;          // 5 seconds
const uint32_t P2P_DEFAULT_PING_CONNECTION_TIMEOUT           = 2000;          // 2 seconds
const uint64_t P2P_DEFAULT_INVOKE_TIMEOUT                    = 60 * 2 * 1000; // 2 minutes
const size_t   P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT          = 5000;          // 5 seconds
const char     P2P_STAT_TRUSTED_PUB_KEY[]                    = "";
const uint32_t CRYPTONOTE_PROTOCOL_MAX_OBJECT_REQUEST_COUNT  = 500;

//seed nodes
const std::initializer_list<const char*> SEED_NODES = {
  "seed1.cash2.org:12275",
  "seed2.cash2.org:12275",
  "seed3.cash2.org:12275",
};

struct CheckpointData {
  uint32_t height;
  const char* blockId;
};

#ifdef __GNUC__
__attribute__((unused))
#endif

const std::initializer_list<CheckpointData> CHECKPOINTS = {
  {  1,  "114201ae0751311ef8789b5c681829c51fd9a30116501326ebb45460f617e4e4" },
  {  100000,  "be3883bb414d9de59d6e26ffb832cdcd376de8c7cdf5c1540217ad83b6809c4a" },
  {  200000,  "2ec04fb7bcb6528b969d4bc1b5a214d6ed403da75e0555815a642d83502fa295" },
  {  300000,  "1dbb7dffceec87db069c336a9fdb486cda8026418e401c6fb58a698b4587a1b4" },
  {  400000,  "435fa3e236ae492486d7ae0618f1eb195ac1db1c17bd76bfbb708719cb0fba95" },
  {  420016,  "49be5e07598ff9598abd581d75041d73788b8b092f694c41a91cf5e07a90280d" },
  {  500000,  "c013c477d192095db6dec711e3733c45b118d11c2b67c4d803e08327fa0e1bd6" },
  {  600000,  "1b38e6c555b19d2e72d2f764877c90dc2f878b9ca6b70b03e61925bb49eb357f" },
  {  700000,  "05e9d51fe458d5037b0f71f55f59e9df80fbc447dd5cd34727c964be40af8e68" },
  {  800000,  "4f6341b48dc0442e45f20c7704b5b626d7d10e95e46e23bf9617be6c8b94dec4" },
  {  900000,  "73d4b4e0940740e3ad3d9b679cf077600bdb49acd071e643680e91d55b9dba23" },
  {  1000000,  "1a2be4b6d435822a3b3be161e72402304df8162fa591e439b3d87bec78ceb1cd" },
  {  1100000,  "6a1dd97ff53e8b20af1035177cb3041bf87fb92e4d7daa9c3486b5c3c9900305" },
  {  1200000,  "29dba32c25654e9f7f3d54e149a62511bdb6c603c55b2172fa48bccfe9440f76" },
  {  1300000,  "26b6736c821b4b1cbeb7bb2104fb4bc65c9a4dc13cec55138502dbf3a8898e54" },
  {  1400000,  "43ac3e9167e1b8ba6f23b0eb4d6d55629cc0939513a4f6bda0aed32c760a6803" },
  {  1500000,  "f64e974daae697553b84c16991de632253f6745af2b664b5f7da16a2ee57deb4" },
  {  1600000,  "a1dcf2f6d2d9042bbcf865c1861355519126e16e65e7813ecb4072ad1f9510ee" },
  {  1700000,  "4dee5007c5c80f7ba6beddd4f41ec6836db6a363de8a5f11c30da10fcedd045a" },
  {  1800000,  "382756f3194282828d16f49b5aaf7cf6851508ddc636852c8a72cb322fa1a630" },
  {  1900000,  "9e389d3c5afb9125f844ef42bd23a711e9db32223f9e14c313da9cdfb1099aee" },
  {  2000000,  "3637213f5bcad3842ef693a17ed4dee8fb03f806d8e2d5e896bdebeaf64bf9e8" },
  {  2100000,  "b8e28003cbbc68de1c8eaa3571fda874f945a19092572525f2c3819557334bca" },
};

} // end namespace CryptoNote

#define ALLOW_DEBUG_COMMANDS

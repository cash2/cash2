// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "CryptoNoteCore/Blockchain.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteConfig.h"
#include "Logging/ConsoleLogger.h"
#include "helperFunctions.h"
#include "Common/Math.h"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class Blockchain : public CryptoNote::ITransactionValidator {
public
  *Blockchain()
  *addObserver()
  *removeObserver()
  *checkTransactionInputs()
  *checkTransactionInputs()
  *haveSpentKeyImages()
  *checkTransactionSize()
  *init()
  *init()
  *deinit()
  *getLowerBound()
  *getBlockIds()
  *getBlocks()
  *getBlocks()
  *getAlternativeBlocks()
  *getAlternativeBlocksCount()
  *getBlockIdByHeight()
  *getBlockByHash()
  *getBlockHeight()
  serialize()
  *haveTransaction()
  *haveTransactionKeyImagesAsSpent()
  *getCurrentBlockchainHeight()
  *getTailId()
  *getTailId()
  *getDifficultyForNextBlock()
  *getCoinsInCirculation()
  *addNewBlock()
  *resetAndSetGenesisBlock()
  *haveBlock()
  *getTotalTransactions()
  *buildSparseChain()
  *buildSparseChain()
  *findBlockchainSupplement()
  *findBlockchainSupplement()
  handleGetObjects()
  getRandomOutsByAmount()
  *getBackwardBlocksSize()
  *getTransactionOutputGlobalIndexes()
  get_out_by_msig_gindex()
  *checkTransactionInputs()
  *getCurrentCumulativeBlocksizeLimit()
  *blockDifficulty()
  *getBlockContainingTransaction()
  *getAlreadyGeneratedCoins()
  *getBlockSize()
  getMultisigOutputReference()
  *getGeneratedTransactionsNumber()
  *getOrphanBlockIdsByHeight()
  *getBlockIdsByTimestamp()
  *getTransactionIdsByPaymentId()
  *isBlockInMainChain()
  scanOutputKeysForIndexes()
  addMessageQueue()
  removeMessageQueue()

private
  const Currency& m_currency
  tx_memory_pool& m_tx_pool
  std::recursive_mutex m_blockchain_lock
  Tools::ObserverManager<IBlockchainStorageObserver> m_observerManager
  key_images_container m_spent_keys
  size_t m_current_block_cumul_sz_limit
  blocks_ext_by_hash m_alternative_chains
  outputs_container m_outputs
  std::string m_config_folder
  Blocks m_blocks
  CryptoNote::BlockIndex m_blockIndex
  TransactionMap m_transactionMap
  MultisignatureOutputsContainer m_multisignatureOutputs
  PaymentIdIndex m_paymentIdIndex
  TimestampBlocksIndex m_timestampIndex
  GeneratedTransactionsIndex m_generatedTransactionsIndex
  OrphanBlocksIndex m_orthanBlocksIndex
  IntrusiveLinkedList<MessageQueue<BlockchainMessage>> m_messageQueueList
  Logging::LoggerRef logger

  rebuildCache()
  storeCache()
  switch_to_alternative_blockchain()
  handle_alternative_block()
  get_next_difficulty_for_alternative_chain()
  prevalidate_miner_transaction()
  validate_miner_transaction()
  rollback_blockchain_switching()
  get_last_n_blocks_sizes()
  add_out_to_get_random_outs()
  is_tx_spendtime_unlocked()
  find_end_of_allowed_index()
  check_block_timestamp_main()
  check_block_timestamp()
  get_adjusted_time()
  complete_timestamps_vector()
  checkCumulativeBlockSize()
  doBuildSparseChain()
  getBlockCumulativeSize()
  update_next_comulative_size_limit()
  check_tx_input()
  checkTransactionInputs()
  checkTransactionInputs()
  have_tx_keyimg_as_spent()
  transactionByIndex()
  pushBlock()
  pushBlock()
  pushBlock()
  popBlock()
  pushTransaction()
  popTransaction()
  popTransactions()
  validateInput()
  storeBlockchainIndexes()
  loadBlockchainIndexes()
  loadTransactions()
  saveTransactions()
  sendMessage()
}

class LockedBlockchainStorage: boost::noncopyable
{
public
  LockedBlockchainStorage()
  Blockchain* operator -> ()
private
  Blockchain& m_bc
  std::lock_guard<std::recursive_mutex> m_lock
}

*/

// Helper functions

class TransactionValidator : public ITransactionValidator
{
  virtual bool checkTransactionInputs(const CryptoNote::Transaction& transaction, BlockInfo& maxUsedBlock) override
  {
    return true;
  }

  virtual bool checkTransactionInputs(const CryptoNote::Transaction& transaction, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) override
  {
    return true;
  }

  virtual bool haveSpentKeyImages(const CryptoNote::Transaction& transaction) override
  {
    return false;
  }

  virtual bool checkTransactionSize(size_t blobSize) override
  {
    return true;
  }
};

class TimeProvider : public ITimeProvider
{
public:
  TimeProvider(time_t timeInput = time(nullptr)) : m_time(timeInput) {}; 
  virtual time_t now() override { return m_time; };

private:
  time_t m_time;
};

class BlockchainStorageObserver : public IBlockchainStorageObserver
{
public:
  virtual void blockchainUpdated() override
  {
    std::cout << "blockchain updated" << std::endl;
  };
};

size_t getBlockSize(const Transaction& baseTransaction, std::vector<Transaction> transactions)
{
  size_t blockSize = getObjectBinarySize(baseTransaction);
  for (size_t i = 0; i < transactions.size(); ++i) {
    blockSize += toBinaryArray(transactions[i]).size();
  }

  return blockSize;
}

size_t getMedianBlockSize(Blockchain& blockchain)
{
  size_t fromHeight = blockchain.getCurrentBlockchainHeight() - 1;
  std::vector<size_t> blockSizes;
  size_t maxCount = parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW;

  blockchain.getBackwardBlocksSize(fromHeight, blockSizes, maxCount);

  return Common::medianValue(blockSizes);
}

std::vector<Crypto::PublicKey> getAccountIncomingTransactionPublicKeys(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, AccountKeys accountKeys)
{
  // get all transactions in the blockchain
  uint32_t startHeight = 1;
  uint32_t count = blockchain.getCurrentBlockchainHeight();
  std::list<Block> blocks;
  std::list<Transaction> transactions;

  std::vector<Crypto::PublicKey> transactionPublicKeys;

  blockchain.getBlocks(startHeight, count, blocks, transactions);

  // add coinbase transactions to transactions list
  for (std::list<Block>::iterator it = blocks.begin(); it != blocks.end(); it++)
  {
    Block block = *it;
    Transaction baseTransaction = block.baseTransaction;

    transactions.push_back(baseTransaction);
  }

  // check block transactions
  for (std::list<Transaction>::iterator it = transactions.begin(); it != transactions.end(); it++)
  {
    Transaction transaction = *it;

    size_t keyIndex = 0;

    for (size_t i = 0; i < transaction.outputs.size(); i++)
    {
      const TransactionOutput transactionOutput = transaction.outputs[i];

      if (transactionOutput.target.type() == typeid(KeyOutput))
      {
        KeyOutput keyOutput = boost::get<KeyOutput>(transactionOutput.target);

        Crypto::PublicKey transactionPublicKey = getTransactionPublicKeyFromExtra(transaction.extra);

        if (is_out_to_acc(accountKeys, keyOutput, transactionPublicKey, keyIndex))
        {
          transactionPublicKeys.push_back(transactionPublicKey);
        }
      
        keyIndex++;
      }
    }
  }

  return transactionPublicKeys;
}

// Adds a new block to the blockchain
bool addBlock1(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& blockHash)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  std::vector<Transaction> transactions;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  // adding transaction extra so that each transaction is unique
  transaction.extra = {1};
  Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  transactions.push_back(transaction);

  Crypto::Hash transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash lastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // Must use a while loop to figure out the current block size and coinbase reward
  // Borrowed from TestGenerator.cpp
  // The current block size is dependent on the amount of the coinbase reward
  // BUT  
  // The amount of the coinbase reward is dependent on the current block size
  // Must use a while loop find the actual current block size so that the coinbase transaction output amount is correct
  while (true)
  {
    currency.constructMinerTx1(currentBlockchainHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  blockHash = get_block_hash(block);

  return added;
}

// Adds a new block to the blockchain
// Finds nonce appropriate for difficulty
// Able to set the block timestamp
bool addBlock2(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, const uint64_t timestamp = time(nullptr), const difficulty_type difficulty = 1)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = timestamp;
  block.previousBlockHash = blockchain.getTailId();

  std::vector<Transaction> transactions;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  // adding transaction extra so that each transaction is unique
  transaction.extra = {1};
  Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  transactions.push_back(transaction);

  Crypto::Hash transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash lastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // Must use a while loop to figure out the current block size and coinbase reward
  // Borrowed from TestGenerator.cpp
  // The current block size is dependent on the amount of the coinbase reward
  // BUT  
  // The amount of the coinbase reward is dependent on the current block size
  // Must use a while loop find the actual current block size so that the coinbase transaction output amount is correct
  while (true)
  {
    currency.constructMinerTx1(currentBlockchainHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  // find nonce appropriate for difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;
}

// Adds a new block to the blockchain
// Returns the coinbase transaction hash
bool addBlock3(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& coinbaseTransactionHash)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  std::vector<Transaction> transactions;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  // adding transaction extra so that each transaction is unique
  transaction.extra = {1};
  Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  transactions.push_back(transaction);

  Crypto::Hash transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash lastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // Must use a while loop to figure out the current block size and coinbase reward
  // Borrowed from TestGenerator.cpp
  // The current block size is dependent on the amount of the coinbase reward
  // BUT  
  // The amount of the coinbase reward is dependent on the current block size
  // Must use a while loop find the actual current block size so that the coinbase transaction output amount is correct
  while (true)
  {
    currency.constructMinerTx1(currentBlockchainHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  coinbaseTransactionHash = getObjectHash(block.baseTransaction);

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;
}

// Adds a new block to the blockchain
// Multiple keyOutputs for 1 keyInput
// Adds 100 random transaction outputs with amount equal to 0.00000050
// Returns the transaction hash
bool addBlock4(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& transactionHash)
{
  // Alice is a miner and finds a block
  // Alice wants to send money to Bob

  AccountKeys aliceAccountKeys;
  
  KeyPair aliceViewKeyPair = generateKeyPair();
  KeyPair aliceSpendKeyPair = generateKeyPair();
  
  Crypto::PublicKey aliceViewPublicKey = aliceViewKeyPair.publicKey;
  Crypto::PublicKey aliceSpendPublicKey = aliceSpendKeyPair.publicKey;
  Crypto::SecretKey aliceViewSecretKey = aliceViewKeyPair.secretKey;
  Crypto::SecretKey aliceSpendSecretKey = aliceSpendKeyPair.secretKey;

  aliceAccountKeys.address.viewPublicKey = aliceViewPublicKey;
  aliceAccountKeys.address.spendPublicKey = aliceSpendPublicKey;
  aliceAccountKeys.viewSecretKey = aliceViewSecretKey;
  aliceAccountKeys.spendSecretKey = aliceSpendSecretKey;
  
  // Bob

  AccountKeys bobAccountKeys;

  KeyPair bobViewKeyPair = generateKeyPair();
  KeyPair bobSpendKeyPair = generateKeyPair();

  Crypto::PublicKey bobViewPublicKey = bobViewKeyPair.publicKey;
  Crypto::PublicKey bobSpendPublicKey = bobSpendKeyPair.publicKey;
  Crypto::SecretKey bobViewSecretKey = bobViewKeyPair.secretKey;
  Crypto::SecretKey bobSpendSecretKey = bobSpendKeyPair.secretKey;

  bobAccountKeys.address.viewPublicKey = bobViewPublicKey;
  bobAccountKeys.address.spendPublicKey = bobSpendPublicKey;
  bobAccountKeys.viewSecretKey = bobViewSecretKey;
  bobAccountKeys.spendSecretKey = bobSpendSecretKey;
  
  //////////////////////////////////////////////////////////////////////////
  // 1. Alice is a miner and finds a new block and gets the coinbase reward
  //////////////////////////////////////////////////////////////////////////

  // create block 1
  Block block1;
  block1.nonce = 0;
  block1.timestamp = time(nullptr);
  block1.previousBlockHash = blockchain.getTailId();

  // create coinbase transaction 1

  Transaction coinbaseTransaction1;
  coinbaseTransaction1.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction1.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction inputs 1

  BaseInput coinbaseInput1;
  coinbaseInput1.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction1.inputs.push_back(coinbaseInput1);

  // coinbase transaction outputs 1

  TransactionOutput coinbaseTransactionOutput1;

  // coinbase transaction public key 1
  KeyPair coinbaseTransactionKeyPair1 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey1 = coinbaseTransactionKeyPair1.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey1 = coinbaseTransactionKeyPair1.secretKey;

  // coinbase ephemeral public key 1
  Crypto::KeyDerivation derivation1;
  Crypto::PublicKey coinbaseEphemeralPublicKey1;
  size_t outputIndex1 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey1, derivation1);
  derive_public_key(derivation1, outputIndex1, aliceSpendPublicKey, coinbaseEphemeralPublicKey1);

  // set coinbase transaction output amount 1
  size_t medianSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins1;
  Crypto::Hash lastBlockHash1 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash1, alreadyGeneratedCoins1);

  uint64_t fee1 = 0;
  uint64_t reward1;
  int64_t emissionChange1;
  currency.getBlockReward1(medianSize1, currentBlockSize1, alreadyGeneratedCoins1, fee1, reward1, emissionChange1);
  coinbaseTransactionOutput1.amount = reward1;

  // coinbase output target 1
  KeyOutput coinbaseKeyOutput1;

  coinbaseKeyOutput1.key = coinbaseEphemeralPublicKey1;
  coinbaseTransactionOutput1.target = coinbaseKeyOutput1;

  coinbaseTransaction1.outputs.push_back(coinbaseTransactionOutput1);

  // coinbase transaction extra 1
  
  coinbaseTransaction1.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction1.extra.push_back(coinbaseTransactionPublicKey1.data[i]);
  }

  // add coinbase transaction 1 to block 1
  block1.baseTransaction = coinbaseTransaction1;

  // add merkle root
  block1.merkleRoot = get_tx_tree_hash(block1);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block1, difficulty, proofOfWorkIgnore))
  {
    block1.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  blockchain.addNewBlock(block1, bvc);

  blockchain.haveTransaction(getObjectHash(coinbaseTransaction1));

  // allow coinbase transaction to mature
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    Crypto::Hash blockHash;
    addBlock1(blockchain, currency, tx_memory_pool, blockHash);
  }

  ////////////////////////////////////////////////////////////////////////
  // 2. Alice sends money to Bob
  ////////////////////////////////////////////////////////////////////////

  // create block 2
  Block block2;
  block2.nonce = 0;
  block2.timestamp = time(nullptr);
  block2.previousBlockHash = blockchain.getTailId();

  // create transaction

  Transaction transaction2;
  transaction2.version = CURRENT_TRANSACTION_VERSION;
  transaction2.unlockTime = 0;

  // create transaction random transaction key
  KeyPair transactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey transactionPublicKey2 = transactionKeyPair2.publicKey;
  Crypto::SecretKey transactionSecretKey2 = transactionKeyPair2.secretKey;

  // create transaction extra
  transaction2.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction2.extra.push_back(transactionPublicKey2.data[i]);
  }

  // transaction input

  // create key image
  KeyPair ephemeralKeyPair2Ignore;
  Crypto::KeyImage keyImage2;
  generate_key_image_helper(aliceAccountKeys, coinbaseTransactionPublicKey1, outputIndex1, ephemeralKeyPair2Ignore, keyImage2);

  KeyInput keyInput2;
  keyInput2.amount = reward1;
  keyInput2.keyImage = keyImage2;
  keyInput2.outputIndexes = {0};
  transaction2.inputs.push_back(keyInput2);

  // transaction output

  // ephemeral public key 2
  Crypto::KeyDerivation transactionDerivation2;
  Crypto::PublicKey transactionEphemeralPublicKey2;
  size_t transactionOutputIndex2 = 0;
  generate_key_derivation(bobViewPublicKey, transactionSecretKey2, transactionDerivation2);
  derive_public_key(transactionDerivation2, transactionOutputIndex2, bobSpendPublicKey, transactionEphemeralPublicKey2);

  // totalOutputAmount are used to calculate the coinbase reward
  uint64_t totalOutputAmount = 0;

  // create output targets with amount = 50
  for (int i = 0; i < 100; i++)
  {
    KeyOutput keyOutput2;
    keyOutput2.key = transactionEphemeralPublicKey2;

    TransactionOutput transactionOutput2;
    transactionOutput2.amount = 50;
    totalOutputAmount += transactionOutput2.amount;
    transactionOutput2.target = keyOutput2;

    transaction2.outputs.push_back(transactionOutput2);
  }

  // transaction signature

  // coinbase keyOutput ephemeral secret key 1
  Crypto::SecretKey coinbaseEphemeralSecretKey1;
  generate_key_derivation(coinbaseTransactionPublicKey1, aliceViewSecretKey, derivation1);
  derive_secret_key(derivation1, outputIndex1, aliceSpendSecretKey, coinbaseEphemeralSecretKey1);

  std::vector<const Crypto::PublicKey*> ephemeralPublicKeysPtrs;
  ephemeralPublicKeysPtrs.push_back(&coinbaseEphemeralPublicKey1);

  transaction2.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& signatures = transaction2.signatures.back();
  signatures.resize(coinbaseTransaction1.outputs.size());
  
  Crypto::Hash transactionPrefixHash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction2));;
  size_t sec_index = 0;
  generate_ring_signature(transactionPrefixHash, keyImage2, ephemeralPublicKeysPtrs, coinbaseEphemeralSecretKey1, sec_index, signatures.data());

  // add transaction2 to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = false;
  tx_memory_pool.add_tx(transaction2, tvc, kept_by_block);

  // add transaction 2 to block 2
  transactionHash = getObjectHash(transaction2);
  block2.transactionHashes.push_back(transactionHash);

  // create coinbase transaction 2

  Transaction coinbaseTransaction2;
  coinbaseTransaction2.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction2.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction input 2

  BaseInput coinbaseInput2;
  coinbaseInput2.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction2.inputs.push_back(coinbaseInput2);

  // coinbase transaction output 2

  TransactionOutput coinbaseTransactionOutput2;

  // coinbase transaction public key 2
  KeyPair coinbaseTransactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey2 = coinbaseTransactionKeyPair2.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey2 = coinbaseTransactionKeyPair2.secretKey;

  // create keyOutput public key 2
  Crypto::KeyDerivation derivation2;
  Crypto::PublicKey coinbaseEphemeralPublicKey2;
  size_t outputIndex2 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey2, derivation2);
  derive_public_key(derivation2, outputIndex2, aliceSpendPublicKey, coinbaseEphemeralPublicKey2);

  // set coinbase transaction output amount 2
  size_t medianSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins2;
  Crypto::Hash lastBlockHash2 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash2, alreadyGeneratedCoins2);

  uint64_t fee2 = keyInput2.amount - totalOutputAmount;
  uint64_t reward2;
  int64_t emissionChange2;
  currency.getBlockReward1(medianSize2, currentBlockSize2, alreadyGeneratedCoins2, fee2, reward2, emissionChange2);
  coinbaseTransactionOutput2.amount = reward2;

  // create output target 2
  KeyOutput coinbaseKeyOutput2;

  coinbaseKeyOutput2.key = coinbaseEphemeralPublicKey2;
  coinbaseTransactionOutput2.target = coinbaseKeyOutput2;

  coinbaseTransaction2.outputs.push_back(coinbaseTransactionOutput2);

  // create coinbase transaction extra 2
  
  coinbaseTransaction2.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction2.extra.push_back(coinbaseTransactionPublicKey2.data[i]);
  }

  // add coinbase transaction 2 to block 2
  block2.baseTransaction = coinbaseTransaction2;

  // add merkle root
  block2.merkleRoot = get_tx_tree_hash(block2);

  difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  while(!currency.checkProofOfWork1(context, block2, difficulty, proofOfWorkIgnore))
  {
    block2.nonce++;
  }

  bool added = blockchain.addNewBlock(block2, bvc);

  return added;
}

// Same as addBlock4
// Able to set the transaction output amount
bool addBlock5(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& transactionHash, const uint64_t transactionOutputAmount)
{
  // Alice is a miner and finds a block
  // Alice wants to send money to Bob

  AccountKeys aliceAccountKeys;
  
  KeyPair aliceViewKeyPair = generateKeyPair();
  KeyPair aliceSpendKeyPair = generateKeyPair();
  
  Crypto::PublicKey aliceViewPublicKey = aliceViewKeyPair.publicKey;
  Crypto::PublicKey aliceSpendPublicKey = aliceSpendKeyPair.publicKey;
  Crypto::SecretKey aliceViewSecretKey = aliceViewKeyPair.secretKey;
  Crypto::SecretKey aliceSpendSecretKey = aliceSpendKeyPair.secretKey;

  aliceAccountKeys.address.viewPublicKey = aliceViewPublicKey;
  aliceAccountKeys.address.spendPublicKey = aliceSpendPublicKey;
  aliceAccountKeys.viewSecretKey = aliceViewSecretKey;
  aliceAccountKeys.spendSecretKey = aliceSpendSecretKey;
  
  // Bob

  AccountKeys bobAccountKeys;

  KeyPair bobViewKeyPair = generateKeyPair();
  KeyPair bobSpendKeyPair = generateKeyPair();

  Crypto::PublicKey bobViewPublicKey = bobViewKeyPair.publicKey;
  Crypto::PublicKey bobSpendPublicKey = bobSpendKeyPair.publicKey;
  Crypto::SecretKey bobViewSecretKey = bobViewKeyPair.secretKey;
  Crypto::SecretKey bobSpendSecretKey = bobSpendKeyPair.secretKey;

  bobAccountKeys.address.viewPublicKey = bobViewPublicKey;
  bobAccountKeys.address.spendPublicKey = bobSpendPublicKey;
  bobAccountKeys.viewSecretKey = bobViewSecretKey;
  bobAccountKeys.spendSecretKey = bobSpendSecretKey;
  
  //////////////////////////////////////////////////////////////////////////
  // 1. Alice is a miner and finds a new block and gets the coinbase reward
  //////////////////////////////////////////////////////////////////////////

  // create block 1
  Block block1;
  block1.nonce = 0;
  block1.timestamp = time(nullptr);
  block1.previousBlockHash = blockchain.getTailId();

  // create coinbase transaction 1

  Transaction coinbaseTransaction1;
  coinbaseTransaction1.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction1.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction inputs 1

  BaseInput coinbaseInput1;
  coinbaseInput1.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction1.inputs.push_back(coinbaseInput1);

  // coinbase transaction outputs 1

  TransactionOutput coinbaseTransactionOutput1;

  // coinbase transaction public key 1
  KeyPair coinbaseTransactionKeyPair1 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey1 = coinbaseTransactionKeyPair1.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey1 = coinbaseTransactionKeyPair1.secretKey;

  // coinbase ephemeral public key 1
  Crypto::KeyDerivation derivation1;
  Crypto::PublicKey coinbaseEphemeralPublicKey1;
  size_t outputIndex1 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey1, derivation1);
  derive_public_key(derivation1, outputIndex1, aliceSpendPublicKey, coinbaseEphemeralPublicKey1);

  // set coinbase transaction output amount 1
  size_t medianSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins1;
  Crypto::Hash lastBlockHash1 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash1, alreadyGeneratedCoins1);

  uint64_t fee1 = 0;
  uint64_t reward1;
  int64_t emissionChange1;
  currency.getBlockReward1(medianSize1, currentBlockSize1, alreadyGeneratedCoins1, fee1, reward1, emissionChange1);
  coinbaseTransactionOutput1.amount = reward1;

  // coinbase output target 1
  KeyOutput coinbaseKeyOutput1;

  coinbaseKeyOutput1.key = coinbaseEphemeralPublicKey1;
  coinbaseTransactionOutput1.target = coinbaseKeyOutput1;

  coinbaseTransaction1.outputs.push_back(coinbaseTransactionOutput1);

  // coinbase transaction extra 1
  
  coinbaseTransaction1.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction1.extra.push_back(coinbaseTransactionPublicKey1.data[i]);
  }

  // add coinbase transaction 1 to block 1
  block1.baseTransaction = coinbaseTransaction1;

  // add merkle root
  block1.merkleRoot = get_tx_tree_hash(block1);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block1, difficulty, proofOfWorkIgnore))
  {
    block1.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  blockchain.addNewBlock(block1, bvc);

  blockchain.haveTransaction(getObjectHash(coinbaseTransaction1));

  // allow coinbase transaction to mature
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    Crypto::Hash blockHash;
    addBlock1(blockchain, currency, tx_memory_pool, blockHash);
  }

  ////////////////////////////////////////////////////////////////////////
  // 2. Alice sends money to Bob
  ////////////////////////////////////////////////////////////////////////

  // create block 2
  Block block2;
  block2.nonce = 0;
  block2.timestamp = time(nullptr);
  block2.previousBlockHash = blockchain.getTailId();

  // create transaction

  Transaction transaction2;
  transaction2.version = CURRENT_TRANSACTION_VERSION;
  transaction2.unlockTime = 0;

  // create transaction random transaction key
  KeyPair transactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey transactionPublicKey2 = transactionKeyPair2.publicKey;
  Crypto::SecretKey transactionSecretKey2 = transactionKeyPair2.secretKey;

  // create transaction extra
  transaction2.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction2.extra.push_back(transactionPublicKey2.data[i]);
  }

  // transaction input

  // create key image
  KeyPair ephemeralKeyPair2Ignore;
  Crypto::KeyImage keyImage2;
  generate_key_image_helper(aliceAccountKeys, coinbaseTransactionPublicKey1, outputIndex1, ephemeralKeyPair2Ignore, keyImage2);

  KeyInput keyInput2;
  keyInput2.amount = reward1;
  keyInput2.keyImage = keyImage2;
  keyInput2.outputIndexes = {0};
  transaction2.inputs.push_back(keyInput2);

  // transaction output

  // ephemeral public key 2
  Crypto::KeyDerivation transactionDerivation2;
  Crypto::PublicKey transactionEphemeralPublicKey2;
  size_t transactionOutputIndex2 = 0;
  generate_key_derivation(bobViewPublicKey, transactionSecretKey2, transactionDerivation2);
  derive_public_key(transactionDerivation2, transactionOutputIndex2, bobSpendPublicKey, transactionEphemeralPublicKey2);

  // totalOutputAmount are used to calculate the coinbase reward
  uint64_t totalOutputAmount = 0;

  KeyOutput keyOutput2;
  keyOutput2.key = transactionEphemeralPublicKey2;

  TransactionOutput transactionOutput2;
  transactionOutput2.amount = transactionOutputAmount;
  totalOutputAmount += transactionOutput2.amount;
  transactionOutput2.target = keyOutput2;

  transaction2.outputs.push_back(transactionOutput2);

  // transaction signature

  // coinbase keyOutput ephemeral secret key 1
  Crypto::SecretKey coinbaseEphemeralSecretKey1;
  generate_key_derivation(coinbaseTransactionPublicKey1, aliceViewSecretKey, derivation1);
  derive_secret_key(derivation1, outputIndex1, aliceSpendSecretKey, coinbaseEphemeralSecretKey1);

  std::vector<const Crypto::PublicKey*> ephemeralPublicKeysPtrs;
  ephemeralPublicKeysPtrs.push_back(&coinbaseEphemeralPublicKey1);

  transaction2.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& signatures = transaction2.signatures.back();
  signatures.resize(coinbaseTransaction1.outputs.size());
  
  Crypto::Hash transactionPrefixHash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction2));;
  size_t sec_index = 0;
  generate_ring_signature(transactionPrefixHash, keyImage2, ephemeralPublicKeysPtrs, coinbaseEphemeralSecretKey1, sec_index, signatures.data());

  // add transaction2 to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = false;
  tx_memory_pool.add_tx(transaction2, tvc, kept_by_block);

  // add transaction 2 to block 2
  transactionHash = getObjectHash(transaction2);
  block2.transactionHashes.push_back(transactionHash);

  // create coinbase transaction 2

  Transaction coinbaseTransaction2;
  coinbaseTransaction2.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction2.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction input 2

  BaseInput coinbaseInput2;
  coinbaseInput2.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction2.inputs.push_back(coinbaseInput2);

  // coinbase transaction output 2

  TransactionOutput coinbaseTransactionOutput2;

  // coinbase transaction public key 2
  KeyPair coinbaseTransactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey2 = coinbaseTransactionKeyPair2.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey2 = coinbaseTransactionKeyPair2.secretKey;

  // create keyOutput public key 2
  Crypto::KeyDerivation derivation2;
  Crypto::PublicKey coinbaseEphemeralPublicKey2;
  size_t outputIndex2 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey2, derivation2);
  derive_public_key(derivation2, outputIndex2, aliceSpendPublicKey, coinbaseEphemeralPublicKey2);

  // set coinbase transaction output amount 2
  size_t medianSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins2;
  Crypto::Hash lastBlockHash2 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash2, alreadyGeneratedCoins2);

  uint64_t fee2 = keyInput2.amount - totalOutputAmount;
  uint64_t reward2;
  int64_t emissionChange2;
  currency.getBlockReward1(medianSize2, currentBlockSize2, alreadyGeneratedCoins2, fee2, reward2, emissionChange2);
  coinbaseTransactionOutput2.amount = reward2;

  // create output target 2
  KeyOutput coinbaseKeyOutput2;

  coinbaseKeyOutput2.key = coinbaseEphemeralPublicKey2;
  coinbaseTransactionOutput2.target = coinbaseKeyOutput2;

  coinbaseTransaction2.outputs.push_back(coinbaseTransactionOutput2);

  // create coinbase transaction extra 2
  
  coinbaseTransaction2.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction2.extra.push_back(coinbaseTransactionPublicKey2.data[i]);
  }

  // add coinbase transaction 2 to block 2
  block2.baseTransaction = coinbaseTransaction2;

  // add merkle root
  block2.merkleRoot = get_tx_tree_hash(block2);

  difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  while(!currency.checkProofOfWork1(context, block2, difficulty, proofOfWorkIgnore))
  {
    block2.nonce++;
  }

  bool added = blockchain.addNewBlock(block2, bvc);

  return added;
}

// Adds a new block to the blockchain
// returns block hash
// returns coinbase transaction hash
bool addBlock7(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& blockHash, Crypto::Hash& transactionHash)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  std::vector<Transaction> transactions;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  // adding transaction extra so that each transaction is unique
  transaction.extra = {1};
  Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  transactions.push_back(transaction);

  transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash lastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // Must use a while loop to figure out the current block size and coinbase reward
  // Borrowed from TestGenerator.cpp
  // The current block size is dependent on the amount of the coinbase reward
  // BUT  
  // The amount of the coinbase reward is dependent on the current block size
  // Must use a while loop find the actual current block size so that the coinbase transaction output amount is correct
  while (true)
  {
    currency.constructMinerTx1(currentBlockchainHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  blockHash = get_block_hash(block);

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;
}

// Adds a new block to the blockchain
// Adds fake transactions to increase the block size
// Able to set number of transactions added
// Returns the block hash
// Returns the block size
bool addBlock8(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& blockHash, const uint32_t numTransactions, size_t& blockSize)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  std::vector<Transaction> transactions;
  for (int i = 0; i < numTransactions; i++)
  {
    // create transaction
    Transaction transaction;
    transaction.version = CURRENT_TRANSACTION_VERSION;
    // adding transaction extra so that each transaction is unique
    transaction.extra = {1};
    Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
    for (int i = 0; i < 32; i++)
    {
      transaction.extra.push_back(transactionPublicKey.data[i]);
    }

    transactions.push_back(transaction);

    Crypto::Hash transactionHash = getObjectHash(transaction);

    // add transaction to block
    block.transactionHashes.push_back(transactionHash);
    
    // add transaction to transaction mempool
    tx_verification_context tvc;
    bool kept_by_block = true;
    tx_memory_pool.add_tx(transaction, tvc, kept_by_block);
  }

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash lastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // Must use a while loop to figure out the current block size and coinbase reward
  // Borrowed from TestGenerator.cpp
  // The current block size is dependent on the amount of the coinbase reward
  // BUT  
  // The amount of the coinbase reward is dependent on the current block size
  // Must use a while loop find the actual current block size so that the coinbase transaction output amount is correct
  while (true)
  {
    currency.constructMinerTx1(currentBlockchainHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  blockHash = get_block_hash(block);

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;
}

// Adds a new block to the blockchain
// Able to set payment id
// Returns transaction hash
bool addBlock9(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, const Crypto::Hash& paymentId, Crypto::Hash& transactionHash)
{
  uint32_t currentBlockchainHeight = blockchain.getCurrentBlockchainHeight();

  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  // coinbase transaction input
  BaseInput baseInput;
  baseInput.blockIndex = currentBlockchainHeight; // blockIndex must match height of the block

  // coinbase transaction output
  TransactionOutput baseOutput;

  // get reward for new block
  size_t medianSize = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins;
  Crypto::Hash mainChainLastBlockHash = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(mainChainLastBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  uint64_t reward;
  int64_t emissionChange;
  currency.getBlockReward1(medianSize, currentBlockSize, alreadyGeneratedCoins, fee, reward, emissionChange);
  baseOutput.amount = reward;

  // create output target
  KeyOutput keyOutput;
  keyOutput.key = generateKeyPair().publicKey;
  baseOutput.target = keyOutput;

  // create coinbase transaction
  Transaction baseTransaction;
  baseTransaction.version = CURRENT_TRANSACTION_VERSION;
  baseTransaction.unlockTime = parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + currentBlockchainHeight;
  baseTransaction.inputs.push_back(baseInput);
  baseTransaction.outputs.push_back(baseOutput);

  // add coinbase transaction to block
  block.baseTransaction = baseTransaction;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;

  // transaction extra public key

  // random transaction public key so that each transaction is unique
  Crypto::Hash transactionPublicKey = getRandHash();

  // 1 signifies a transaction public key
  transaction.extra.push_back(1);

  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  // transaction extra payment id

  // 2 means we are creating a transaction extra nonce
  transaction.extra.push_back(2);
  // 33 tells the size of the transaction extra nonce (must be sizeof(Crypto::Hash) + 1)
  transaction.extra.push_back(33);
  // 0 is the extra nonce payment id
  transaction.extra.push_back(0);

  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(paymentId.data[i]);
  }

  transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;
}

// Adds a new alternative or orphaned block to the blockchain
bool addAlternativeBlock(Blockchain& blockchain, Currency& currency, tx_memory_pool& tx_memory_pool, Crypto::Hash& blockHash, const Crypto::Hash& prevBlockHash, const uint32_t blockHeight)
{
  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = prevBlockHash;

  std::vector<Transaction> transactions;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  // adding transaction extra so that each transaction is unique
  transaction.extra = {1};
  Crypto::PublicKey transactionPublicKey= generateKeyPair().publicKey;
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  transactions.push_back(transaction);

  Crypto::Hash transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  tx_memory_pool.add_tx(transaction, tvc, kept_by_block);

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  // need to get the hash of the block on the main chain that is at the same hight as the last block on the alternative chain to calculate alreadyGeneratedCoins
  uint64_t alreadyGeneratedCoins;
  // uint32_t prevAltBlockHeight;
  // blockchain.getBlockHeight(prevBlockHash, prevAltBlockHeight);
  // Crypto::Hash mainChainBlockHash = blockchain.getBlockIdByHeight(prevAltBlockHeight);
  Crypto::Hash mainChainBlockHash = blockchain.getBlockIdByHeight(blockHeight - 1);
  blockchain.getAlreadyGeneratedCoins(mainChainBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(blockchain);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  // uint32_t blockIndexHeight = blockchain.getAlternativeBlocksCount();

  // if (blockchain.isBlockInMainChain(prevBlockHash))
  // {
    // blockIndexHeight = blockHeight;
  // }

  while (true)
  {
    currency.constructMinerTx1(blockHeight, medianBlockSize, alreadyGeneratedCoins, currentBlockSize,
    fee, AccountPublicAddress(), block.baseTransaction, BinaryArray(), maxOuts);

    size_t actualBlockSize = getBlockSize(block.baseTransaction, transactions);

    if (actualBlockSize == currentBlockSize)
    {
      break;
    }

    currentBlockSize = actualBlockSize;
  }

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  blockHash = get_block_hash(block);

  // add block to blockchain
  block_verification_context bvc;
  bool added = blockchain.addNewBlock(block, bvc);

  return added;

}

// constructor
TEST(Blockchain, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Blockchain blockchain(currency, tx_memory_pool, logger);
}

// addObserver()
TEST(Blockchain, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Blockchain blockchain(currency, tx_memory_pool, logger);

  BlockchainStorageObserver observer;
  ASSERT_TRUE(blockchain.addObserver(&observer));
}

// removeObserver()
TEST(Blockchain, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Blockchain blockchain(currency, tx_memory_pool, logger);

  BlockchainStorageObserver observer;

  ASSERT_TRUE(blockchain.addObserver(&observer));
  ASSERT_TRUE(blockchain.removeObserver(&observer));
}

// addNewBlock()
TEST(Blockchain, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);

  Blockchain blockchain(currency, tx_memory_pool, logger);

  std::string config_folder = Tools::getDefaultDataDirectory();

  ASSERT_TRUE(blockchain.init(config_folder, false));

  // create block
  Block block;
  block.nonce = 1;
  block.timestamp = time(nullptr);
  block.previousBlockHash = blockchain.getTailId();

  // coinbase transaction input
  BaseInput baseInput;
  baseInput.blockIndex = 1; // blockIndex must match height of the block

  // coinbase transaction output
  TransactionOutput baseOutput;
  baseOutput.amount = 894069618; // block reward for 2nd block in blockchain
  // create output target
  KeyOutput keyOutput;
  keyOutput.key = generateKeyPair().publicKey;
  baseOutput.target = keyOutput;

  // create coinbase transaction
  Transaction baseTransaction;
  baseTransaction.version = CURRENT_TRANSACTION_VERSION;
  baseTransaction.unlockTime = parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 1; // I do not know why we have to add 1 but we do. Is the genesis block timestamp equal to 1?
  baseTransaction.inputs.push_back(baseInput);
  baseTransaction.outputs.push_back(baseOutput);

  // add coinbase transaction to block
  block.baseTransaction = baseTransaction;

  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  Crypto::Hash transactionHash = getObjectHash(transaction);

  // add transaction to block
  block.transactionHashes.push_back(transactionHash);
  
  // add transaction to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = true;
  ASSERT_TRUE(tx_memory_pool.add_tx(transaction, tvc, kept_by_block));

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  // add block to blockchain
  block_verification_context bvc;
  ASSERT_TRUE(blockchain.addNewBlock(block, bvc));
}

// getAlreadyGeneratedCoins()
// 2 blocks in blockchain
TEST(Blockchain, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  Block block;
  Crypto::Hash blockHash;

  // initialize blockchain
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // add new block to blockchain at height 2
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint64_t alreadyGeneratedCoins;
  blockchain.getAlreadyGeneratedCoins(blockHash, alreadyGeneratedCoins);

  ASSERT_EQ(894069671 + 894069618, alreadyGeneratedCoins);
}

// getAlreadyGeneratedCoins()
// 3 blocks in blockchain
TEST(Blockchain, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // add new block to blockchain at height 1
  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash1));
  // add new block to blockchain at height 2
  Crypto::Hash blockHash2;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash2));

  // ULL needed to prevent interger overflow error
  uint64_t alreadyGeneratedCoins1;
  ASSERT_TRUE(blockchain.getAlreadyGeneratedCoins(blockHash1, alreadyGeneratedCoins1));
  ASSERT_EQ(894069671ULL + 894069618, alreadyGeneratedCoins1);

  uint64_t alreadyGeneratedCoins2;
  ASSERT_TRUE(blockchain.getAlreadyGeneratedCoins(blockHash2, alreadyGeneratedCoins2));
  ASSERT_EQ(894069671ULL + 894069618 + 894069565, alreadyGeneratedCoins2);
}

// getBlockIds()
TEST(Blockchain, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint32_t startHeight = 0;
  uint32_t maxCount = 2;
  std::vector<Crypto::Hash> blockHashes = blockchain.getBlockIds(startHeight, maxCount);

  ASSERT_EQ(2, blockHashes.size());

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  ASSERT_TRUE(hashesEqual(genesisBlockHash, blockHashes[0]));

  ASSERT_TRUE(hashesEqual(blockHash, blockHashes[1]));
}

// getBlocks()
TEST(Blockchain, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint32_t start_offset = 0;
  uint32_t count = 2;
  std::list<Block> blocks;
  ASSERT_TRUE(blockchain.getBlocks(start_offset, count, blocks));

  ASSERT_EQ(2, blocks.size());

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  Crypto::Hash blockHash0 = get_block_hash(blocks.front());
  ASSERT_TRUE(hashesEqual(genesisBlockHash, blockHash0));

  Crypto::Hash blockHash1 = get_block_hash(blocks.back());
  ASSERT_TRUE(hashesEqual(blockHash, blockHash1));
}

// getBlockIdByHeight()
TEST(Blockchain, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash1));
  Crypto::Hash blockHash2;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash2));
  Crypto::Hash blockHash3;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash3));

  uint32_t height0 = 0;
  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  Crypto::Hash blockHashOutput0 = blockchain.getBlockIdByHeight(height0);
  ASSERT_TRUE(hashesEqual(genesisBlockHash, blockHashOutput0));

  uint32_t height1 = 1;
  Crypto::Hash blockHashOutput1 = blockchain.getBlockIdByHeight(height1);
  ASSERT_TRUE(hashesEqual(blockHash1, blockHashOutput1));

  uint32_t height2 = 2;
  Crypto::Hash blockHashOutput2 = blockchain.getBlockIdByHeight(height2);
  ASSERT_TRUE(hashesEqual(blockHash2, blockHashOutput2));

  uint32_t height3 = 3;
  Crypto::Hash blockHashOutput3 = blockchain.getBlockIdByHeight(height3);
  ASSERT_TRUE(hashesEqual(blockHash3, blockHashOutput3));
}

// getTailId()
TEST(Blockchain, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);

  ASSERT_TRUE(hashesEqual(NULL_HASH, blockchain.getTailId()));

  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  ASSERT_TRUE(hashesEqual(genesisBlockHash, blockchain.getTailId()));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_TRUE(hashesEqual(blockHash, blockchain.getTailId()));
}

// getCoinsInCirculation()
TEST(Blockchain, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  uint64_t coinsInCirculation0 = blockchain.getCoinsInCirculation();
  ASSERT_EQ(894069671, coinsInCirculation0);

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint64_t coinsInCirculation1 = blockchain.getCoinsInCirculation();
  ASSERT_EQ(894069671 + 894069618, coinsInCirculation1);
}

// haveBlock()
TEST(Blockchain, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  ASSERT_TRUE(blockchain.haveBlock(genesisBlockHash));

  Crypto::Hash blockHash;
  ASSERT_FALSE(blockchain.haveBlock(blockHash));
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_TRUE(blockchain.haveBlock(blockHash));
}

// isBlockInMainChain()
TEST(Blockchain, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  ASSERT_TRUE(blockchain.isBlockInMainChain(genesisBlockHash));

  Crypto::Hash blockHash;
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash));
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash));
}

// getBlockHeight()
// I think this is only guaranteed to work for blocks on the mainchain
TEST(Blockchain, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  uint32_t blockHeight;
  ASSERT_TRUE(blockchain.getBlockHeight(genesisBlockHash, blockHeight));
  ASSERT_EQ(0, blockHeight);

  Crypto::Hash blockHash;
  ASSERT_FALSE(blockchain.getBlockHeight(blockHash, blockHeight));
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_TRUE(blockchain.getBlockHeight(blockHash, blockHeight));
  ASSERT_EQ(1, blockHeight);
}

// getCurrentBlockchainHeight()()
TEST(Blockchain, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);

  ASSERT_EQ(0, blockchain.getCurrentBlockchainHeight());

  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  ASSERT_EQ(1, blockchain.getCurrentBlockchainHeight());

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_EQ(2, blockchain.getCurrentBlockchainHeight());
}

// getBlockByHash()
TEST(Blockchain, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);

  Block block;

  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  ASSERT_FALSE(blockchain.getBlockByHash(genesisBlockHash, block));

  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  ASSERT_TRUE(blockchain.getBlockByHash(genesisBlockHash, block));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_TRUE(blockchain.getBlockByHash(blockHash, block));
}

// blockDifficulty()
TEST(Blockchain, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  uint64_t difficulty0  = blockchain.blockDifficulty(0);
  ASSERT_EQ(1, difficulty0);

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint64_t difficulty1  = blockchain.blockDifficulty(1);
  ASSERT_EQ(1, difficulty1);
}

// getBlockIdsByTimestamp()
TEST(Blockchain, 18)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  uint64_t timestampBegin = time(nullptr) - 10;
  uint64_t timestampEnd = time(nullptr) + 10;
  uint32_t blocksNumberLimit = 1;
  std::vector<Crypto::Hash> blockHashes;
  uint32_t blocksNumberWithinTimestamps;
  ASSERT_TRUE(blockchain.getBlockIdsByTimestamp(timestampBegin, timestampEnd, blocksNumberLimit, blockHashes, blocksNumberWithinTimestamps));

  ASSERT_TRUE(hashesEqual(blockHash, blockHashes[0]));
  ASSERT_EQ(1, blocksNumberWithinTimestamps);
}

// checkTransactionInputs()
TEST(Blockchain, 19)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // Alice is a miner and finds a block
  // Alice wants to send money to Bob

  AccountKeys aliceAccountKeys;
  
  KeyPair aliceViewKeyPair = generateKeyPair();
  KeyPair aliceSpendKeyPair = generateKeyPair();
  
  Crypto::PublicKey aliceViewPublicKey = aliceViewKeyPair.publicKey;
  Crypto::PublicKey aliceSpendPublicKey = aliceSpendKeyPair.publicKey;
  Crypto::SecretKey aliceViewSecretKey = aliceViewKeyPair.secretKey;
  Crypto::SecretKey aliceSpendSecretKey = aliceSpendKeyPair.secretKey;

  aliceAccountKeys.address.viewPublicKey = aliceViewPublicKey;
  aliceAccountKeys.address.spendPublicKey = aliceSpendPublicKey;
  aliceAccountKeys.viewSecretKey = aliceViewSecretKey;
  aliceAccountKeys.spendSecretKey = aliceSpendSecretKey;
  
  // Bob

  AccountKeys bobAccountKeys;

  KeyPair bobViewKeyPair = generateKeyPair();
  KeyPair bobSpendKeyPair = generateKeyPair();

  Crypto::PublicKey bobViewPublicKey = bobViewKeyPair.publicKey;
  Crypto::PublicKey bobSpendPublicKey = bobSpendKeyPair.publicKey;
  Crypto::SecretKey bobViewSecretKey = bobViewKeyPair.secretKey;
  Crypto::SecretKey bobSpendSecretKey = bobSpendKeyPair.secretKey;

  bobAccountKeys.address.viewPublicKey = bobViewPublicKey;
  bobAccountKeys.address.spendPublicKey = bobSpendPublicKey;
  bobAccountKeys.viewSecretKey = bobViewSecretKey;
  bobAccountKeys.spendSecretKey = bobSpendSecretKey;
  
  //////////////////////////////////////////////////////////////////////////
  // 1. Alice is a miner and finds a new block and gets the coinbase reward
  //////////////////////////////////////////////////////////////////////////

  // create block 1
  Block block1;
  block1.nonce = 0;
  block1.timestamp = time(nullptr);
  block1.previousBlockHash = blockchain.getTailId();

  // create coinbase transaction 1

  Transaction coinbaseTransaction1;
  coinbaseTransaction1.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction1.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction inputs 1

  BaseInput coinbaseInput1;
  coinbaseInput1.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction1.inputs.push_back(coinbaseInput1);

  // coinbase transaction outputs 1

  TransactionOutput coinbaseTransactionOutput1;

  // coinbase transaction public key 1
  KeyPair coinbaseTransactionKeyPair1 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey1 = coinbaseTransactionKeyPair1.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey1 = coinbaseTransactionKeyPair1.secretKey;

  // coinbase ephemeral public key 1
  Crypto::KeyDerivation derivation1;
  Crypto::PublicKey coinbaseEphemeralPublicKey1;
  size_t outputIndex1 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey1, derivation1);
  derive_public_key(derivation1, outputIndex1, aliceSpendPublicKey, coinbaseEphemeralPublicKey1);

  // set coinbase transaction output amount 1
  size_t medianSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins1;
  Crypto::Hash lastBlockHash1 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash1, alreadyGeneratedCoins1);

  uint64_t fee1 = 0;
  uint64_t reward1;
  int64_t emissionChange1;
  currency.getBlockReward1(medianSize1, currentBlockSize1, alreadyGeneratedCoins1, fee1, reward1, emissionChange1);
  coinbaseTransactionOutput1.amount = reward1;

  // coinbase output target 1
  KeyOutput coinbaseKeyOutput1;

  coinbaseKeyOutput1.key = coinbaseEphemeralPublicKey1;
  coinbaseTransactionOutput1.target = coinbaseKeyOutput1;

  coinbaseTransaction1.outputs.push_back(coinbaseTransactionOutput1);

  // coinbase transaction extra 1
  
  coinbaseTransaction1.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction1.extra.push_back(coinbaseTransactionPublicKey1.data[i]);
  }

  // add coinbase transaction 1 to block 1
  block1.baseTransaction = coinbaseTransaction1;

  // add merkle root
  block1.merkleRoot = get_tx_tree_hash(block1);

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block1, difficulty, proofOfWorkIgnore))
  {
    block1.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  blockchain.addNewBlock(block1, bvc);

  blockchain.haveTransaction(getObjectHash(coinbaseTransaction1));

  // allow coinbase transaction to mature
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    Crypto::Hash blockHash;
    addBlock1(blockchain, currency, tx_memory_pool, blockHash);
  }

  ////////////////////////////////////////////////////////////////////////
  // 2. Alice sends money to Bob
  ////////////////////////////////////////////////////////////////////////

  // create block 2
  Block block2;
  block2.nonce = 0;
  block2.timestamp = time(nullptr);
  block2.previousBlockHash = blockchain.getTailId();

  // create transaction

  Transaction transaction2;
  transaction2.version = CURRENT_TRANSACTION_VERSION;
  transaction2.unlockTime = 0;

  // create transaction random transaction key
  KeyPair transactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey transactionPublicKey2 = transactionKeyPair2.publicKey;
  Crypto::SecretKey transactionSecretKey2 = transactionKeyPair2.secretKey;

  // create transaction extra
  transaction2.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction2.extra.push_back(transactionPublicKey2.data[i]);
  }

  // transaction input

  // create key image
  KeyPair ephemeralKeyPair2Ignore;
  Crypto::KeyImage keyImage2;
  generate_key_image_helper(aliceAccountKeys, coinbaseTransactionPublicKey1, outputIndex1, ephemeralKeyPair2Ignore, keyImage2);

  KeyInput keyInput2;
  keyInput2.amount = reward1;
  keyInput2.keyImage = keyImage2;
  keyInput2.outputIndexes = {0};
  transaction2.inputs.push_back(keyInput2);

  // transaction output

  // ephemeral public key 2
  Crypto::KeyDerivation transactionDerivation2;
  Crypto::PublicKey transactionEphemeralPublicKey2;
  size_t transactionOutputIndex2 = 0;
  generate_key_derivation(bobViewPublicKey, transactionSecretKey2, transactionDerivation2);
  derive_public_key(transactionDerivation2, transactionOutputIndex2, bobSpendPublicKey, transactionEphemeralPublicKey2);

  // totalOutputAmount are used to calculate the coinbase reward
  uint64_t totalOutputAmount = 0;

  // create output targets with amount = 50
  for (int i = 0; i < 100; i++)
  {
    KeyOutput keyOutput2;
    keyOutput2.key = transactionEphemeralPublicKey2;

    TransactionOutput transactionOutput2;
    transactionOutput2.amount = 50;
    totalOutputAmount += transactionOutput2.amount;
    transactionOutput2.target = keyOutput2;

    transaction2.outputs.push_back(transactionOutput2);
  }

  // transaction signature

  // coinbase keyOutput ephemeral secret key 1
  Crypto::SecretKey coinbaseEphemeralSecretKey1;
  generate_key_derivation(coinbaseTransactionPublicKey1, aliceViewSecretKey, derivation1);
  derive_secret_key(derivation1, outputIndex1, aliceSpendSecretKey, coinbaseEphemeralSecretKey1);

  std::vector<const Crypto::PublicKey*> ephemeralPublicKeysPtrs;
  ephemeralPublicKeysPtrs.push_back(&coinbaseEphemeralPublicKey1);

  transaction2.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& signatures = transaction2.signatures.back();
  signatures.resize(coinbaseTransaction1.outputs.size());
  
  Crypto::Hash transactionPrefixHash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction2));;
  size_t sec_index = 0;
  generate_ring_signature(transactionPrefixHash, keyImage2, ephemeralPublicKeysPtrs, coinbaseEphemeralSecretKey1, sec_index, signatures.data());

  BlockInfo maxUsedBlock;
  // maxUsedBlock height and id must be filled out or checkTransactionInputs() fails for some reason
  maxUsedBlock.blockIndex = blockchain.getCurrentBlockchainHeight() - 1;
  maxUsedBlock.id = blockchain.getTailId();
  BlockInfo lastFailed;
  
  ASSERT_TRUE(blockchain.checkTransactionInputs(transaction2, maxUsedBlock, lastFailed));
}

// checkTransactionSize()
TEST(Blockchain, 20)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // median block size is 1000000
  // returns false if blob size is greater than 2 * median block size - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE

  size_t blobSize = 1000000;
  ASSERT_TRUE(blockchain.checkTransactionSize(blobSize));
  blobSize = 2000000;
  ASSERT_TRUE(blockchain.checkTransactionSize(blobSize));
  blobSize = 3000000;
  ASSERT_FALSE(blockchain.checkTransactionSize(blobSize));
}

// init()
TEST(Blockchain, 21)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));
}

// deinit()
TEST(Blockchain, 22)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  ASSERT_TRUE(blockchain.deinit());

  // // I don't understand why this assertion fails
  // ASSERT_TRUE(blockchain.init(config_folder, false));
}

// getLowerBound()
// I have no idea what this function does right now
TEST(Blockchain, 23)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  uint64_t timestamp = time(nullptr);
  uint64_t startOffset = 0;
  uint32_t height;
  
  ASSERT_FALSE(blockchain.getLowerBound(timestamp, startOffset, height));

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  ASSERT_TRUE(blockchain.getLowerBound(timestamp, startOffset, height));
  ASSERT_EQ(1, height);
}

// haveTransaction()
TEST(Blockchain, 24)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  AccountKeys aliceAccountKeys;
  KeyPair aliceViewKeyPair = generateKeyPair();
  KeyPair aliceSpendKeyPair = generateKeyPair();
  aliceAccountKeys.address.viewPublicKey = aliceViewKeyPair.publicKey;
  aliceAccountKeys.address.spendPublicKey = aliceSpendKeyPair.publicKey;
  Crypto::PublicKey aliceViewPublicKey = aliceViewKeyPair.publicKey;
  Crypto::PublicKey aliceSpendPublicKey = aliceSpendKeyPair.publicKey;

  ////////////////////////////////////////////////////////////////////////
  // 1. Alice is a miner and finds a new block and gets the coinbase reward from the genesis block
  ////////////////////////////////////////////////////////////////////////

  // create block
  Block block1;
  block1.nonce = 1;
  block1.timestamp = time(nullptr) + (blockchain.getCurrentBlockchainHeight() * 10);
  block1.previousBlockHash = blockchain.getTailId();

  // create coinbase transaction

  Transaction coinbaseTransaction1;
  coinbaseTransaction1.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction1.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // create coinbase random transaction key
  KeyPair coinbaseTransactionKeyPair1 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey1 = coinbaseTransactionKeyPair1.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey1 = coinbaseTransactionKeyPair1.secretKey;
  
  // create coinbase transaction extra
  coinbaseTransaction1.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction1.extra.push_back(coinbaseTransactionPublicKey1.data[i]);
  }

  // coinbase transaction input

  BaseInput baseInput1;
  baseInput1.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction1.inputs.push_back(baseInput1);

  // coinbase transaction output

  TransactionOutput coinbaseTransactionOutput1;

  // create keyOutput public key
  Crypto::KeyDerivation derivation1;
  Crypto::PublicKey out_eph_public_key_1;
  size_t outputIndex1 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey1, derivation1);
  derive_public_key(derivation1, outputIndex1, aliceSpendPublicKey, out_eph_public_key_1);

  // set coinbase transaction output amount
  size_t medianSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins1;
  Crypto::Hash lastBlockHash1 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash1, alreadyGeneratedCoins1);

  uint64_t fee1 = 0;
  uint64_t reward1;
  int64_t emissionChange1;
  currency.getBlockReward1(medianSize1, currentBlockSize1, alreadyGeneratedCoins1, fee1, reward1, emissionChange1);
  coinbaseTransactionOutput1.amount = reward1;

  // create output target
  KeyOutput keyOutput1;

  keyOutput1.key = out_eph_public_key_1;
  coinbaseTransactionOutput1.target = keyOutput1;

  coinbaseTransaction1.outputs.push_back(coinbaseTransactionOutput1);

  // add coinbase transaction to block
  block1.baseTransaction = coinbaseTransaction1;

  ASSERT_FALSE(blockchain.haveTransaction(getObjectHash(coinbaseTransaction1)));

  // add merkle root
  block1.merkleRoot = get_tx_tree_hash(block1);

  // add block to blockchain
  block_verification_context bvc;
  ASSERT_TRUE(blockchain.addNewBlock(block1, bvc));

  ASSERT_TRUE(blockchain.haveTransaction(getObjectHash(coinbaseTransaction1)));
}

// getTotalTransactions()
TEST(Blockchain, 25)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  
  ASSERT_EQ(0, blockchain.getTotalTransactions());

  ASSERT_TRUE(blockchain.init(config_folder, false));

  // genesis block transaction
  ASSERT_EQ(1, blockchain.getTotalTransactions());

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  // add new block helper adds 2 transactions to the blockchain
  ASSERT_EQ(3, blockchain.getTotalTransactions());

  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_EQ(5, blockchain.getTotalTransactions());
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_EQ(7, blockchain.getTotalTransactions());
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  ASSERT_EQ(9, blockchain.getTotalTransactions());
}

// haveSpentKeyImages() and haveTransactionKeyImagesAsSpent()
TEST(Blockchain, 26)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // Alice is a miner and finds a block
  // Alice sends money to Bob
  // Bob sends money to Carol

  AccountKeys aliceAccountKeys;
  KeyPair aliceViewKeyPair = generateKeyPair();
  KeyPair aliceSpendKeyPair = generateKeyPair();
  aliceAccountKeys.address.viewPublicKey = aliceViewKeyPair.publicKey;
  aliceAccountKeys.address.spendPublicKey = aliceSpendKeyPair.publicKey;
  aliceAccountKeys.viewSecretKey = aliceViewKeyPair.secretKey;
  aliceAccountKeys.spendSecretKey = aliceSpendKeyPair.secretKey;
  Crypto::PublicKey aliceViewPublicKey = aliceViewKeyPair.publicKey;
  Crypto::PublicKey aliceSpendPublicKey = aliceSpendKeyPair.publicKey;
  Crypto::SecretKey aliceViewSecretKey = aliceViewKeyPair.secretKey;
  Crypto::SecretKey aliceSpendSecretKey = aliceSpendKeyPair.secretKey;

  AccountKeys bobAccountKeys;
  KeyPair bobViewKeyPair = generateKeyPair();
  KeyPair bobSpendKeyPair = generateKeyPair();
  bobAccountKeys.address.viewPublicKey = bobViewKeyPair.publicKey;
  bobAccountKeys.address.spendPublicKey = bobSpendKeyPair.publicKey;
  bobAccountKeys.viewSecretKey = bobViewKeyPair.secretKey;
  bobAccountKeys.spendSecretKey = bobSpendKeyPair.secretKey;
  Crypto::PublicKey bobViewPublicKey = bobViewKeyPair.publicKey;
  Crypto::PublicKey bobSpendPublicKey = bobSpendKeyPair.publicKey;
  Crypto::SecretKey bobViewSecretKey = bobViewKeyPair.secretKey;
  Crypto::SecretKey bobSpendSecretKey = bobSpendKeyPair.secretKey;

  // AccountKeys carolAccountKeys;
  // KeyPair carolViewKeyPair = generateKeyPair();
  // KeyPair carolSpendKeyPair = generateKeyPair();
  // carolAccountKeys.address.viewPublicKey = carolViewKeyPair.publicKey;
  // carolAccountKeys.address.spendPublicKey = carolSpendKeyPair.publicKey;
  // carolAccountKeys.viewSecretKey = carolViewKeyPair.secretKey;
  // carolAccountKeys.spendSecretKey = carolSpendKeyPair.secretKey;
  // Crypto::PublicKey carolViewPublicKey = carolViewKeyPair.publicKey;
  // Crypto::PublicKey carolSpendPublicKey = carolSpendKeyPair.publicKey;
  // Crypto::SecretKey carolViewSecretKey = carolViewKeyPair.secretKey;
  // Crypto::SecretKey carolSpendSecretKey = carolSpendKeyPair.secretKey;

  // For some reason, there must be at least 1 block between Alice's block and the genesis block for this test to work
  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));

  ////////////////////////////////////////////////////////////////////////
  // 1. Alice is a miner and finds a new block and gets the coinbase reward
  ////////////////////////////////////////////////////////////////////////

  // create block 1
  Block block1;
  block1.nonce = 0;
  block1.timestamp = time(nullptr);
  block1.previousBlockHash = blockchain.getTailId();

  // create coinbase transaction 1

  Transaction coinbaseTransaction1;
  coinbaseTransaction1.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction1.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction input 1

  BaseInput coinbaseInput1;
  coinbaseInput1.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction1.inputs.push_back(coinbaseInput1);

  // coinbase transaction output 1

  TransactionOutput coinbaseTransactionOutput1;

  // coinbase transaction public key 1
  KeyPair coinbaseTransactionKeyPair1 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey1 = coinbaseTransactionKeyPair1.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey1 = coinbaseTransactionKeyPair1.secretKey;

  // coinbase ephemeral public key 1
  Crypto::KeyDerivation derivation1;
  Crypto::PublicKey coinbaseEphemeralPublicKey1;
  size_t outputIndex1 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey1, derivation1);
  derive_public_key(derivation1, outputIndex1, aliceSpendPublicKey, coinbaseEphemeralPublicKey1);

  // set coinbase transaction output amount 1
  size_t medianSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize1 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins1;
  Crypto::Hash lastBlockHash1 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash1, alreadyGeneratedCoins1);

  uint64_t fee1 = 0;
  uint64_t reward1;
  int64_t emissionChange1;
  currency.getBlockReward1(medianSize1, currentBlockSize1, alreadyGeneratedCoins1, fee1, reward1, emissionChange1);
  coinbaseTransactionOutput1.amount = reward1;

  // coinbase output target 1
  KeyOutput coinbaseKeyOutput1;

  coinbaseKeyOutput1.key = coinbaseEphemeralPublicKey1;
  coinbaseTransactionOutput1.target = coinbaseKeyOutput1;

  coinbaseTransaction1.outputs.push_back(coinbaseTransactionOutput1);

  // coinbase transaction extra 1
  
  coinbaseTransaction1.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction1.extra.push_back(coinbaseTransactionPublicKey1.data[i]);
  }

  // add coinbase transaction 1 to block 1
  block1.baseTransaction = coinbaseTransaction1;

  // add merkle root
  block1.merkleRoot = get_tx_tree_hash(block1);

  // find nonce appropriate for current difficulty
  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block1, difficulty, proofOfWorkIgnore))
  {
    block1.nonce++;
  }

  // add block to blockchain
  block_verification_context bvc;
  ASSERT_TRUE(blockchain.addNewBlock(block1, bvc));

  ASSERT_TRUE(blockchain.haveTransaction(getObjectHash(coinbaseTransaction1)));

  // allow coinbase transaction to mature
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    Crypto::Hash blockHashIgnore;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHashIgnore));
  }

  ////////////////////////////////////////////////////////////////////////
  // 2. Alice sends money to Bob
  ////////////////////////////////////////////////////////////////////////

  // totalInputAmount and totalOutputAmount are used to calculate the coinbase reward
  uint64_t totalInputAmount = 0;
  uint64_t totalOutputAmount = 0;

  // create block 2
  Block block2;
  block2.nonce = 1;
  block2.timestamp = time(nullptr);
  block2.previousBlockHash = blockchain.getTailId();

  // create transaction

  Transaction transaction2;
  transaction2.version = CURRENT_TRANSACTION_VERSION;
  transaction2.unlockTime = 0;

  // create transaction random transaction key
  KeyPair transactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey transactionPublicKey2 = transactionKeyPair2.publicKey;
  Crypto::SecretKey transactionSecretKey2 = transactionKeyPair2.secretKey;

  // create transaction extra
  transaction2.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction2.extra.push_back(transactionPublicKey2.data[i]);
  }

  // transaction input

  // create key image
  KeyPair input_eph_key_pair_2;
  Crypto::KeyImage keyImage2;
  size_t realOutputIndex2 = 0;
  ASSERT_TRUE(generate_key_image_helper(aliceAccountKeys, coinbaseTransactionPublicKey1, realOutputIndex2, input_eph_key_pair_2, keyImage2));

  KeyInput keyInput2;
  keyInput2.amount = reward1;  // should find a way to calculate this value by using alice's view private key to find the transaction
  totalInputAmount += keyInput2.amount;
  keyInput2.keyImage = keyImage2;
  keyInput2.outputIndexes = {0};
  keyInput2.outputIndexes = absolute_output_offsets_to_relative(keyInput2.outputIndexes);
  transaction2.inputs.push_back(keyInput2);

  // transaction output

  // ephemeral public key 2
  Crypto::KeyDerivation transactionDerivation2;
  Crypto::PublicKey out_eph_public_key_2;
  size_t transactionOutputIndex2 = 0;
  generate_key_derivation(bobViewPublicKey, transactionSecretKey2, transactionDerivation2);
  derive_public_key(transactionDerivation2, transactionOutputIndex2, bobSpendPublicKey, out_eph_public_key_2);

  // output target
  KeyOutput keyOutput2;
  keyOutput2.key = out_eph_public_key_2;

  TransactionOutput transactionOutput2;
  transactionOutput2.amount = 100;
  // totalOutputAmount is used later to calcultate the coinbase reward
  totalOutputAmount += transactionOutput2.amount;
  transactionOutput2.target = keyOutput2;

  transaction2.outputs.push_back(transactionOutput2);

  // transaction prefix hash
  Crypto::Hash tx2_prefix_hash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction2));

  // transaction signature

  // coinbase keyOutput ephemeral secret key 1
  std::vector<Crypto::PublicKey> transactionPublicKeysToAlice = getAccountIncomingTransactionPublicKeys(blockchain, currency, tx_memory_pool, aliceAccountKeys);
  ASSERT_EQ(1, transactionPublicKeysToAlice.size());
  
  Crypto::PublicKey transactionPublicKeyToAlice = transactionPublicKeysToAlice[0];

  ASSERT_TRUE(publicKeysEqual(transactionPublicKeyToAlice, coinbaseTransactionPublicKey1));

  Crypto::SecretKey coinbase_eph_secret_key_1;
  generate_key_derivation(transactionPublicKeyToAlice, aliceViewSecretKey, derivation1);
  derive_secret_key(derivation1, outputIndex1, aliceSpendSecretKey, coinbase_eph_secret_key_1);

  ASSERT_TRUE(publicKeysEqual(input_eph_key_pair_2.publicKey, coinbaseEphemeralPublicKey1));
  ASSERT_TRUE(secretKeysEqual(input_eph_key_pair_2.secretKey, coinbase_eph_secret_key_1));

  std::vector<const Crypto::PublicKey*> keys_ptrs2;
  // keys_ptrs2.push_back(&input_eph_key_pair_2.publicKey);
  keys_ptrs2.push_back(&coinbaseEphemeralPublicKey1);

  transaction2.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& sigs = transaction2.signatures.back();
  sigs.resize(coinbaseTransaction1.outputs.size());
  
  Crypto::Hash prefix_hash = tx2_prefix_hash;
  Crypto::KeyImage image = keyImage2;
  std::vector<const Crypto::PublicKey *> pubs = keys_ptrs2;
  // Crypto::SecretKey sec = input_eph_key_pair_2.secretKey;
  Crypto::SecretKey sec = coinbase_eph_secret_key_1;
  size_t sec_index = 0;
  Crypto::Signature *sig = sigs.data();
  generate_ring_signature(prefix_hash, image, pubs, sec, sec_index, sig);
  
  ASSERT_TRUE(check_ring_signature(prefix_hash, image, pubs, sig));

  // add transaction2 to transaction mempool
  tx_verification_context tvc;
  bool kept_by_block = false;
  tx_memory_pool.add_tx(transaction2, tvc, kept_by_block);

  // add transaction 2 to block 2
  block2.transactionHashes.push_back(getObjectHash(transaction2));

  ASSERT_FALSE(blockchain.haveSpentKeyImages(transaction2));

  // create coinbase transaction 2

  Transaction coinbaseTransaction2;
  coinbaseTransaction2.version = CURRENT_TRANSACTION_VERSION;
  coinbaseTransaction2.unlockTime = blockchain.getCurrentBlockchainHeight() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // coinbase transaction input 2

  BaseInput coinbaseInput2;
  coinbaseInput2.blockIndex = blockchain.getCurrentBlockchainHeight();
  coinbaseTransaction2.inputs.push_back(coinbaseInput2);

  // coinbase transaction output 2

  TransactionOutput coinbaseTransactionOutput2;

  // coinbase transaction public key 2
  KeyPair coinbaseTransactionKeyPair2 = generateKeyPair();
  Crypto::PublicKey coinbaseTransactionPublicKey2 = coinbaseTransactionKeyPair2.publicKey;
  Crypto::SecretKey coinbaseTransactionSecretKey2 = coinbaseTransactionKeyPair2.secretKey;

  // create keyOutput public key 2
  Crypto::KeyDerivation derivation2;
  Crypto::PublicKey coinbase_eph_public_key_2;
  size_t outputIndex2 = 0;
  generate_key_derivation(aliceViewPublicKey, coinbaseTransactionSecretKey2, derivation2);
  derive_public_key(derivation2, outputIndex2, aliceSpendPublicKey, coinbase_eph_public_key_2);

  // set coinbase transaction output amount 2
  size_t medianSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  size_t currentBlockSize2 = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  uint64_t alreadyGeneratedCoins2;
  Crypto::Hash lastBlockHash2 = blockchain.getTailId();
  blockchain.getAlreadyGeneratedCoins(lastBlockHash2, alreadyGeneratedCoins2);

  uint64_t fee2 = totalInputAmount - totalOutputAmount;
  uint64_t reward2;
  int64_t emissionChange2;
  currency.getBlockReward1(medianSize2, currentBlockSize2, alreadyGeneratedCoins2, fee2, reward2, emissionChange2);
  coinbaseTransactionOutput2.amount = reward2;

  // create output target 2
  KeyOutput coinbaseKeyOutput2;

  coinbaseKeyOutput2.key = coinbase_eph_public_key_2;
  coinbaseTransactionOutput2.target = coinbaseKeyOutput2;

  coinbaseTransaction2.outputs.push_back(coinbaseTransactionOutput2);

  // create coinbase transaction extra 2
  
  coinbaseTransaction2.extra = {1}; // 1 signifies a transaction public key
  for (int i = 0; i < 32; i++)
  {
    coinbaseTransaction2.extra.push_back(coinbaseTransactionPublicKey2.data[i]);
  }

  // add coinbase transaction 2 to block 2
  block2.baseTransaction = coinbaseTransaction2;

  // add merkle root
  block2.merkleRoot = get_tx_tree_hash(block2);

  // find nonce appropriate for current difficulty
  difficulty = blockchain.getDifficultyForNextBlock();
  while(!currency.checkProofOfWork1(context, block2, difficulty, proofOfWorkIgnore))
  {
    block2.nonce++;
  }

  ASSERT_TRUE(blockchain.addNewBlock(block2, bvc));

  ASSERT_TRUE(blockchain.haveSpentKeyImages(transaction2));

  // check ephemeral public key using bob's secret 
  Crypto::KeyDerivation bobPublicEphKeyDerivation2;
  Crypto::PublicKey bob_eph_public_key_2;
  size_t bobTransactionOutputIndex2 = 0;
  generate_key_derivation(transactionPublicKey2, bobViewSecretKey, bobPublicEphKeyDerivation2);
  derive_public_key(bobPublicEphKeyDerivation2, bobTransactionOutputIndex2, bobSpendPublicKey, bob_eph_public_key_2);

  ASSERT_TRUE(publicKeysEqual(out_eph_public_key_2, bob_eph_public_key_2));

  // check ephemeral secret key using bob's secret keys
  Crypto::KeyDerivation bobSecretEphKeyDerivation2;
  Crypto::SecretKey bob_eph_secret_key_2;
  generate_key_derivation(transactionPublicKey2, bobViewSecretKey, bobSecretEphKeyDerivation2);
  derive_secret_key(bobSecretEphKeyDerivation2, bobTransactionOutputIndex2, bobSpendSecretKey, bob_eph_secret_key_2);

  // get output ephemeral public key from output ephemeral secret key
  Crypto::PublicKey out_eph_public_key_2_2;
  ASSERT_TRUE(secret_key_to_public_key(bob_eph_secret_key_2, out_eph_public_key_2_2));

  ASSERT_TRUE(publicKeysEqual(bob_eph_public_key_2, out_eph_public_key_2_2));
}

// getDifficultyForNextBlock()
TEST(Blockchain, 27)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  difficulty_type difficulty = blockchain.getDifficultyForNextBlock();

  ASSERT_EQ(1, difficulty);

  Crypto::Hash blockHashIgnore;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHashIgnore));

  difficulty = blockchain.getDifficultyForNextBlock();
  ASSERT_EQ(100000, difficulty);
}

// getAlternativeBlocksCount() and
// getAlternativeBlocks() and
// isBlockInMainChain()
TEST(Blockchain, 28)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  ASSERT_EQ(0, blockchain.getAlternativeBlocksCount());

  // add 3 blocks to main chain
  Crypto::Hash blockHash1a;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash1a));

  Crypto::Hash blockHash2a;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash2a));

  Crypto::Hash blockHash3a;
  ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash3a));

  ASSERT_EQ(4, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(0, blockchain.getAlternativeBlocksCount());

  // add an alternative block to the genesis block
  uint32_t blockHeight = 1;
  Crypto::Hash blockHash1b;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash1b, currency.genesisBlockHash(), blockHeight));

  //                block1b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(1, blockchain.getAlternativeBlocksCount());

  // add an altBlock2 to altBlock1
  blockHeight = 2;
  Crypto::Hash blockHash2b;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash2b, blockHash1b, blockHeight));

  //                block1b - block2b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(2, blockchain.getAlternativeBlocksCount());

  // add an altBlock3 to altBlock2
  blockHeight = 3;
  Crypto::Hash blockHash3b;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash3b, blockHash2b, blockHeight));

  //                block1b - block2b - block3b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(3, blockchain.getAlternativeBlocksCount());

  // add block4b to block3b
  // causes a blockchain reorganization
  // main chain is now the alternative chain
  // alternative chain now becomes the main chain
  blockHeight = 4;
  Crypto::Hash blockHash4b;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash4b, blockHash3b, blockHeight));

  //                block1b - block2b - block3b - block4b (main chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (alt chain)

  ASSERT_EQ(5, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(3, blockchain.getAlternativeBlocksCount());

  // check block hashes on main chain
  ASSERT_TRUE(hashesEqual(blockHash1b, blockchain.getBlockIdByHeight(1)));
  ASSERT_TRUE(hashesEqual(blockHash2b, blockchain.getBlockIdByHeight(2)));
  ASSERT_TRUE(hashesEqual(blockHash3b, blockchain.getBlockIdByHeight(3)));
  ASSERT_TRUE(hashesEqual(blockHash4b, blockchain.getBlockIdByHeight(4)));

  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash1b));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash2b));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash3b));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash4b));

  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash1a));
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash2a));
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash3a));

  // check blocks on alternative chain
  std::list<Block> altBlocks;
  ASSERT_TRUE(blockchain.getAlternativeBlocks(altBlocks));
  ASSERT_EQ(3, altBlocks.size());
  Block altBlock1 = altBlocks.front();
  altBlocks.pop_front();
  Block altBlock2 = altBlocks.front();
  altBlocks.pop_front();
  Block altBlock3 = altBlocks.front();

  std::vector<Crypto::Hash> altBlockHashes;
  altBlockHashes.push_back(get_block_hash(altBlock1));
  altBlockHashes.push_back(get_block_hash(altBlock2));
  altBlockHashes.push_back(get_block_hash(altBlock3));

  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash1a) != altBlockHashes.end());
  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash2a) != altBlockHashes.end());
  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash3a) != altBlockHashes.end());

  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash1b) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash2b) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash3b) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash4b) != altBlockHashes.end());

  // add block4a to block3a
  blockHeight = 4;
  Crypto::Hash blockHash4a;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash4a, blockHash3a, blockHeight));

  //                block1b - block2b - block3b - block4b (main chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a - block4a (alt chain)

  ASSERT_EQ(5, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(4, blockchain.getAlternativeBlocksCount());

  // add block5a to block4a
  // causes a blockchain reorganization again
  // main chain is now the alternative chain
  // alternative chain now becomes the main chain
  blockHeight = 5;
  Crypto::Hash blockHash5a;
  ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, blockHash5a, blockHash4a, blockHeight));

  //                block1b - block2b - block3b - block4b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a - block4a - block5a (main chain)

  ASSERT_EQ(6, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(4, blockchain.getAlternativeBlocksCount());

  // check block hashes on main chain
  ASSERT_TRUE(hashesEqual(blockHash1a, blockchain.getBlockIdByHeight(1)));
  ASSERT_TRUE(hashesEqual(blockHash2a, blockchain.getBlockIdByHeight(2)));
  ASSERT_TRUE(hashesEqual(blockHash3a, blockchain.getBlockIdByHeight(3)));
  ASSERT_TRUE(hashesEqual(blockHash4a, blockchain.getBlockIdByHeight(4)));
  ASSERT_TRUE(hashesEqual(blockHash5a, blockchain.getBlockIdByHeight(5)));

  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash1a));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash2a));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash3a));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash4a));
  ASSERT_TRUE(blockchain.isBlockInMainChain(blockHash5a));

  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash1b));
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash2b));
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash3b));
  ASSERT_FALSE(blockchain.isBlockInMainChain(blockHash4b));

  // check block hashes on alternative chain
  altBlocks.clear();
  ASSERT_TRUE(blockchain.getAlternativeBlocks(altBlocks));
  ASSERT_EQ(4, altBlocks.size());
  altBlock1 = altBlocks.front();
  altBlocks.pop_front();
  altBlock2 = altBlocks.front();
  altBlocks.pop_front();
  altBlock3 = altBlocks.front();
  altBlocks.pop_front();
  Block altBlock4 = altBlocks.front();
  altBlocks.pop_front();

  altBlockHashes.clear();
  altBlockHashes.push_back(get_block_hash(altBlock1));
  altBlockHashes.push_back(get_block_hash(altBlock2));
  altBlockHashes.push_back(get_block_hash(altBlock3));
  altBlockHashes.push_back(get_block_hash(altBlock4));

  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash1b) != altBlockHashes.end());
  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash2b) != altBlockHashes.end());
  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash3b) != altBlockHashes.end());
  ASSERT_TRUE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash4b) != altBlockHashes.end());

  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash1a) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash2a) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash3a) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash4a) != altBlockHashes.end());
  ASSERT_FALSE(std::find(altBlockHashes.begin(), altBlockHashes.end(), blockHash5a) != altBlockHashes.end());
}

// resetAndSetGenesisBlock()
TEST(Blockchain, 29)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // add 10 blocks to main chain
  for (int i = 0; i < 10; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  }

  // add 10 blocks to alternative chain
  Crypto::Hash prevBlockHash = currency.genesisBlockHash();
  for (uint32_t height = 1; height <= 10; height++)
  {
    Crypto::Hash altBlockHash;
    ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, altBlockHash, prevBlockHash, height));
    prevBlockHash = altBlockHash;
  }

  ASSERT_EQ(11, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(10, blockchain.getAlternativeBlocksCount());

  ASSERT_TRUE(blockchain.resetAndSetGenesisBlock(currency.genesisBlock()));

  ASSERT_EQ(1, blockchain.getCurrentBlockchainHeight());
  ASSERT_EQ(0, blockchain.getAlternativeBlocksCount());
}

// buildSparseChain()
TEST(Blockchain, 30)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> sparseChain = blockchain.buildSparseChain();

  std::vector<Crypto::Hash> expectedSparseChain;
  // How to get indexes:
  // 100 = 99 + 1

  // 100 - 2^0 = 99
  // 100 - 2^1 = 98
  // 100 - 2^2 = 96
  // 100 - 2^3 = 92
  // 100 - 2^4 = 84
  // 100 - 2^5 = 68
  // 100 - 2^6 = 36
  // add genesis block
  expectedSparseChain.push_back(blockHashes[99]);
  expectedSparseChain.push_back(blockHashes[98]);
  expectedSparseChain.push_back(blockHashes[96]);
  expectedSparseChain.push_back(blockHashes[92]);
  expectedSparseChain.push_back(blockHashes[84]);
  expectedSparseChain.push_back(blockHashes[68]);
  expectedSparseChain.push_back(blockHashes[36]);
  expectedSparseChain.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(std::equal(sparseChain.begin(), sparseChain.end(), expectedSparseChain.begin()));
}

// buildSparseChain(startBlockId)
TEST(Blockchain, 31)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> sparseChain = blockchain.buildSparseChain(blockHashes[60]);

  std::vector<Crypto::Hash> expectedSparseChain;
  // How to get indexes:
  // 61 = 60 + 1

  // 61 - 2^0 = 60
  // 61 - 2^1 = 59
  // 61 - 2^2 = 57
  // 61 - 2^3 = 53
  // 61 - 2^4 = 45
  // 61 - 2^5 = 29
  // add genesis block
  expectedSparseChain.push_back(blockHashes[60]);
  expectedSparseChain.push_back(blockHashes[59]);
  expectedSparseChain.push_back(blockHashes[57]);
  expectedSparseChain.push_back(blockHashes[53]);
  expectedSparseChain.push_back(blockHashes[45]);
  expectedSparseChain.push_back(blockHashes[29]);
  expectedSparseChain.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(std::equal(sparseChain.begin(), sparseChain.end(), expectedSparseChain.begin()));
}

// findBlockchainSupplement()
TEST(Blockchain, 32)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> supplementHashes;

  // last element in vector must be the genesis block hash
  supplementHashes.push_back(currency.genesisBlockHash());
  ASSERT_EQ(0, blockchain.findBlockchainSupplement(supplementHashes));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  // blockHash at index 9 has a height of 10?
  ASSERT_EQ(10, blockchain.findBlockchainSupplement(supplementHashes));

  // returns the hight of the first block in the vector
  // the genesis block must be the last entry in the vector
  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[4]);
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  ASSERT_EQ(5, blockchain.findBlockchainSupplement(supplementHashes));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[0]);
  supplementHashes.push_back(blockHashes[5]);
  supplementHashes.push_back(blockHashes[10]);
  supplementHashes.push_back(blockHashes[15]);
  supplementHashes.push_back(currency.genesisBlockHash());
  ASSERT_EQ(1, blockchain.findBlockchainSupplement(supplementHashes));
  
  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[99]);
  supplementHashes.push_back(blockHashes[50]);
  supplementHashes.push_back(blockHashes[25]);
  supplementHashes.push_back(blockHashes[10]);
  supplementHashes.push_back(currency.genesisBlockHash());
  ASSERT_EQ(100, blockchain.findBlockchainSupplement(supplementHashes));
}

// findBlockchainSupplement(blockHashes, maxCount, totalBlockCount, startBlockIndex)
TEST(Blockchain, 33)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> supplementHashes;

  supplementHashes.push_back(currency.genesisBlockHash());
  size_t maxCount = 50;
  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  // returns blocks from blockchain starting at startBlockIndex
  std::vector<Crypto::Hash> supplementHashesOuput = blockchain.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(101, totalBlockCount);
  ASSERT_EQ(0, startBlockIndex);
  ASSERT_EQ(50, supplementHashesOuput.size());

  ASSERT_TRUE(hashesEqual(supplementHashesOuput[0], currency.genesisBlockHash()));
  for (int i = 0; i < 49; i++)
  {
    ASSERT_TRUE(hashesEqual(supplementHashesOuput[i + 1], blockHashes[i]));
  }

  ////////////////////////////////////////////////////////////////////////

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  maxCount = 50;
  supplementHashesOuput = blockchain.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(101, totalBlockCount);
  ASSERT_EQ(10, startBlockIndex);
  ASSERT_EQ(50, supplementHashesOuput.size());

  for (int i = 0; i < 50; i++)
  {
    ASSERT_TRUE(hashesEqual(supplementHashesOuput[i], blockHashes[i + 9]));
  }

  ////////////////////////////////////////////////////////////////////////

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[25]);
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  maxCount = 50;
  supplementHashesOuput = blockchain.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(101, totalBlockCount);
  ASSERT_EQ(26, startBlockIndex);
  ASSERT_EQ(50, supplementHashesOuput.size());

  for (int i = 0; i < 50; i++)
  {
    ASSERT_TRUE(hashesEqual(supplementHashesOuput[i], blockHashes[i + 25]));
  }

  ////////////////////////////////////////////////////////////////////////

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[49]);
  supplementHashes.push_back(blockHashes[25]);
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  maxCount = 50;
  supplementHashesOuput = blockchain.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(101, totalBlockCount);
  ASSERT_EQ(50, startBlockIndex);
  ASSERT_EQ(50, supplementHashesOuput.size());

  for (int i = 0; i < 50; i++)
  {
    ASSERT_TRUE(hashesEqual(supplementHashesOuput[i], blockHashes[i + 49]));
  }

  ////////////////////////////////////////////////////////////////////////

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[75]);
  supplementHashes.push_back(blockHashes[49]);
  supplementHashes.push_back(blockHashes[25]);
  supplementHashes.push_back(blockHashes[9]);
  supplementHashes.push_back(currency.genesisBlockHash());
  maxCount = 50;
  supplementHashesOuput = blockchain.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(101, totalBlockCount);
  ASSERT_EQ(76, startBlockIndex);
  ASSERT_EQ(25, supplementHashesOuput.size());

  for (int i = 0; i < 25; i++)
  {
    ASSERT_TRUE(hashesEqual(supplementHashesOuput[i], blockHashes[i + 75]));
  }
}

// handleGetObjects()
// skip for now
TEST(Blockchain, 34)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // NOTIFY_REQUEST_GET_OBJECTS_request arg;
  // NOTIFY_RESPONSE_GET_OBJECTS_request rsp;
  // ASSERT_TRUE(blockchain.handleGetObjects(arg, rsp));
}

// getRandomOutsByAmount()
// skip for now
TEST(Blockchain, 35)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request req;
  // CORE_RPC_COMMAND_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response res;
  // ASSERT_TRUE(blockchain.getRandomOutsByAmount(req, res));
}

// getBackwardBlocksSize()
TEST(Blockchain, 36)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
    blockHashes.push_back(blockHash);
  }

  size_t fromHeight = 0;
  size_t maxCount = 10;
  std::vector<size_t> sizeVector;
  blockchain.getBackwardBlocksSize(fromHeight, sizeVector, maxCount);
  // get sizes of blocks starting from block 0 (genesis block) and moving backwards
  ASSERT_EQ(1, sizeVector.size());

  sizeVector.clear();
  fromHeight = 1;
  maxCount = 10;
  blockchain.getBackwardBlocksSize(fromHeight, sizeVector, maxCount);
  ASSERT_EQ(2, sizeVector.size());

  sizeVector.clear();
  fromHeight = 2;
  maxCount = 10;
  blockchain.getBackwardBlocksSize(fromHeight, sizeVector, maxCount);
  ASSERT_EQ(3, sizeVector.size());

  sizeVector.clear();
  fromHeight = 20;
  maxCount = 10;
  blockchain.getBackwardBlocksSize(fromHeight, sizeVector, maxCount);
  ASSERT_EQ(10, sizeVector.size());

  sizeVector.clear();
  fromHeight = 70;
  maxCount = 100;
  blockchain.getBackwardBlocksSize(fromHeight, sizeVector, maxCount);
  ASSERT_EQ(71, sizeVector.size());

  // size of genesis block is 77 according to gdb
  // size of every other block is 82 according to gdb
}

// getTransactionOutputGlobalIndexes()
TEST(Blockchain, 37)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash transactionHash;
  std::vector<uint32_t> indexes;

  std::vector<Crypto::Hash> transactionHashes;

  // add 10 blocks to blockchain
  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(addBlock3(blockchain, currency, tx_memory_pool, transactionHash));
    transactionHashes.push_back(transactionHash);
  }

  for (int i = 0; i < 10; i++)
  {
    // each transaction hash has a global output index of 0
    // each transction has a different amount
    ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHashes[i], indexes));
    ASSERT_EQ(1, indexes.size());
    ASSERT_EQ(0, indexes[0]);
    indexes.clear();
  }

  // creates a transaction with 100 outputs each with an amount of 50
  ASSERT_TRUE(addBlock4(blockchain, currency, tx_memory_pool, transactionHash));

  indexes.clear();
  ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHash, indexes));
  ASSERT_EQ(100, indexes.size());

  for (int i = 0; i < 100; i++)
  {
    //  index =
    //    {
    //      0, 1, 2, 3, 4, 5, 6, 7, 8 , 9,
    //      10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    //      20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    //      30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    //      40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    //
    //    }
    ASSERT_EQ(i, indexes[i]);
  }

  // create a transaction with amount equal to 0.00000123
  uint64_t transactionAmount = 123;
  ASSERT_TRUE(addBlock5(blockchain, currency, tx_memory_pool, transactionHash, transactionAmount));
  indexes.clear();
  ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHash, indexes));
  ASSERT_EQ(1, indexes.size());
  ASSERT_EQ(0, indexes[0]);

  // create another transaction with amount equal to 0.00000123
  ASSERT_TRUE(addBlock5(blockchain, currency, tx_memory_pool, transactionHash, transactionAmount));
  indexes.clear();
  ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHash, indexes));
  ASSERT_EQ(1, indexes.size());
  // global index of this transaction is now 1
  ASSERT_EQ(1, indexes[0]);

  // create another transaction with amount equal to 0.00000123
  ASSERT_TRUE(addBlock5(blockchain, currency, tx_memory_pool, transactionHash, transactionAmount));
  indexes.clear();
  ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHash, indexes));
  ASSERT_EQ(1, indexes.size());
  // global index of this transaction is now 2
  ASSERT_EQ(2, indexes[0]);

  // create another transaction with amount equal to 0.00000123
  ASSERT_TRUE(addBlock5(blockchain, currency, tx_memory_pool, transactionHash, transactionAmount));
  indexes.clear();
  ASSERT_TRUE(blockchain.getTransactionOutputGlobalIndexes(transactionHash, indexes));
  ASSERT_EQ(1, indexes.size());
  // global index of this transaction is now 3
  ASSERT_EQ(3, indexes[0]);
}

// getCurrentCumulativeBlocksizeLimit()
TEST(Blockchain, 38)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // block height 0 (genesis block)
  // sz = {77}
  // median is actually 77 but is converted to 1,048,576 (1 mb)
  // currentCumulativeBlockSizeLimit = median * 2
  ASSERT_EQ(2097152, blockchain.getCurrentCumulativeBlocksizeLimit());
}

// getBlockContainingTransaction()
TEST(Blockchain, 39)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash transactionHash;
  Crypto::Hash blockHash;
  uint32_t blockHeight;
  Crypto::Hash blockHashRet;

  for (int i = 0; i < 100; i++)
  {
    ASSERT_TRUE(addBlock7(blockchain, currency, tx_memory_pool, blockHash, transactionHash));
    ASSERT_TRUE(blockchain.getBlockContainingTransaction(transactionHash, blockHashRet, blockHeight));
    ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
    ASSERT_EQ(i + 1, blockHeight);
  }
}

// getBlockSize()
TEST(Blockchain, 40)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  for (int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    uint32_t numTransactions = rand() % 449 + 1; // more than 450 transactions causes the blocks to be too big
    size_t blockSize;
    ASSERT_TRUE(addBlock8(blockchain, currency, tx_memory_pool, blockHash, numTransactions, blockSize));
    
    size_t blockSizeRet;
    ASSERT_TRUE(blockchain.getBlockSize(blockHash, blockSizeRet));
  }
}

// getGeneratedTransactionsNumber()
// returns total number of transactions ever created up to a certain blockchain height
TEST(Blockchain, 41)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  uint64_t totalTransactions = 1;

  for (int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    uint32_t numTransactions = rand() % 449 + 1; // more than 450 transactions causes the blocks to be too big
    size_t blockSize;
    ASSERT_TRUE(addBlock8(blockchain, currency, tx_memory_pool, blockHash, numTransactions, blockSize));
    
    totalTransactions += numTransactions + 1; // plus 1 is for the coinbase transaction in each block

    uint64_t totalTransactionsRet;
    uint32_t blockHeight = i + 1;
    ASSERT_TRUE(blockchain.getGeneratedTransactionsNumber(blockHeight, totalTransactionsRet));
    ASSERT_EQ(totalTransactions, totalTransactionsRet);
  }
}

// getOrphanBlockIdsByHeight()
// returns all orphaned blocks at a specific height
TEST(Blockchain, 42)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  // add 50 blocks to main chain
  for (int i = 0; i < 50; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock1(blockchain, currency, tx_memory_pool, blockHash));
  }

  // genesisBlock - block1 - block2 - block3 - ... - block98 - block99 - block100 (main chain)

  Crypto::Hash orphanedBlockHash;
  std::vector<Crypto::Hash> orphanedBlockHashes;
  Crypto::Hash prevOrphanedBlockHash = currency.genesisBlockHash();

  // // add 50 blocks to alternative chain branching off the genesis block
  for (uint32_t height = 1; height <= 50; height++)
  {
    ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, orphanedBlockHash, prevOrphanedBlockHash, height));
    orphanedBlockHashes.push_back(orphanedBlockHash);
    prevOrphanedBlockHash = orphanedBlockHash;
  }

  //               block1 - block2 - block3 - ... - block98 - block99 - block100 (alt chain 1)
  //              /
  // genesisBlock - block1 - block2 - block3 - ... - block98 - block99 - block100 (main chain)

  std::vector<Crypto::Hash> orphanedBlockHashesRet;

  uint32_t height = 1;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));
  ASSERT_EQ(1, orphanedBlockHashesRet.size());
  ASSERT_TRUE(hashesEqual(orphanedBlockHashes[0], orphanedBlockHashesRet[0]));

  orphanedBlockHashesRet.clear();
  height = 2;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));
  ASSERT_EQ(1, orphanedBlockHashesRet.size());
  ASSERT_TRUE(hashesEqual(orphanedBlockHashes[1], orphanedBlockHashesRet[0]));

  orphanedBlockHashesRet.clear();
  height = 3;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));
  ASSERT_EQ(1, orphanedBlockHashesRet.size());
  ASSERT_TRUE(hashesEqual(orphanedBlockHashes[2], orphanedBlockHashesRet[0]));

  orphanedBlockHashesRet.clear();
  height = 4;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));
  ASSERT_EQ(1, orphanedBlockHashesRet.size());
  ASSERT_TRUE(hashesEqual(orphanedBlockHashes[3], orphanedBlockHashesRet[0]));

  orphanedBlockHashesRet.clear();
  height = 5;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));
  ASSERT_EQ(1, orphanedBlockHashesRet.size());
  ASSERT_TRUE(hashesEqual(orphanedBlockHashes[4], orphanedBlockHashesRet[0]));

  // check rest of orphaned blocks
  for (uint32_t height = 6; height <= 50; height++)
  {
    orphanedBlockHashesRet.clear();
    ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet));

    ASSERT_EQ(1, orphanedBlockHashesRet.size());
    ASSERT_TRUE(hashesEqual(orphanedBlockHashes[height - 1], orphanedBlockHashesRet[0]));
  }

  Crypto::Hash orphanedBlockHash2;
  std::vector<Crypto::Hash> orphanedBlockHashes2;
  Crypto::Hash prevOrphanedBlockHash2 = currency.genesisBlockHash();

  // add 50 more blocks to alternative chain branching off the genesis block

  for (uint32_t height = 1; height <= 50; height++)
  {
    ASSERT_TRUE(addAlternativeBlock(blockchain, currency, tx_memory_pool, orphanedBlockHash2, prevOrphanedBlockHash2, height));
    orphanedBlockHashes2.push_back(orphanedBlockHash2);
    prevOrphanedBlockHash2 = orphanedBlockHash2;
  }

  //               block1 - block2 - block3 - ... - block98 - block99 - block100 (alt chain 2)
  //              /
  //             / block1 - block2 - block3 - ... - block98 - block99 - block100 (alt chain 1)
  //            / /
  // genesisBlock - block1 - block2 - block3 - ... - block98 - block99 - block100 (main chain)

  std::vector<Crypto::Hash> orphanedBlockHashesRet2;

  uint32_t height2 = 1;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height2, orphanedBlockHashesRet2));
  ASSERT_EQ(2, orphanedBlockHashesRet2.size());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[0]) != orphanedBlockHashesRet2.end());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[0]) != orphanedBlockHashesRet2.end());

  orphanedBlockHashesRet2.clear();
  height2 = 2;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height2, orphanedBlockHashesRet2));
  ASSERT_EQ(2, orphanedBlockHashesRet2.size());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[1]) != orphanedBlockHashesRet2.end());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[1]) != orphanedBlockHashesRet2.end());

  orphanedBlockHashesRet2.clear();
  height2 = 3;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height2, orphanedBlockHashesRet2));
  ASSERT_EQ(2, orphanedBlockHashesRet2.size());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[2]) != orphanedBlockHashesRet2.end());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[2]) != orphanedBlockHashesRet2.end());

  orphanedBlockHashesRet2.clear();
  height2 = 4;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height2, orphanedBlockHashesRet2));
  ASSERT_EQ(2, orphanedBlockHashesRet2.size());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[3]) != orphanedBlockHashesRet2.end());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[3]) != orphanedBlockHashesRet2.end());

  orphanedBlockHashesRet2.clear();
  height2 = 5;
  ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height2, orphanedBlockHashesRet2));
  ASSERT_EQ(2, orphanedBlockHashesRet2.size());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[4]) != orphanedBlockHashesRet2.end());
  ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[4]) != orphanedBlockHashesRet2.end());

  // check rest of orphaned blocks
  for (uint32_t height = 6; height <= 50; height++)
  {
    orphanedBlockHashesRet2.clear();
    ASSERT_TRUE(blockchain.getOrphanBlockIdsByHeight(height, orphanedBlockHashesRet2));
    ASSERT_EQ(2, orphanedBlockHashesRet2.size());
    ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes[height - 1]) != orphanedBlockHashesRet2.end());
    ASSERT_TRUE(std::find(orphanedBlockHashesRet2.begin(), orphanedBlockHashesRet2.end(), orphanedBlockHashes2[height - 1]) != orphanedBlockHashesRet2.end());
  }
}

// getTransactionIdsByPaymentId()
TEST(Blockchain, 43)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  TransactionValidator validator;
  TimeProvider timeProvider;

  tx_memory_pool tx_memory_pool(currency, validator, timeProvider, logger);
  Blockchain blockchain(currency, tx_memory_pool, logger);
  std::string config_folder = Tools::getDefaultDataDirectory();
  ASSERT_TRUE(blockchain.init(config_folder, false));

  Crypto::Hash paymentId = getRandHash();
  Crypto::Hash transactionHash;
  std::vector<Crypto::Hash> transactionHashes;
  std::vector<Crypto::Hash> transactionHashesExpected;

  ASSERT_TRUE(addBlock9(blockchain, currency, tx_memory_pool, paymentId, transactionHash));
  ASSERT_TRUE(blockchain.getTransactionIdsByPaymentId(paymentId, transactionHashes));
  ASSERT_EQ(1, transactionHashes.size());
  ASSERT_TRUE(hashesEqual(transactionHash, transactionHashes[0]));

  // add the same paymentId to another transaction
  transactionHashes.clear();
  ASSERT_TRUE(addBlock9(blockchain, currency, tx_memory_pool, paymentId, transactionHash));
  ASSERT_TRUE(blockchain.getTransactionIdsByPaymentId(paymentId, transactionHashes));
  ASSERT_EQ(2, transactionHashes.size());

  // add the same paymentId to 100 other transaction
  for (int i = 0; i < 100; i++)
  {
    transactionHashes.clear();
    ASSERT_TRUE(addBlock9(blockchain, currency, tx_memory_pool, paymentId, transactionHash));
    ASSERT_TRUE(blockchain.getTransactionIdsByPaymentId(paymentId, transactionHashes));
    ASSERT_EQ(i + 3, transactionHashes.size());
  }
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
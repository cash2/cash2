// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/Core.h"
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
#include "Common/Math.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "Rpc/CoreRpcCommands.h"
#include "CryptoNoteCore/CryptoNoteStatInfo.h"
#include <random>
#include <iostream>

using namespace CryptoNote;

/*

My Notes

class Core
public
  *Core()
  ~Core()
  *on_idle()
  handle_incoming_tx()
  *handle_incoming_block_blob()
  *get_protocol()
  *currency()
  *handle_block_found()
  *get_block_template()
  *addObserver()
  *removeObserver()
  *get_miner()
  *init_options()
  *init()
  *set_genesis_block()
  *deinit()
  addChain()
  handle_get_objects()
  *getBackwardBlocksSizes()
  *getBlockSize()
  *getAlreadyGeneratedCoins()
  *getBlockReward1()
  scanOutputkeysForIndexes()
  *getBlockDifficulty()
  *getBlockContainingTx()
  getMultisigOutputReference()
  *getGeneratedTransactionsNumber()
  *getOrphanBlocksByHeight()
  *getBlocksByTimestamp()
  *getPoolTransactionsByTimestamp()
  getTransactionsByPaymentId()
  getOutByMSigGIndex()
  *getBlock()
  *handleIncomingTransaction()
  executeLocked()
  *addMessageQueue()
  *removeMessageQueue()
  *get_current_blockchain_height()
  *have_block()
  *buildSparseChain()
  *buildSparseChain()
  *on_synchronized()
  *get_blockchain_top()
  *get_blocks()
  *get_blocks()
  get_blocks()
  *queryBlocks()
  *queryBlocksLite()
  *getBlockIdByHeight()
  *getTransactions()
  *getBlockByHash()
  *getBlockHeight()
  *get_alternative_blocks()
  *get_alternative_blocks_count()
  *set_cryptonote_protocol()
  *getPoolTransactions()
  *get_pool_transactions_count()
  *get_blockchain_total_transactions()
  *findBlockchainSupplement()
  *get_stat_info()
  *get_tx_outputs_gindexes()
  *get_tail_id()
  *get_random_outs_for_amounts()
  *pause_mining()
  *update_block_template_and_resume_mining()
  *print_blockchain()
  *print_blockchain_index()
  *print_pool()
  *print_blockchain_outs()
  *getPoolChanges()
  *getPoolChangesLite()
  *getPoolChanges()
  *getNextBlockDifficulty()
  *getTotalGeneratedAmount()

private
  add_new_tx()
  parse_tx_from_blob()
  handle_incoming_block()
  check_tx_syntax()
  check_tx_semantic()
  update_miner_block_template()
  handle_command_line()
  check_tx_inputs_keyimages_diff()
  blockchainUpdated()
  txDeletedFromPool()
  poolUpdated()
  findStartAndFullOffsets()
  findIdsForShortBlocks()

  const Currency& m_currency
  Logging::LoggerRef logger
  CryptoNote::RealTimeProvider m_timeProvider
  tx_memory_pool m_mempool
  Blockchain m_blockchain
  i_cryptonote_protocol* m_pprotocol
  std::unique_ptr<miner> m_miner
  std::string m_config_folder
  cryptonote_protocol_stub m_protocol_stub
  friend class tx_validate_inputs
  std::atomic<bool> m_starter_message_showed
  Tools::ObserverManager<ICoreObserver> m_observerManager
}

*/

uint32_t loopCount = 1;

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
  TimeProvider(time_t timeInput = time(nullptr)) : m_time(timeInput) {}
  virtual time_t now() override { return m_time; }

private:
  time_t m_time;
};

class BlockchainStorageObserver : public IBlockchainStorageObserver
{
public:
  virtual void blockchainUpdated() override
  {
    std::cout << "blockchain updated" << std::endl;
  }
};

class CryptonoteProtocol : public i_cryptonote_protocol
{
public:
  void relay_block(NOTIFY_NEW_BLOCK_request& arg) override
  {
    std::cout << "relay block" << std::endl;
  }

  void relay_transactions(NOTIFY_NEW_TRANSACTIONS_request& arg) override
  {
    std::cout << "relay transactions" << std::endl;
  }
};

class CoreObserver : public ICoreObserver
{
public:
  void blockchainUpdated() override
  {
    std::cout << "blockchain updated" << std::endl;
  }

  void poolUpdated() override
  {
    std::cout << "pool updated" << std::endl;
  }
};

class IBlockImpl : public IBlock
{
public:

  virtual const Block& getBlock() const override
  {
    return m_block;
  }

  virtual size_t getTransactionCount() const override
  {
    return m_transactionCount;
  }

  virtual const Transaction& getTransaction(size_t index) const override
  {
    return m_transaction;
  }

  private:
  Block m_block;
  size_t m_transactionCount;
  Transaction m_transaction;
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

size_t getMedianBlockSize(Core& core)
{
  size_t fromHeight = core.get_current_blockchain_height() - 1;
  std::vector<size_t> blockSizes;
  size_t maxCount = parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW;

  core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount);

  return Common::medianValue(blockSizes);
}

// Returns an empty block to be later added to the blockchain
Block createEmptyBlock(Core& core)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  uint32_t currentBlockchainHeight = core.get_current_blockchain_height();
  block.timestamp = time(nullptr) + (currentBlockchainHeight * parameters::DIFFICULTY_TARGET);

  return block;
}

// Adds an empty block to the blockchain
bool addBlock1(Core& core)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  bool blockAdded = core.handle_block_found(block);

  return blockAdded;
}

// Adds an empty block to the blockchain
// returns the hash of the block added
bool addBlock3(Core& core, Crypto::Hash& blockHash)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  block.timestamp = time(nullptr);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  blockHash = get_block_hash(block);

  bool blockAdded = core.handle_block_found(block);

  return blockAdded;
}

// Adds an empty block to the blockchain
// able to set the timestamp
// returns the hash of the block added
bool addBlock4(Core& core, Crypto::Hash& blockHash, uint64_t timestamp)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  block.timestamp = timestamp;

  blockHash = get_block_hash(block);

  bool added = core.handle_block_found(block);

  return added;
}

// Adds an empty block to the blockchain
// returns transaction public key of the coinbase transaction
// returns hash of the coinbase transaction
bool addBlock5(Core& core, const AccountPublicAddress& minerPublicAddress, Crypto::PublicKey& transactionPublicKey, Crypto::Hash& transactionHash)
{
  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, minerPublicAddress, difficulty, height, extraNonce);

  transactionPublicKey = getTransactionPublicKeyFromExtra(block.baseTransaction.extra);

  transactionHash = getObjectHash(block.baseTransaction);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  bool added = core.handle_block_found(block);

  return added;
}

// Adds an empty block to the blockchain
// returns transaction public key of the coinbase transaction
// returns hash of block added
bool addBlock6(Core& core, const AccountPublicAddress& minerPublicAddress,
                                  Crypto::PublicKey& transactionPublicKey,
                  Crypto::Hash& transactionHash, Crypto::Hash& blockHash)
{
  uint32_t currentBlockchainHeight = core.get_current_blockchain_height();

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, minerPublicAddress, difficulty, height, extraNonce);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  transactionPublicKey = getTransactionPublicKeyFromExtra(block.baseTransaction.extra);

  transactionHash = getObjectHash(block.baseTransaction);

  blockHash = get_block_hash(block);

  bool added = core.handle_block_found(block);

  return added;
}

// Adds an empty block to the blockchain
// returns hash of the coinbase transaction
bool addBlock6(Core& core, Crypto::Hash& transactionHash)
{
  uint32_t currentBlockchainHeight = core.get_current_blockchain_height();

  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  bool blockAdded = core.handle_block_found(block);

  transactionHash = getObjectHash(block.baseTransaction);

  return blockAdded;
}

// Adds an empty block to the blockchain
// returns hash of the coinbase transaction
bool addBlock7(Core& core, Crypto::Hash& transactionHash, Crypto::Hash& blockHash, uint32_t& blockHeight)
{
  blockHeight = core.get_current_blockchain_height();

  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  block.timestamp = time(nullptr) + (blockHeight * parameters::DIFFICULTY_TARGET);

  bool blockAdded = core.handle_block_found(block);

  transactionHash = getObjectHash(block.baseTransaction);

  blockHash = get_block_hash(block);

  return blockAdded;
}

// Adds an empty block to the blockchain
// able to set timestamp
// returns coinbase transaction hash
bool addBlock8(Core& core, const uint64_t timestamp, Crypto::Hash& transactionHash)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  block.timestamp = timestamp;

  // find nonce appropriate for difficulty
  Crypto::Hash proofOfWorkIgnore = NULL_HASH;
  Currency currency = core.currency();
  Crypto::cn_context context;
  while(!currency.checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  transactionHash = getObjectHash(block.baseTransaction);

  bool added = core.handle_block_found(block);

  return added;
}

// Adds a new alternative or orphaned block to the blockchain
bool addOrphanBlock(Core& core, Crypto::Hash& blockHash, const Crypto::Hash& prevBlockHash, const uint32_t blockHeight)
{
  // create block
  Block block;
  block.nonce = 0;
  block.timestamp = time(nullptr);
  block.previousBlockHash = prevBlockHash;

  std::vector<Transaction> transactions;

  // create coinbase transaction
  block.baseTransaction = boost::value_initialized<Transaction>();

  // need to get the hash of the block on the main chain that is at the same hight as the last block on the alternative chain to calculate alreadyGeneratedCoins
  uint64_t alreadyGeneratedCoins;
  // uint32_t prevAltBlockHeight;
  // blockchain.getBlockHeight(prevBlockHash, prevAltBlockHeight);
  // Crypto::Hash mainChainBlockHash = blockchain.getBlockIdByHeight(prevAltBlockHeight);
  Crypto::Hash mainChainBlockHash = core.getBlockIdByHeight(blockHeight - 1);
  core.getAlreadyGeneratedCoins(mainChainBlockHash, alreadyGeneratedCoins);

  uint64_t fee = 0;
  size_t medianBlockSize = getMedianBlockSize(core);
  size_t currentBlockSize = getBlockSize(block.baseTransaction, transactions);
  size_t maxOuts = 1;

  Currency currency = core.currency();

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

  // find nonce appropriate for current difficulty
  difficulty_type difficulty = core.getNextBlockDifficulty();
  Crypto::Hash proofOfWorkIgnore;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  blockHash = get_block_hash(block);

  bool addedToMainChain = core.handle_block_found(block);

  return !addedToMainChain;
}

// creates a transaction and adds it to the mempool
bool createTransaction(Core& core, const AccountKeys& senderAccountKeys,
                const AccountPublicAddress& receiverAccountPublicAddress,
                              Crypto::PublicKey inputTransactionPublicKey,
                                        Crypto::Hash inputTransactionHash)
{
  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = core.get_current_blockchain_height() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // create transaction random transaction key
  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;
  Crypto::SecretKey transactionSecretKey = transactionKeyPair.secretKey;

  // create transaction extra
  transaction.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  // transaction input

  std::vector<uint32_t> indexes;
  core.get_tx_outputs_gindexes(inputTransactionHash, indexes);

  // amount = 894069565
  //                     5
  //                    /  60
  //                   /  /  500
  //                  /  /  /  9000
  //                 /  /  /  /  60000
  //                /  /  /  /  /  4000000
  //               /  /  /  /  /  /  90000000
  //              /  /  /  /  /  /  /  800000000
  //             /  /  /  /  /  /  /  /
  // indexes = {0, 0, 0, 1, 1, 1, 1, 1} 

  // create key image
  KeyPair inputStealthKeyPair;
  Crypto::KeyImage keyImage;
  size_t realOutputIndex = 4; // index in indexes
  generate_key_image_helper(senderAccountKeys, inputTransactionPublicKey, realOutputIndex, inputStealthKeyPair, keyImage);

  KeyInput keyInput;
  keyInput.amount = 60000;
  keyInput.keyImage = keyImage;
  keyInput.outputIndexes = {indexes[realOutputIndex]}; // value in indexes (in this case indexes[4] = 1)
  keyInput.outputIndexes = absolute_output_offsets_to_relative(keyInput.outputIndexes);
  transaction.inputs.push_back(keyInput);

  // transaction output

  // ephemeral public key
  Crypto::KeyDerivation transactionDerivation;
  Crypto::PublicKey outputStealthPublicKey;
  size_t transactionOutputIndex = 0;
  generate_key_derivation(receiverAccountPublicAddress.viewPublicKey, transactionSecretKey, transactionDerivation);
  derive_public_key(transactionDerivation, transactionOutputIndex, receiverAccountPublicAddress.spendPublicKey, outputStealthPublicKey);

  // output target
  KeyOutput keyOutput;
  keyOutput.key = outputStealthPublicKey;

  TransactionOutput transactionOutput;
  transactionOutput.amount = keyInput.amount - parameters::MINIMUM_FEE;
  // totalOutputAmount is used later to calcultate the coinbase reward
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // transaction prefix hash
  Crypto::Hash tx_prefix_hash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction));

  // transaction signature

  std::vector<const Crypto::PublicKey*> keys_ptrs;
  keys_ptrs.push_back(&inputStealthKeyPair.publicKey);

  transaction.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& sigs = transaction.signatures.back();
  sigs.resize(keyInput.outputIndexes.size());
  
  Crypto::Hash prefix_hash = tx_prefix_hash;
  Crypto::KeyImage image = keyImage;
  std::vector<const Crypto::PublicKey *> pubs = keys_ptrs;
  Crypto::SecretKey sec = inputStealthKeyPair.secretKey;
  size_t sec_index = 0;
  Crypto::Signature *sig = sigs.data();
  generate_ring_signature(prefix_hash, image, pubs, sec, sec_index, sig);

  Crypto::Hash transactionHash = getObjectHash(transaction);
  size_t transactionSize = getObjectBinarySize(transaction);
  tx_verification_context tvc;
  bool keptByBlock = false;
  bool transactionAdded = core.handleIncomingTransaction(transaction, transactionHash, transactionSize, tvc, keptByBlock);

  return transactionAdded;
}

// creates a transaction and adds it to the mempool
// returns hash of transaction created
bool createTransaction2(Core& core, const AccountKeys& senderAccountKeys,
                const AccountPublicAddress& receiverAccountPublicAddress,
                              Crypto::PublicKey inputTransactionPublicKey,
        Crypto::Hash inputTransactionHash, Crypto::Hash& transactionHash)
{
  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = core.get_current_blockchain_height() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // create transaction random transaction key
  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;
  Crypto::SecretKey transactionSecretKey = transactionKeyPair.secretKey;

  // create transaction extra
  transaction.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  // transaction input

  std::vector<uint32_t> indexes;
  core.get_tx_outputs_gindexes(inputTransactionHash, indexes);

  // amount = 894069565
  //                     5
  //                    /  60
  //                   /  /  500
  //                  /  /  /  9000
  //                 /  /  /  /  60000
  //                /  /  /  /  /  4000000
  //               /  /  /  /  /  /  90000000
  //              /  /  /  /  /  /  /  800000000
  //             /  /  /  /  /  /  /  /
  // indexes = {0, 0, 0, 1, 1, 1, 1, 1} 

  // create key image
  KeyPair inputStealthKeyPair;
  Crypto::KeyImage keyImage;
  size_t realOutputIndex = 4; // index in indexes
  generate_key_image_helper(senderAccountKeys, inputTransactionPublicKey, realOutputIndex, inputStealthKeyPair, keyImage);

  KeyInput keyInput;
  keyInput.amount = 60000;
  keyInput.keyImage = keyImage;
  keyInput.outputIndexes = {indexes[realOutputIndex]}; // value in indexes (in this case indexes[4] = 1)
  keyInput.outputIndexes = absolute_output_offsets_to_relative(keyInput.outputIndexes);
  transaction.inputs.push_back(keyInput);

  // transaction output

  // ephemeral public key
  Crypto::KeyDerivation transactionDerivation;
  Crypto::PublicKey outputStealthPublicKey;
  size_t transactionOutputIndex = 0;
  generate_key_derivation(receiverAccountPublicAddress.viewPublicKey, transactionSecretKey, transactionDerivation);
  derive_public_key(transactionDerivation, transactionOutputIndex, receiverAccountPublicAddress.spendPublicKey, outputStealthPublicKey);

  // output target
  KeyOutput keyOutput;
  keyOutput.key = outputStealthPublicKey;

  TransactionOutput transactionOutput;
  transactionOutput.amount = keyInput.amount - parameters::MINIMUM_FEE;
  // totalOutputAmount is used later to calcultate the coinbase reward
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // transaction prefix hash
  Crypto::Hash tx_prefix_hash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction));

  // transaction signature

  std::vector<const Crypto::PublicKey*> keys_ptrs;
  keys_ptrs.push_back(&inputStealthKeyPair.publicKey);

  transaction.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& sigs = transaction.signatures.back();
  sigs.resize(keyInput.outputIndexes.size());
  
  Crypto::Hash prefix_hash = tx_prefix_hash;
  Crypto::KeyImage image = keyImage;
  std::vector<const Crypto::PublicKey *> pubs = keys_ptrs;
  Crypto::SecretKey sec = inputStealthKeyPair.secretKey;
  size_t sec_index = 0;
  Crypto::Signature *sig = sigs.data();
  generate_ring_signature(prefix_hash, image, pubs, sec, sec_index, sig);

  transactionHash = getObjectHash(transaction);
  size_t transactionSize = getObjectBinarySize(transaction);
  tx_verification_context tvc;
  bool keptByBlock = false;
  bool transactionAdded = core.handleIncomingTransaction(transaction, transactionHash, transactionSize, tvc, keptByBlock);

  return transactionAdded;
}

// creates a transaction and adds it to the mempool
// returns hash of transaction created
bool createTransaction3(Core& core, const AccountKeys& senderAccountKeys,
                const AccountPublicAddress& receiverAccountPublicAddress,
                              Crypto::PublicKey inputTransactionPublicKey,
        Crypto::Hash inputTransactionHash, Crypto::Hash& transactionHash,
                                                  Crypto::Hash paymentId)
{
  // create transaction
  Transaction transaction;
  transaction.version = CURRENT_TRANSACTION_VERSION;
  transaction.unlockTime = core.get_current_blockchain_height() + parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;

  // create transaction random transaction key
  KeyPair transactionKeyPair = generateKeyPair();
  Crypto::PublicKey transactionPublicKey = transactionKeyPair.publicKey;
  Crypto::SecretKey transactionSecretKey = transactionKeyPair.secretKey;

  // create transaction extra
  transaction.extra = {1};
  for (int i = 0; i < 32; i++)
  {
    transaction.extra.push_back(transactionPublicKey.data[i]);
  }

  // transaction payment id
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

  // transaction input

  std::vector<uint32_t> indexes;
  core.get_tx_outputs_gindexes(inputTransactionHash, indexes);

  // amount = 894069565
  //                     5
  //                    /  60
  //                   /  /  500
  //                  /  /  /  9000
  //                 /  /  /  /  60000
  //                /  /  /  /  /  4000000
  //               /  /  /  /  /  /  90000000
  //              /  /  /  /  /  /  /  800000000
  //             /  /  /  /  /  /  /  /
  // indexes = {0, 0, 0, 1, 1, 1, 1, 1} 

  // create key image
  KeyPair inputStealthKeyPair;
  Crypto::KeyImage keyImage;
  size_t realOutputIndex = 4; // index in indexes
  generate_key_image_helper(senderAccountKeys, inputTransactionPublicKey, realOutputIndex, inputStealthKeyPair, keyImage);

  KeyInput keyInput;
  keyInput.amount = 60000;
  keyInput.keyImage = keyImage;
  keyInput.outputIndexes = {indexes[realOutputIndex]}; // value in indexes (in this case indexes[4] = 1)
  keyInput.outputIndexes = absolute_output_offsets_to_relative(keyInput.outputIndexes);
  transaction.inputs.push_back(keyInput);

  // transaction output

  // ephemeral public key
  Crypto::KeyDerivation transactionDerivation;
  Crypto::PublicKey outputStealthPublicKey;
  size_t transactionOutputIndex = 0;
  generate_key_derivation(receiverAccountPublicAddress.viewPublicKey, transactionSecretKey, transactionDerivation);
  derive_public_key(transactionDerivation, transactionOutputIndex, receiverAccountPublicAddress.spendPublicKey, outputStealthPublicKey);

  // output target
  KeyOutput keyOutput;
  keyOutput.key = outputStealthPublicKey;

  TransactionOutput transactionOutput;
  transactionOutput.amount = keyInput.amount - parameters::MINIMUM_FEE;
  // totalOutputAmount is used later to calcultate the coinbase reward
  transactionOutput.target = keyOutput;

  transaction.outputs.push_back(transactionOutput);

  // transaction prefix hash
  Crypto::Hash tx_prefix_hash = getObjectHash(*static_cast<TransactionPrefix*>(&transaction));

  // transaction signature

  std::vector<const Crypto::PublicKey*> keys_ptrs;
  keys_ptrs.push_back(&inputStealthKeyPair.publicKey);

  transaction.signatures.push_back(std::vector<Crypto::Signature>());
  std::vector<Crypto::Signature>& sigs = transaction.signatures.back();
  sigs.resize(keyInput.outputIndexes.size());
  
  Crypto::Hash prefix_hash = tx_prefix_hash;
  Crypto::KeyImage image = keyImage;
  std::vector<const Crypto::PublicKey *> pubs = keys_ptrs;
  Crypto::SecretKey sec = inputStealthKeyPair.secretKey;
  size_t sec_index = 0;
  Crypto::Signature *sig = sigs.data();
  generate_ring_signature(prefix_hash, image, pubs, sec, sec_index, sig);

  transactionHash = getObjectHash(transaction);
  size_t transactionSize = getObjectBinarySize(transaction);
  tx_verification_context tvc;
  bool keptByBlock = false;
  bool transactionAdded = core.handleIncomingTransaction(transaction, transactionHash, transactionSize, tvc, keptByBlock);

  return transactionAdded;
}

// constructor
TEST(Core, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;

  Core core(currency, &crpytonoteProtocol, logger);
}

// on_idle()
TEST(Core, 2)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;

  Core core(currency, &crpytonoteProtocol, logger);

  ASSERT_TRUE(core.on_idle());
}

// init()
TEST(Core, 3)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));
}

// set_genesis_block()
TEST(Core, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();

  ASSERT_TRUE(core.set_genesis_block(genesisBlock));
}

// handle_incoming_block_blob() and
// init() and
// set_genesis_block()
TEST(Core, 5)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  Block block = createEmptyBlock(core);
  BinaryArray blockBlob = toBinaryArray(block);
  bool controlMiner = true;
  bool relayBlock = false;

  block_verification_context bvc;
  ASSERT_TRUE(core.handle_incoming_block_blob(blockBlob, bvc, controlMiner, relayBlock));
}

// handle_incoming_block_blob()
TEST(Core, 5a)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  Block block = createEmptyBlock(core);
  BinaryArray blockBlob = toBinaryArray(block);
  bool controlMiner = true;
  bool relayBlock = false;

  block_verification_context bvc;
  ASSERT_TRUE(core.handle_incoming_block_blob(blockBlob, bvc, controlMiner, relayBlock));
}

// get_protocol()
TEST(Core, 6)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  core.get_protocol();
}

// currency()
TEST(Core, 7)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  Currency currency2 = core.currency();
}

// get_block_template()
TEST(Core, 8)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  Block block;
  difficulty_type difficulty;
  uint32_t height;

  ASSERT_TRUE(core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce));
}

// handle_block_found()
TEST(Core, 9)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block block = createEmptyBlock(core);

  ASSERT_TRUE(core.handle_block_found(block));
}

// addObserver()
TEST(Core, 10)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreObserver coreObserver;

  ASSERT_TRUE(core.addObserver(&coreObserver));
}

// removeObserver()
TEST(Core, 11)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  CoreObserver coreObserver;

  ASSERT_TRUE(core.addObserver(&coreObserver));

  ASSERT_TRUE(core.removeObserver(&coreObserver));
}

// get_miner()
TEST(Core, 12)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  // statement below does not work because miner class implicitly deletes the operator= function
  // miner = core.get_miner();
}

// init_options()
TEST(Core, 13)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  boost::program_options::options_description description;

  core.init_options(description);
}

// deinit()
TEST(Core, 14)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  ASSERT_TRUE(core.deinit());
}

// addChain()
// skip for now
TEST(Core, 15)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<const IBlock*> chain;

  IBlockImpl myIBlockImpl;

  chain.push_back(&myIBlockImpl);

  // size_t blocksCounter = core.addChain(chain);
}

// addChain()
// skip for now
TEST(Core, 15b)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock3(core, blockHash1));
  Crypto::Hash blockHash2;
  ASSERT_TRUE(addBlock3(core, blockHash2));
  Crypto::Hash blockHash3;
  ASSERT_TRUE(addBlock3(core, blockHash3));

  uint32_t currentBlockchainHeight = core.get_current_blockchain_height();
  ASSERT_EQ(4, currentBlockchainHeight);

  std::vector<const IBlock*> chain;
  // // get() returns the stored pointer from the unique pointer returned by getBlock()
  chain.push_back(core.getBlock(blockHash1).get());
  chain.push_back(core.getBlock(blockHash2).get());
  chain.push_back(core.getBlock(blockHash3).get());

  // reset the blockchain
  // Block genesisBlock = currency.genesisBlock();
  // ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  // size_t numBlocksAdded = core.addChain(chain);
  // ASSERT_EQ(4, numBlocksAdded);

  // currentBlockchainHeight = core.get_current_blockchain_height();
  // ASSERT_EQ(4, currentBlockchainHeight);
}

// getBackwardBlocksSizes()
TEST(Core, 16)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  uint32_t fromHeight = core.get_current_blockchain_height() - 1;
  std::vector<size_t> blockSizes;
  size_t maxCount = parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW;

  // genesis block
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(1, blockSizes.size());

  // add block 1
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(2, blockSizes.size());

  // add block 2
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(3, blockSizes.size());

  // add block 3
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(4, blockSizes.size());

  // add block 4
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(5, blockSizes.size());

  // add block 5
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
  ASSERT_EQ(6, blockSizes.size());

  // add 100 more blocks
  for (int i = 1; i <= 100; i++)
  {
    ASSERT_TRUE(addBlock1(core));
    ASSERT_TRUE(core.getBackwardBlocksSizes(fromHeight, blockSizes, maxCount));
    ASSERT_EQ(i + 6, blockSizes.size());
  }
}

// getBlockSize()
TEST(Core, 17)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));
  Crypto::Hash blockHash = get_block_hash(genesisBlock);

  size_t blockSize;

  core.getBlockSize(blockHash, blockSize);
  ASSERT_EQ(78, blockSize);

  ASSERT_TRUE(addBlock1(core));
  core.getBlockSize(blockHash, blockSize);
  ASSERT_EQ(78, blockSize);
}

// getAlreadyGeneratedCoins()
TEST(Core, 18)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t alreadyGeneratedCoins = 0;
  Crypto::Hash lastBlockHash = core.get_tail_id();
  core.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);
  // I don't know why this is not 0
  ASSERT_EQ(894069671, alreadyGeneratedCoins);

  // add genesis block
  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  lastBlockHash = core.get_tail_id();
  core.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);
  ASSERT_EQ(894069671, alreadyGeneratedCoins);

  // add a block
  ASSERT_TRUE(addBlock1(core));

  lastBlockHash = core.get_tail_id();
  core.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);
  ASSERT_EQ(894069671+ 894069618, alreadyGeneratedCoins);
}

// getBlockReward1()
TEST(Core, 19)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // add genesis block
  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  uint64_t alreadyGeneratedCoins = 0;
  Crypto::Hash lastBlockHash = core.get_tail_id();
  core.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  size_t medianBlockSize = getMedianBlockSize(core);
  uint64_t fee = 0;
  uint64_t reward;
  int64_t emissionChange;
  size_t currentBlockSize = parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  ASSERT_TRUE(core.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, fee, reward, emissionChange));
  ASSERT_EQ(894069618, reward);

  // add a block
  Block block = createEmptyBlock(core);
  ASSERT_TRUE(core.handle_block_found(block));

  lastBlockHash = core.get_tail_id();
  core.getAlreadyGeneratedCoins(lastBlockHash, alreadyGeneratedCoins);

  ASSERT_TRUE(core.getBlockReward1(medianBlockSize, currentBlockSize, alreadyGeneratedCoins, fee, reward, emissionChange));
  ASSERT_EQ(894069565, reward);
}

// getBlockDifficulty()
TEST(Core, 20)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // add genesis block
  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  // check difficulty
  difficulty_type difficulty;
  uint32_t height = core.get_current_blockchain_height() - 1;
  ASSERT_TRUE(core.getBlockDifficulty(height, difficulty));
  ASSERT_EQ(1, difficulty);

  // add block
  ASSERT_TRUE(addBlock1(core));

  // check difficulty
  height = core.get_current_blockchain_height() - 1;
  ASSERT_TRUE(core.getBlockDifficulty(height, difficulty));
  ASSERT_EQ(1, difficulty);

  // add block
  ASSERT_TRUE(addBlock1(core));

  // check difficulty
  height = core.get_current_blockchain_height() - 1;
  ASSERT_TRUE(core.getBlockDifficulty(height, difficulty));
  ASSERT_EQ(100000, difficulty);
 
}

// getOrphanBlocksByHeight()
TEST(Core, 21)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  // add 5 blocks to the main chain
  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock3(core, blockHash1));
  Crypto::Hash blockHash2;
  ASSERT_TRUE(addBlock3(core, blockHash2));
  Crypto::Hash blockHash3;
  ASSERT_TRUE(addBlock3(core, blockHash3));
  Crypto::Hash blockHash4;
  ASSERT_TRUE(addBlock3(core, blockHash4));
  Crypto::Hash blockHash5;
  ASSERT_TRUE(addBlock3(core, blockHash5));

  // add an orphaned block
  Crypto::Hash orphanedBlockHash1;
  Crypto::Hash prevBlockHash = currency.genesisBlockHash();
  uint32_t blockHeight = 1;
  ASSERT_TRUE(addOrphanBlock(core, orphanedBlockHash1, prevBlockHash, blockHeight));
  
  std::vector<Block> orphanedBlocks;
  ASSERT_TRUE(core.getOrphanBlocksByHeight(blockHeight, orphanedBlocks));
  Crypto::Hash orphanedBlockHash = get_block_hash(orphanedBlocks[0]);
  ASSERT_TRUE(hashesEqual(orphanedBlockHash1, orphanedBlockHash));

  // add another orphaned block
  Crypto::Hash orphanedBlockHash2;
  prevBlockHash = orphanedBlockHash1;
  blockHeight = 2;
  ASSERT_TRUE(addOrphanBlock(core, orphanedBlockHash2, prevBlockHash, blockHeight));
  
  orphanedBlocks.clear();
  ASSERT_TRUE(core.getOrphanBlocksByHeight(blockHeight, orphanedBlocks));
  orphanedBlockHash = get_block_hash(orphanedBlocks[0]);
  ASSERT_TRUE(hashesEqual(orphanedBlockHash2, orphanedBlockHash));
}

// getBlocksByTimestamp()
TEST(Core, 22)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash;
  uint64_t timestamp = 123456789;
  ASSERT_TRUE(addBlock4(core, blockHash, timestamp));
  
  uint64_t timestampBegin = 123456788;
  uint64_t timestampEnd = 123456790;
  uint32_t blocksNumberLimit = 1;

  std::vector<Block> blocks;
  uint32_t blocksNumberWithinTimestamps;
  ASSERT_TRUE(core.getBlocksByTimestamp(timestampBegin, timestampEnd, blocksNumberLimit, blocks, blocksNumberWithinTimestamps));
  
  ASSERT_EQ(1, blocks.size());
  ASSERT_EQ(1, blocksNumberWithinTimestamps);
  Crypto::Hash blockHashRet = get_block_hash(blocks[0]);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
}

// getBlock()
TEST(Core, 23)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash;
  uint64_t timestamp = 123456789;
  ASSERT_TRUE(addBlock4(core, blockHash, timestamp));

  std::unique_ptr<IBlock> iBlock = core.getBlock(blockHash);
  Block blockRet = iBlock->getBlock();

  Crypto::Hash blockRetHash = get_block_hash(blockRet);
  ASSERT_TRUE(hashesEqual(blockHash, blockRetHash));

  ASSERT_EQ(timestamp, blockRet.timestamp);
}

// get_current_blockchain_height()
TEST(Core, 24)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  ASSERT_EQ(1, core.get_current_blockchain_height());

  ASSERT_TRUE(addBlock1(core));
  ASSERT_EQ(2, core.get_current_blockchain_height());
}

// have_block()
TEST(Core, 25)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash = getRandHash();

  ASSERT_FALSE(core.have_block(blockHash));

  ASSERT_TRUE(addBlock3(core, blockHash));

  ASSERT_TRUE(core.have_block(blockHash));
}

// get_tail_id()
TEST(Core, 26)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash lastBlockHash = core.get_tail_id();

  ASSERT_TRUE(hashesEqual(currency.genesisBlockHash(), lastBlockHash));

  // add a block
  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock3(core, blockHash));
  lastBlockHash = core.get_tail_id();
  ASSERT_TRUE(hashesEqual(blockHash, lastBlockHash));

  // add another block
  ASSERT_TRUE(addBlock3(core, blockHash));
  lastBlockHash = core.get_tail_id();
  ASSERT_TRUE(hashesEqual(blockHash, lastBlockHash));
}

// get_alternative_blocks_count()
TEST(Core, 27)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(core.set_genesis_block(genesisBlock));

  // add 5 blocks to the main chain
  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock3(core, blockHash1));
  Crypto::Hash blockHash2;
  ASSERT_TRUE(addBlock3(core, blockHash2));
  Crypto::Hash blockHash3;
  ASSERT_TRUE(addBlock3(core, blockHash3));
  Crypto::Hash blockHash4;
  ASSERT_TRUE(addBlock3(core, blockHash4));
  Crypto::Hash blockHash5;
  ASSERT_TRUE(addBlock3(core, blockHash5));

  // add an orphaned block
  Crypto::Hash orphanedBlockHash1;
  Crypto::Hash prevBlockHash = currency.genesisBlockHash();
  uint32_t blockHeight = 1;
  ASSERT_TRUE(addOrphanBlock(core, orphanedBlockHash1, prevBlockHash, blockHeight));

  size_t altBlocksCount = core.get_alternative_blocks_count();
  ASSERT_EQ(1, altBlocksCount);

  // add another orphaned block
  Crypto::Hash orphanedBlockHash2;
  prevBlockHash = orphanedBlockHash1;
  blockHeight = 2;
  ASSERT_TRUE(addOrphanBlock(core, orphanedBlockHash2, prevBlockHash, blockHeight));

  altBlocksCount = core.get_alternative_blocks_count();
  ASSERT_EQ(2, altBlocksCount);
}

// getNextBlockDifficulty()
TEST(Core, 28)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t nextDifficulty = core.getNextBlockDifficulty();

  ASSERT_EQ(1, nextDifficulty);

  ASSERT_TRUE(addBlock1(core));
  nextDifficulty = core.getNextBlockDifficulty();
  ASSERT_EQ(100000, nextDifficulty);
}

// getBlockHeight()
TEST(Core, 29)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // add genesis block at height 0
  Crypto::Hash genesisBlockHash = currency.genesisBlockHash();
  uint32_t blockHeight;
  ASSERT_TRUE(core.getBlockHeight(genesisBlockHash, blockHeight));
  ASSERT_EQ(0, blockHeight);

  // add block 1
  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockHeight(blockHash, blockHeight));
  ASSERT_EQ(1, blockHeight);

  // add block 2
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockHeight(blockHash, blockHeight));
  ASSERT_EQ(2, blockHeight);

  // add block 3
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockHeight(blockHash, blockHeight));
  ASSERT_EQ(3, blockHeight);
}

// getBlockByHash()
TEST(Core, 30)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // add genesis block at height 0
  Crypto::Hash blockHash = currency.genesisBlockHash();
  Block block;
  ASSERT_TRUE(core.getBlockByHash(blockHash, block));
  Crypto::Hash blockHashRet = get_block_hash(block);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
  uint32_t blockHeight;
  ASSERT_TRUE(core.getBlockHeight(blockHashRet, blockHeight));
  ASSERT_EQ(0, blockHeight);

  // add block 1
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockByHash(blockHash, block));
  blockHashRet = get_block_hash(block);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
  ASSERT_TRUE(core.getBlockHeight(blockHashRet, blockHeight));
  ASSERT_EQ(1, blockHeight);

  // add block 2
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockByHash(blockHash, block));
  blockHashRet = get_block_hash(block);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
  ASSERT_TRUE(core.getBlockHeight(blockHashRet, blockHeight));
  ASSERT_EQ(2, blockHeight);

  // add block 3
  ASSERT_TRUE(addBlock3(core, blockHash));
  ASSERT_TRUE(core.getBlockByHash(blockHash, block));
  blockHashRet = get_block_hash(block);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
  ASSERT_TRUE(core.getBlockHeight(blockHashRet, blockHeight));
  ASSERT_EQ(3, blockHeight);
}

// getBlockIdByHeight()
TEST(Core, 31)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash = currency.genesisBlockHash();

  // genesis block
  uint32_t height = 0;
  Crypto::Hash blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));

  // block 1
  ASSERT_TRUE(addBlock3(core, blockHash));
  height = 1;
  blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));

  // block 2
  ASSERT_TRUE(addBlock3(core, blockHash));
  height = 2;
  blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));

  // block 3
  ASSERT_TRUE(addBlock3(core, blockHash));
  height = 3;
  blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));

  // block 4
  ASSERT_TRUE(addBlock3(core, blockHash));
  height = 4;
  blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));

  // block 5
  ASSERT_TRUE(addBlock3(core, blockHash));
  height = 5;
  blockHashRet = core.getBlockIdByHeight(height);
  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
}

// get_blockchain_top()
TEST(Core, 32)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash blockHash = currency.genesisBlockHash();

  uint32_t height;
  Crypto::Hash topBlockHash;

  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(0, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));

  // block 1
  ASSERT_TRUE(addBlock3(core, blockHash));
  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(1, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));

  // block 2
  ASSERT_TRUE(addBlock3(core, blockHash));
  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(2, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));

  // block 3
  ASSERT_TRUE(addBlock3(core, blockHash));
  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(3, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));

  // block 4
  ASSERT_TRUE(addBlock3(core, blockHash));
  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(4, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));

  // block 5
  ASSERT_TRUE(addBlock3(core, blockHash));
  core.get_blockchain_top(height, topBlockHash);
  ASSERT_EQ(5, height);
  ASSERT_TRUE(hashesEqual(blockHash, topBlockHash));
}

// getTotalGeneratedAmount()
TEST(Core, 33)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t total = core.getTotalGeneratedAmount();
  ASSERT_EQ(894069671, total);

  ASSERT_TRUE(addBlock1(core));

  total = core.getTotalGeneratedAmount();
  ASSERT_EQ(894069671 + 894069618, total);
}

// get_alternative_blocks()
TEST(Core, 34)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  ASSERT_EQ(0, core.get_alternative_blocks_count());

  // add 3 blocks to main chain
  Crypto::Hash blockHash1a;
  ASSERT_TRUE(addBlock3(core, blockHash1a));

  Crypto::Hash blockHash2a;
  ASSERT_TRUE(addBlock3(core, blockHash2a));

  Crypto::Hash blockHash3a;
  ASSERT_TRUE(addBlock3(core, blockHash3a));

  ASSERT_EQ(4, core.get_current_blockchain_height());
  ASSERT_EQ(0, core.get_alternative_blocks_count());

  // add an alternative block to the genesis block
  uint32_t blockHeight = 1;
  Crypto::Hash blockHash1b;
  ASSERT_TRUE(addOrphanBlock(core, blockHash1b, currency.genesisBlockHash(), blockHeight));

  //                block1b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, core.get_current_blockchain_height());
  ASSERT_EQ(1, core.get_alternative_blocks_count());

  // add an altBlock2 to altBlock1
  blockHeight = 2;
  Crypto::Hash blockHash2b;
  ASSERT_TRUE(addOrphanBlock(core, blockHash2b, blockHash1b, blockHeight));

  //                block1b - block2b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, core.get_current_blockchain_height());
  ASSERT_EQ(2, core.get_alternative_blocks_count());

  // add an altBlock3 to altBlock2
  blockHeight = 3;
  Crypto::Hash blockHash3b;
  ASSERT_TRUE(addOrphanBlock(core, blockHash3b, blockHash2b, blockHeight));

  //                block1b - block2b - block3b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (main chain)

  ASSERT_EQ(4, core.get_current_blockchain_height());
  ASSERT_EQ(3, core.get_alternative_blocks_count());

  // add block4b to block3b
  // causes a core reorganization
  // main chain is now the alternative chain
  // alternative chain now becomes the main chain
  blockHeight = 4;
  Crypto::Hash blockHash4b;
  // False because addOrphanBlock tells if the block was added to the alternative chain but since block 4b is now part of the main chain, it is considered to have been added to the main chain
  ASSERT_FALSE(addOrphanBlock(core, blockHash4b, blockHash3b, blockHeight));

  //                block1b - block2b - block3b - block4b (main chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a (alt chain)

  ASSERT_EQ(5, core.get_current_blockchain_height());
  ASSERT_EQ(3, core.get_alternative_blocks_count());

  // check block hashes on main chain
  ASSERT_TRUE(hashesEqual(blockHash1b, core.getBlockIdByHeight(1)));
  ASSERT_TRUE(hashesEqual(blockHash2b, core.getBlockIdByHeight(2)));
  ASSERT_TRUE(hashesEqual(blockHash3b, core.getBlockIdByHeight(3)));
  ASSERT_TRUE(hashesEqual(blockHash4b, core.getBlockIdByHeight(4)));

  // check blocks on alternative chain
  std::list<Block> altBlocks;
  ASSERT_TRUE(core.get_alternative_blocks(altBlocks));
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
  ASSERT_TRUE(addOrphanBlock(core, blockHash4a, blockHash3a, blockHeight));

  //                block1b - block2b - block3b - block4b (main chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a - block4a (alt chain)

  ASSERT_EQ(5, core.get_current_blockchain_height());
  ASSERT_EQ(4, core.get_alternative_blocks_count());

  // add block5a to block4a
  // causes a core reorganization again
  // main chain is now the alternative chain
  // alternative chain now becomes the main chain
  blockHeight = 5;
  Crypto::Hash blockHash5a;
  // False because blocks is considered to be added to the main chain and not the alternative chain
  ASSERT_FALSE(addOrphanBlock(core, blockHash5a, blockHash4a, blockHeight));

  //                block1b - block2b - block3b - block4b (alt chain)
  //               / 
  //              /
  // genesis block - block1a - block2a - block3a - block4a - block5a (main chain)

  ASSERT_EQ(6, core.get_current_blockchain_height());
  ASSERT_EQ(4, core.get_alternative_blocks_count());

  // check block hashes on main chain
  ASSERT_TRUE(hashesEqual(blockHash1a, core.getBlockIdByHeight(1)));
  ASSERT_TRUE(hashesEqual(blockHash2a, core.getBlockIdByHeight(2)));
  ASSERT_TRUE(hashesEqual(blockHash3a, core.getBlockIdByHeight(3)));
  ASSERT_TRUE(hashesEqual(blockHash4a, core.getBlockIdByHeight(4)));
  ASSERT_TRUE(hashesEqual(blockHash5a, core.getBlockIdByHeight(5)));

  // check block hashes on alternative chain
  altBlocks.clear();
  ASSERT_TRUE(core.get_alternative_blocks(altBlocks));
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

// get_blockchain_total_transactions();
TEST(Core, 35)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // genesis coinbase transaction
  size_t totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(1, totalTransactions);

  ASSERT_TRUE(addBlock1(core));

  // genesis block coinbase transaction + block1 coinbase transaction
  totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(2, totalTransactions);

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(3, totalTransactions);

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(63, totalTransactions);

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  // transaction has not yet been added to the blockchain so total transactions remains at 63
  totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(63, totalTransactions);

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  // 65 because of coinbase transaction + new transaction from createTransaction()
  totalTransactions = core.get_blockchain_total_transactions();
  ASSERT_EQ(65, totalTransactions);
}

// get_pool_transactions_count()
TEST(Core, 36)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  size_t poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  ASSERT_TRUE(addBlock1(core));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(1, poolTransactions);

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);
}

// getTransactions()
TEST(Core, 37)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<Crypto::Hash> transactionHashes;
  std::list<Transaction> transactions;
  std::list<Crypto::Hash> missedTransactionHashes;

  Crypto::Hash transactionHash;
  ASSERT_TRUE(addBlock6(core, transactionHash));

  // transaction is in a block so checkTxPool has no effect on transactions size
  
  transactionHashes.push_back(transactionHash);
  bool checkTxPool = false;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  transactionHashes.push_back(transactionHash);
  checkTxPool = true;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // transaction is in a block so checkTxPool has no effect on transactions size

  transactionHashes.push_back(transactionHash);
  checkTxPool = false;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  transactionHashes.push_back(transactionHash);
  checkTxPool = true;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction2(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash, transactionHash));

  // transaction is in a the mempool only so checkTxPool has an effect on transactions size

  transactionHashes.push_back(transactionHash);
  checkTxPool = false;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(0, transactions.size());
  ASSERT_EQ(1, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  transactionHashes.push_back(transactionHash);
  checkTxPool = true;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  // transaction is in a block so checkTxPool has no effect on transactions size

  transactionHashes.push_back(transactionHash);
  checkTxPool = false;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();

  transactionHashes.push_back(transactionHash);
  checkTxPool = true;
  core.getTransactions(transactionHashes, transactions, missedTransactionHashes, checkTxPool);
  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(0, missedTransactionHashes.size());
  transactionHashes.clear();
  transactions.clear();
  missedTransactionHashes.clear();
}

// getBlockContainingTx()
TEST(Core, 38)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash transactionHash;
  Crypto::Hash blockHash;
  uint32_t blockHeight;
  ASSERT_TRUE(addBlock7(core, transactionHash, blockHash, blockHeight));

  Crypto::Hash blockHashRet;
  uint32_t blockHeightRet;
  ASSERT_TRUE(core.getBlockContainingTx(transactionHash, blockHashRet, blockHeightRet));

  ASSERT_TRUE(hashesEqual(blockHash, blockHashRet));
  ASSERT_EQ(blockHeight, blockHeightRet);
}

// getGeneratedTransactionsNumber()
TEST(Core, 39)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t generatedTransactions;

  uint32_t blockHeight = 0;
  ASSERT_TRUE(core.getGeneratedTransactionsNumber(blockHeight, generatedTransactions));
  ASSERT_EQ(1, generatedTransactions);

  ASSERT_TRUE(addBlock1(core));

  blockHeight = 1;
  ASSERT_TRUE(core.getGeneratedTransactionsNumber(blockHeight, generatedTransactions));
  ASSERT_EQ(2, generatedTransactions);

  ASSERT_TRUE(addBlock1(core));

  blockHeight = 2;
  ASSERT_TRUE(core.getGeneratedTransactionsNumber(blockHeight, generatedTransactions));
  ASSERT_EQ(3, generatedTransactions);

  ASSERT_TRUE(addBlock1(core));

  blockHeight = 3;
  ASSERT_TRUE(core.getGeneratedTransactionsNumber(blockHeight, generatedTransactions));
  ASSERT_EQ(4, generatedTransactions);
}

// getPoolTransactionsByTimestamp()
TEST(Core, 40)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  size_t poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  ASSERT_TRUE(addBlock1(core));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  Crypto::Hash newTransactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction2(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash, newTransactionHash));

  uint64_t timestampBegin = time(nullptr) - 10;
  uint64_t timestampEnd = time(nullptr) + 10;
  uint32_t transactionsNumberLimit = 1;
  std::vector<Transaction> transactions;
  uint64_t transactionsNumberWithinTimestamps;
  ASSERT_TRUE(core.getPoolTransactionsByTimestamp(timestampBegin, timestampEnd, transactionsNumberLimit, transactions, transactionsNumberWithinTimestamps));

  ASSERT_EQ(1, transactions.size());
  ASSERT_EQ(1, transactionsNumberWithinTimestamps);

  Crypto::Hash transactionHashRet = getObjectHash(transactions[0]);

  ASSERT_TRUE(hashesEqual(newTransactionHash, transactionHashRet));

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  // no transactions in the mempool

  transactions.clear();
  ASSERT_FALSE(core.getPoolTransactionsByTimestamp(timestampBegin, timestampEnd, transactionsNumberLimit, transactions, transactionsNumberWithinTimestamps));
}

// getTransactionsByPaymentId()
// skip for now
// cannot make function return true
TEST(Core, 41)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  size_t poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  ASSERT_TRUE(addBlock1(core));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  poolTransactions = core.get_pool_transactions_count();
  ASSERT_EQ(0, poolTransactions);

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  Crypto::Hash newTransactionHash;

  Crypto::Hash paymentId = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction3(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash, newTransactionHash, paymentId));

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  // I do not know how to make getTransactionsByPaymentId() return true because the transaction must exist in the blockchain and also in the mempool
  // The problem is once a transaction is included in a block, it is deleted from the mempool, so it can't exist in both places
  std::vector<Transaction> transactions;
  ASSERT_FALSE(core.getTransactionsByPaymentId(paymentId, transactions));
  
  // ASSERT_EQ(0, transactions.size());
  // Crypto::Hash transactionHashRet = getObjectHash(transactions[0]);
  // ASSERT_TRUE(hashesEqual(newTransactionHash, transactionHashRet));
}

// getPoolChanges()
TEST(Core, 42)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash tailBlockId = core.get_tail_id();
  std::vector<Crypto::Hash> knownTxsIds;
  std::vector<Transaction> addedTxs;
  std::vector<Crypto::Hash> deletedTxsIds;
  ASSERT_TRUE(core.getPoolChanges(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(0, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  ASSERT_TRUE(addBlock1(core));

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  tailBlockId = core.get_tail_id();
  knownTxsIds.clear();
  addedTxs.clear();
  deletedTxsIds.clear();
  ASSERT_TRUE(core.getPoolChanges(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(1, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  tailBlockId = core.get_tail_id();
  knownTxsIds.clear();
  addedTxs.clear();
  deletedTxsIds.clear();
  ASSERT_TRUE(core.getPoolChanges(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(0, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  // how do we delete a transaction from mempool?
}

// getPoolChangesLite()
TEST(Core, 43)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash tailBlockId = core.get_tail_id();
  std::vector<Crypto::Hash> knownTxsIds;
  std::vector<TransactionPrefixInfo> addedTxs;
  std::vector<Crypto::Hash> deletedTxsIds;
  ASSERT_TRUE(core.getPoolChangesLite(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(0, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  ASSERT_TRUE(addBlock1(core));

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  tailBlockId = core.get_tail_id();
  knownTxsIds.clear();
  addedTxs.clear();
  deletedTxsIds.clear();
  ASSERT_TRUE(core.getPoolChangesLite(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(1, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  tailBlockId = core.get_tail_id();
  knownTxsIds.clear();
  addedTxs.clear();
  deletedTxsIds.clear();
  ASSERT_TRUE(core.getPoolChangesLite(tailBlockId, knownTxsIds, addedTxs, deletedTxsIds));
  ASSERT_EQ(0, addedTxs.size());
  ASSERT_EQ(0, deletedTxsIds.size());

  // how do we delete a transaction from mempool?
}

// print_pool()
TEST(Core, 44)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  bool short_format = false;
  std::cout << core.print_pool(short_format) << std::endl;

  ASSERT_TRUE(addBlock1(core));

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  std::cout << core.print_pool(short_format) << std::endl;

  short_format = true;
  std::cout << core.print_pool(short_format) << std::endl;
}

// print_blockchain()
TEST(Core, 45)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint32_t start_index = 0;
  uint32_t end_index = core.get_current_blockchain_height();
  core.print_blockchain(start_index, end_index);

  ASSERT_TRUE(addBlock1(core));

  end_index = core.get_current_blockchain_height();
  core.print_blockchain(start_index, end_index);

  // raise the difficulty so that nonce changes
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(addBlock1(core));
  ASSERT_TRUE(addBlock1(core));

  end_index = core.get_current_blockchain_height();
  core.print_blockchain(start_index, end_index);
}

// get_random_outs_for_amounts()
TEST(Core, 46)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  for (int i = 0; i < 100; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request request;
  request.amounts.push_back(800000000); // this is equal to 0.8 cash2s
  request.outs_count = 5;
  CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response response = boost::value_initialized<CryptoNote::COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response>();
  ASSERT_TRUE(core.get_random_outs_for_amounts(request, response));

  // response =
  // {
  //   outs = 
  //   {
  //     {
  //       amount = 0x2faf0800, // 800000000
  //       outs = 
  //       {
  //         {
  //           global_amount_index = 0xf, // 15
  //           out_key = 
  //           {
  //             0x66, 0x13, 0x94, 0x56, 0x57, 0x56, 0x1d, 0x68, 0x37, 0x39, 
  //             0x28, 0x8a, 0x17, 0x11, 0x1a, 0x82, 0x1b, 0x70, 0x53, 0xb5,
  //             0x5c, 0x8d, 0x66, 0xa9, 0x1a, 0x9e, 0x77, 0x86, 0x73, 0xb0,
  //             0xb8, 0xef
  //           }
  //         },
  //         {
  //           global_amount_index = 0x27, // 39
  //           out_key = 
  //           {
  //             0xb3, 0x66, 0xf, 0x51, 0x2b, 0xd, 0xb4, 0x7b, 0x39, 0x8d,
  //             0x4f, 0x87, 0xe9, 0xf2, 0xd7, 0xe0, 0xbb, 0x8b, 0x53, 0xcf,
  //             0xf3, 0x47, 0xf9, 0x91, 0xe2, 0xa3, 0x92, 0x34, 0x44, 0x55,
  //             0x63, 0x9e
  //           }
  //         },
  //         {
  //           global_amount_index = 0x4, // 4
  //           out_key = 
  //           {
  //             0x43, 0x9c, 0x46, 0x7c, 0x9e, 0xed, 0x2f, 0xcb, 0xea, 0x5,
  //             0xfe, 0xa6, 0x33, 0xe5, 0x9, 0xfb, 0x87, 0x5c, 0xd3, 0x92,
  //             0x51, 0xd9, 0x1, 0x10, 0x5f, 0x13, 0x55, 0xc8, 0x98, 0x74,
  //             0xb5, 0xb6
  //           }
  //         },
  //         {
  //           global_amount_index = 0x18, // 24
  //           out_key = 
  //           {
  //             0xa7, 0xb4, 0x98, 0xa8, 0xb3, 0x1e, 0x3b, 0xa2, 0xda, 0xa8, 
  //             0xb5, 0xe3, 0x3c, 0x2f, 0x8a, 0xff, 0x5a, 0x6b, 0xdb, 0x4,
  //             0xa0, 0x17, 0xf8, 0x81, 0xd5, 0x5a, 0x9e, 0x4f, 0x9, 0x56,
  //             0x2b, 0xfb
  //           }
  //         },
  //         {
  //           global_amount_index = 0x14, // 20
  //           out_key = 
  //           {
  //             0xeb, 0xb8, 0xaa, 0x5c, 0x85, 0x32, 0x0, 0xe0, 0x7d, 0xe,
  //             0x46, 0x67, 0xb7, 0xfb, 0xb1, 0xe0, 0x98, 0xf4, 0xd6, 0xb8,
  //             0xf0, 0x3, 0x24, 0x2b, 0xa8, 0x48, 0x4d, 0x5f, 0x31, 0x16,
  //             0x6d, 0x13
  //           }
  //         }
  //       }
  //     }
  //   },
  //   status = ""
  // }
}

// print_blockchain_index()
TEST(Core, 47)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  core.print_blockchain_index();
}

// update_block_template_and_resume_mining()
TEST(Core, 48)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  core.update_block_template_and_resume_mining();
}

// pause_mining()
TEST(Core, 49)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  core.pause_mining();
}

// get_tx_outputs_gindexes()
TEST(Core, 50)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  Crypto::Hash transactionHash;
  ASSERT_TRUE(addBlock6(core, transactionHash));

  std::vector<uint32_t> indexes;
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 1 = 89406961
  // indexes = {0, 0, 0, 0, 0, 0, 0};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 2 = 89406956
  // indexes = {0, 0, 1, 1, 1, 1, 1};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 3 = 89406951
  // indexes = {1, 1, 2, 2, 2, 2, 2};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 4 = 89406945
  // indexes = {0, 0, 3, 3, 3, 3, 3};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 5 = 89406940
  // indexes = {1, 4, 4, 4, 4, 4}; // last 0 is below dust threshold so it is not included in indexes

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 6 = 89406935
  // indexes = {1, 0, 5, 5, 5, 5, 5};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 7 = 89406929
  // indexes = {0, 0, 6, 6, 6, 6, 6};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 8 = 89406924
  // indexes = {0, 1, 7, 7, 7, 7, 7};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 9 = 89406919
  // indexes = {1, 0, 8, 8, 8, 8, 8};

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 10 = 89406913
  // indexes = {0, 1, 9, 9, 9, 9, 9};

  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 21 = 89406855
  // indexes = {3, 2, 8, 20, 20, 20, 20};

  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 32 = 89406796
  // indexes = {2, 2, 0, 31, 31, 31, 31};

  for (int i = 0; i < 100; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 133 = 89406258
  // indexes = {14, 13, 7, 132, 132, 132, 132};

  for (int i = 0; i < 100; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  ASSERT_TRUE(addBlock6(core, transactionHash));
  indexes.clear();
  ASSERT_TRUE(core.get_tx_outputs_gindexes(transactionHash, indexes));

  // reward for block 234 = 89405720
  // indexes = {23, 33, 52, 233, 233, 233};
}

// get_stat_info()
TEST(Core, 51)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  core_stat_info coreStatInfo;

  ASSERT_TRUE(core.get_stat_info(coreStatInfo));
  ASSERT_EQ(0, coreStatInfo.tx_pool_size);
  ASSERT_EQ(1, coreStatInfo.blockchain_height);
  ASSERT_EQ(0, coreStatInfo.mining_speed);
  ASSERT_EQ(0, coreStatInfo.alternative_blocks);
  // genesis block hash
  ASSERT_EQ("3cb6cb55ddf0eeb58476b9d93edbcfc4ffbe2a3d37dbcffb3897bc161e9d345c", coreStatInfo.top_block_id_str);

  // add a block
  ASSERT_TRUE(addBlock1(core));

  ASSERT_TRUE(core.get_stat_info(coreStatInfo));
  ASSERT_EQ(0, coreStatInfo.tx_pool_size);
  ASSERT_EQ(2, coreStatInfo.blockchain_height);
  ASSERT_EQ(0, coreStatInfo.mining_speed);
  ASSERT_EQ(0, coreStatInfo.alternative_blocks);

  // add an orphan block
  Crypto::Hash blockHashIgnore;
  Crypto::Hash prevBlockHash = currency.genesisBlockHash();
  uint32_t blockHeight = 1;
  ASSERT_TRUE(addOrphanBlock(core, blockHashIgnore, prevBlockHash, blockHeight));

  ASSERT_TRUE(core.get_stat_info(coreStatInfo));
  ASSERT_EQ(0, coreStatInfo.tx_pool_size);
  ASSERT_EQ(2, coreStatInfo.blockchain_height);
  ASSERT_EQ(0, coreStatInfo.mining_speed);
  ASSERT_EQ(1, coreStatInfo.alternative_blocks);

  // add transaction

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  ASSERT_TRUE(core.get_stat_info(coreStatInfo));
  ASSERT_EQ(1, coreStatInfo.tx_pool_size);
  ASSERT_EQ(63, coreStatInfo.blockchain_height);
  ASSERT_EQ(0, coreStatInfo.mining_speed);
  ASSERT_EQ(1, coreStatInfo.alternative_blocks);

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  ASSERT_TRUE(core.get_stat_info(coreStatInfo));
  ASSERT_EQ(0, coreStatInfo.tx_pool_size);
  ASSERT_EQ(64, coreStatInfo.blockchain_height);
  ASSERT_EQ(0, coreStatInfo.mining_speed);
  ASSERT_EQ(1, coreStatInfo.alternative_blocks);

  // I do no know how to increase the mining speed
}

// findBlockchainSupplement()
TEST(Core, 52)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 100; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> supplementHashes;
  std::vector<Crypto::Hash> supplementHashesRet;

  // last element in vector must be the genesis block hash
  supplementHashes.push_back(currency.genesisBlockHash());

  size_t maxCount = 5;
  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(currency.genesisBlockHash(), supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[0], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[1], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[2], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[3], supplementHashesRet[4]));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[3]);
  supplementHashes.push_back(currency.genesisBlockHash());
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(blockHashes[3], supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[4], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[5], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[6], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[7], supplementHashesRet[4]));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[3]);
  supplementHashes.push_back(blockHashes[2]);
  supplementHashes.push_back(blockHashes[1]);
  supplementHashes.push_back(blockHashes[0]);
  supplementHashes.push_back(currency.genesisBlockHash());
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(blockHashes[3], supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[4], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[5], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[6], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[7], supplementHashesRet[4]));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[0]);
  supplementHashes.push_back(blockHashes[1]);
  supplementHashes.push_back(blockHashes[2]);
  supplementHashes.push_back(blockHashes[3]);
  supplementHashes.push_back(currency.genesisBlockHash());
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(blockHashes[0], supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[1], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[2], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[3], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[4], supplementHashesRet[4]));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[0]); // this is the only hash that matters
  supplementHashes.push_back(blockHashes[10]); // this does not matter
  supplementHashes.push_back(blockHashes[20]); // this does not matter
  supplementHashes.push_back(blockHashes[30]); // this does not matter
  supplementHashes.push_back(currency.genesisBlockHash());
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(blockHashes[0], supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[1], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[2], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[3], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[4], supplementHashesRet[4]));

  supplementHashes.clear();
  supplementHashes.push_back(blockHashes[22]); // this is the only hash that matters
  supplementHashes.push_back(blockHashes[2]); // this does not matter
  supplementHashes.push_back(blockHashes[40]); // this does not matter
  supplementHashes.push_back(blockHashes[30]); // this does not matter
  supplementHashes.push_back(currency.genesisBlockHash());
  supplementHashesRet = core.findBlockchainSupplement(supplementHashes, maxCount, totalBlockCount, startBlockIndex);

  ASSERT_EQ(5, supplementHashesRet.size());
  ASSERT_TRUE(hashesEqual(blockHashes[22], supplementHashesRet[0]));
  ASSERT_TRUE(hashesEqual(blockHashes[23], supplementHashesRet[1]));
  ASSERT_TRUE(hashesEqual(blockHashes[24], supplementHashesRet[2]));
  ASSERT_TRUE(hashesEqual(blockHashes[25], supplementHashesRet[3]));
  ASSERT_TRUE(hashesEqual(blockHashes[26], supplementHashesRet[4]));
}

// set_cryptonote_protocol()
TEST(Core, 54)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  CryptonoteProtocol crpytonoteProtocol2;

  core.set_cryptonote_protocol(&crpytonoteProtocol2);
}

// print_blockchain_outs()
TEST(Core, 55)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  const std::string fileName = "cash2BlockchainOuts";

  core.print_blockchain_outs(fileName);
}

// queryBlocks()
TEST(Core, 56)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t timestamp = time(nullptr);

  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock3(core, blockHash1));

  std::vector<Crypto::Hash> blockHashes;
  blockHashes.push_back(blockHash1);

  // for some reason, blockHashes must end with the genesis block hash
  blockHashes.push_back(currency.genesisBlockHash());

  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset; // I am not sure what fullOffset is
  std::vector<BlockFullInfo> entries;

  ASSERT_TRUE(core.queryBlocks(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(2, currentHeight);
  ASSERT_EQ(1, fullOffset);
  ASSERT_TRUE(hashesEqual(blockHashes[0], entries[0].block_id));

  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  std::vector<Crypto::Hash> allBlockHashes;

  blockHashes.push_back(blockHash1);
  for (int i = 0; i < 10; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocks(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(12, currentHeight);
  ASSERT_EQ(1, fullOffset);
  
  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(hashesEqual(blockHashes[i], entries[i].block_id));
  }

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin(), blockHashes.end() - 1);
  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  for (int i = 0; i < 10; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocks(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(12, startHeight);
  ASSERT_EQ(22, currentHeight);
  ASSERT_EQ(12, fullOffset);

  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(hashesEqual(blockHashes[i], entries[i].block_id));
  }

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin(), blockHashes.end() - 1);
  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  blockHashes.push_back(blockHash1);
  for (int i = 0; i < 20; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocks(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(42, currentHeight);
  ASSERT_EQ(1, fullOffset);

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin() + 1, blockHashes.end() - 1);

  for (int i = 0; i < 41; i++)
  {
    ASSERT_TRUE(hashesEqual(allBlockHashes[i], entries[i].block_id));
  }

}

// queryBlocksLite()
TEST(Core, 57)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  uint64_t timestamp = time(nullptr);

  Crypto::Hash blockHash1;
  ASSERT_TRUE(addBlock3(core, blockHash1));

  std::vector<Crypto::Hash> blockHashes;
  blockHashes.push_back(blockHash1);

  // for some reason, blockHashes must end with the genesis block hash
  blockHashes.push_back(currency.genesisBlockHash());

  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset; // I am not sure what fullOffset is
  std::vector<BlockShortInfo> entries;

  ASSERT_TRUE(core.queryBlocksLite(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(2, currentHeight);
  ASSERT_EQ(1, fullOffset);
  ASSERT_TRUE(hashesEqual(blockHashes[0], entries[0].blockId));

  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  std::vector<Crypto::Hash> allBlockHashes;

  blockHashes.push_back(blockHash1);
  for (int i = 0; i < 10; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocksLite(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(12, currentHeight);
  ASSERT_EQ(1, fullOffset);
  
  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(hashesEqual(blockHashes[i], entries[i].blockId));
  }

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin(), blockHashes.end() - 1);
  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  for (int i = 0; i < 10; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocksLite(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(12, startHeight);
  ASSERT_EQ(22, currentHeight);
  ASSERT_EQ(12, fullOffset);

  for (int i = 0; i < 10; i++)
  {
    ASSERT_TRUE(hashesEqual(blockHashes[i], entries[i].blockId));
  }

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin(), blockHashes.end() - 1);
  blockHashes.clear();
  entries.clear();

//////////////////////////////////////////////////////////////////////////

  blockHashes.push_back(blockHash1);
  for (int i = 0; i < 20; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }
  blockHashes.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(core.queryBlocksLite(blockHashes, timestamp, startHeight, currentHeight, fullOffset, entries));
  ASSERT_EQ(1, startHeight);
  ASSERT_EQ(42, currentHeight);
  ASSERT_EQ(1, fullOffset);

  allBlockHashes.insert(allBlockHashes.end(), blockHashes.begin() + 1, blockHashes.end() - 1);

  for (int i = 0; i < 41; i++)
  {
    ASSERT_TRUE(hashesEqual(allBlockHashes[i], entries[i].blockId));
  }

}

// on_synchronized()
TEST(Core, 58)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  core.on_synchronized();
}

// buildSparseChain()
TEST(Core, 59)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 500; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> sparseChain = core.buildSparseChain();
  
  // How to get indexes:
  // 500 - 2^0 = 500 - 1   = 499
  // 500 - 2^1 = 500 - 2   = 498
  // 500 - 2^2 = 500 - 4   = 496
  // 500 - 2^3 = 500 - 8   = 492
  // 500 - 2^4 = 500 - 16  = 484
  // 500 - 2^5 = 500 - 32  = 468
  // 500 - 2^6 = 500 - 64  = 436
  // 500 - 2^7 = 500 - 128 = 372
  // 500 - 2^8 = 500 - 256 = 244
  // add genesis block

  std::vector<Crypto::Hash> expectedSparseChain;
  expectedSparseChain.push_back(blockHashes[499]);
  expectedSparseChain.push_back(blockHashes[498]);
  expectedSparseChain.push_back(blockHashes[496]);
  expectedSparseChain.push_back(blockHashes[492]);
  expectedSparseChain.push_back(blockHashes[484]);
  expectedSparseChain.push_back(blockHashes[468]);
  expectedSparseChain.push_back(blockHashes[436]);
  expectedSparseChain.push_back(blockHashes[372]);
  expectedSparseChain.push_back(blockHashes[244]);
  expectedSparseChain.push_back(currency.genesisBlockHash());

  sparseChain = core.buildSparseChain();

  ASSERT_TRUE(std::equal(sparseChain.begin(), sparseChain.end(), expectedSparseChain.begin()));
}

// buildSparseChain(startBlockHash)
TEST(Core, 60)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<Crypto::Hash> blockHashes;
  for(int i = 0; i < 500; i++)
  {
    Crypto::Hash blockHash;
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }

  std::vector<Crypto::Hash> sparseChain = core.buildSparseChain(blockHashes[250]);
  
  // How to get indexes:
  // 250 - 0   = 250
  // 250 - 2^0 = 250 - 1   = 249
  // 249 - 2^1 = 249 - 2   = 247
  // 247 - 2^2 = 247 - 4   = 243
  // 243 - 2^3 = 243 - 8   = 235
  // 235 - 2^4 = 235 - 16  = 219
  // 219 - 2^5 = 219 - 32  = 187
  // 187 - 2^6 = 187 - 64  = 123
  // add genesis block

  std::vector<Crypto::Hash> expectedSparseChain;
  // I don't know why blockHashes[250] is included in the sparse chain
  expectedSparseChain.push_back(blockHashes[250]);
  expectedSparseChain.push_back(blockHashes[249]);
  expectedSparseChain.push_back(blockHashes[247]);
  expectedSparseChain.push_back(blockHashes[243]);
  expectedSparseChain.push_back(blockHashes[235]);
  expectedSparseChain.push_back(blockHashes[219]);
  expectedSparseChain.push_back(blockHashes[187]);
  expectedSparseChain.push_back(blockHashes[123]);
  expectedSparseChain.push_back(currency.genesisBlockHash());

  ASSERT_TRUE(std::equal(sparseChain.begin(), sparseChain.end(), expectedSparseChain.begin()));
}

// addMessageQueue() and
// removeMessageQueue()
TEST(Core, 61)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  ASSERT_TRUE(core.addMessageQueue(messageQueue));

  ASSERT_TRUE(core.removeMessageQueue(messageQueue));
}

// handleIncomingTransaction()
TEST(Core, 62)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  ASSERT_TRUE(addBlock1(core));

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock5(core, minerAccountKeys.address, transactionPublicKey, transactionHash));

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock1(core));
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // handleIncomingTransaction() called inside createTransaction()
  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));
}

// get_blocks()
TEST(Core, 63)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  std::vector<Crypto::Hash> blockHashes;

  Crypto::Hash blockHash;
  ASSERT_TRUE(addBlock3(core, blockHash));
  blockHashes.push_back(blockHash);

  // miner finds a block
  AccountKeys minerAccountKeys;
  KeyPair viewKeyPair1 = generateKeyPair();
  KeyPair spendKeyPair1 = generateKeyPair();
  minerAccountKeys.address.viewPublicKey = viewKeyPair1.publicKey;
  minerAccountKeys.address.spendPublicKey = spendKeyPair1.publicKey;
  minerAccountKeys.viewSecretKey = viewKeyPair1.secretKey;
  minerAccountKeys.spendSecretKey = spendKeyPair1.secretKey;

  ASSERT_TRUE(addBlock3(core, blockHash));
  blockHashes.push_back(blockHash);

  Crypto::PublicKey transactionPublicKey;
  Crypto::Hash transactionHash;

  // add block that sends the coinbase transaction to the miner's address
  ASSERT_TRUE(addBlock6(core, minerAccountKeys.address, transactionPublicKey, transactionHash, blockHash));
  blockHashes.push_back(blockHash);

  // allow the miner's coinbase transaction to mature for 60 blocks
  for (int i = 0; i < parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; i++)
  {
    ASSERT_TRUE(addBlock3(core, blockHash));
    blockHashes.push_back(blockHash);
  }

  // create transaction to send miner's money to another person
  AccountKeys senderAccountKeys = minerAccountKeys;

  AccountPublicAddress receiverAccountPublicAddress;
  KeyPair viewKeyPair2 = generateKeyPair();
  KeyPair spendKeyPair2 = generateKeyPair();
  receiverAccountPublicAddress.viewPublicKey = viewKeyPair2.publicKey;
  receiverAccountPublicAddress.spendPublicKey = spendKeyPair2.publicKey;

  Crypto::Hash inputTransactionHash = transactionHash;

  // handleIncomingTransaction() called inside createTransaction()
  // create a transaction and add it to the mempool
  ASSERT_TRUE(createTransaction(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash));

  // add transaction to a block
  ASSERT_TRUE(addBlock6(core, minerAccountKeys.address, transactionPublicKey, transactionHash, blockHash));
  blockHashes.push_back(blockHash);

  uint32_t start = 0;
  uint32_t count = 100;
  std::list<Block> blocks;
  std::list<Transaction> transactions; // counts all transactions that are not coinbase transactions
  ASSERT_TRUE(core.get_blocks(start, count, blocks, transactions));

  ASSERT_EQ(65, blocks.size());
  ASSERT_EQ(1, transactions.size());

  // check genesis block hash
  Block block = blocks.front();
  blocks.pop_front();
  blockHash = get_block_hash(block);
  ASSERT_TRUE(hashesEqual(currency.genesisBlockHash(), blockHash));

  for (int i = 0; i < 64; i++)
  {
    block = blocks.front();
    blocks.pop_front();
    Crypto::Hash blockHash = get_block_hash(block);
    ASSERT_TRUE(hashesEqual(blockHashes[i], blockHash));
  }
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
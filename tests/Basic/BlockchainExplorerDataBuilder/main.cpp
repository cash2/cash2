// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "BlockchainExplorer/BlockchainExplorerDataBuilder.h"
#include "CryptoNoteCore/Core.h"
#include "Logging/ConsoleLogger.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "Common/Math.h"
#include "CryptoNoteConfig.h"

using namespace CryptoNote;

/*

My Notes

class BlockchainExplorerDataBuilder

public
  BlockchainExplorerDataBuilder()
  fillBlockDetails()
  fillTransactionDetails()
  getPaymentId()

*/

// Helper Functions


// Adds a new block to the blockchain
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
// returns transaction public key of the coinbase transaction
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
// return block that was added
bool addBlock8(Core& core, Block& block)
{
  AccountPublicAddress accountPublicAddress;
  KeyPair viewKeyPair = generateKeyPair();
  KeyPair spendKeyPair = generateKeyPair();
  accountPublicAddress.viewPublicKey = viewKeyPair.publicKey;
  accountPublicAddress.spendPublicKey = spendKeyPair.publicKey;

  BinaryArray extraNonce;

  difficulty_type difficulty;
  uint32_t height;

  core.get_block_template(block, accountPublicAddress, difficulty, height, extraNonce);

  block.timestamp = time(nullptr);

  // add merkle root
  block.merkleRoot = get_tx_tree_hash(block);

  // find nonce appropriate for current difficulty
  Crypto::Hash proofOfWorkIgnore;
  Crypto::cn_context context;
  while(!core.currency().checkProofOfWork1(context, block, difficulty, proofOfWorkIgnore))
  {
    block.nonce++;
  }

  bool blockAdded = core.handle_block_found(block);

  return blockAdded;
}

// creates a transaction and adds it to the mempool
// returns transaction created
bool createTransaction4(Core& core, const AccountKeys& senderAccountKeys, const AccountPublicAddress& receiverAccountPublicAddress, Crypto::PublicKey inputTransactionPublicKey, Crypto::Hash inputTransactionHash, Transaction& transaction)
{
  // create transaction
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

class CryptoNoteProtocolQuery : public ICryptoNoteProtocolQuery {
public:
  virtual bool addObserver(ICryptoNoteProtocolObserver* observer) { return true; };
  virtual bool removeObserver(ICryptoNoteProtocolObserver* observer) { return true; };

  virtual uint32_t getObservedHeight() const { return 0; };
  virtual size_t getPeerCount() const { return 0; };
  virtual bool isSynchronized() const { return true; };
};

// constructor()
TEST(BlockchainExplorerDataBuilder, 1)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CryptoNoteProtocolQuery protocol;
  BlockchainExplorerDataBuilder(core, protocol);
}

// fillBlockDetails()
TEST(BlockchainExplorerDataBuilder, 2)
{
  // create core object
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);

  // initialize core object
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

  // create BlockchainExplorerDataBuilder object
  CryptoNoteProtocolQuery protocol;
  BlockchainExplorerDataBuilder blockchainExplorerDataBuilder(core, protocol);

  BlockDetails blockDetails;
  Block genesisBlock = currency.genesisBlock();
  ASSERT_TRUE(blockchainExplorerDataBuilder.fillBlockDetails(genesisBlock, blockDetails));

  // add new block to blockchain
  Block block;
  ASSERT_TRUE(addBlock8(core, block));

  ASSERT_TRUE(blockchainExplorerDataBuilder.fillBlockDetails(block, blockDetails));
}

// fillTransactionDetails()
TEST(BlockchainExplorerDataBuilder, 3)
{
  // create core object
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  
  Core core(currency, &crpytonoteProtocol, logger);

  // initialize core object
  CoreConfig coreConfig;
  MinerConfig minerConfig;
  bool loadExisting = false;
  ASSERT_TRUE(core.init(coreConfig, minerConfig, loadExisting));

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

  // create a transaction and add it to the mempool
  Crypto::Hash inputTransactionHash = transactionHash;
  Transaction transaction;
  ASSERT_TRUE(createTransaction4(core, senderAccountKeys, receiverAccountPublicAddress, transactionPublicKey, inputTransactionHash, transaction));

  // add transaction to a block
  ASSERT_TRUE(addBlock1(core));

  // create BlockchainExplorerDataBuilder object
  CryptoNoteProtocolQuery protocol;
  BlockchainExplorerDataBuilder blockchainExplorerDataBuilder(core, protocol);

  TransactionDetails transactionDetails;
  uint64_t timestamp = time(nullptr);
  ASSERT_TRUE(blockchainExplorerDataBuilder.fillTransactionDetails(transaction, transactionDetails, timestamp));
}

// getPaymentId()
TEST(BlockchainExplorerDataBuilder, 4)
{
  Logging::ConsoleLogger logger;
  Currency currency = CurrencyBuilder(logger).currency();
  CryptonoteProtocol crpytonoteProtocol;
  Core core(currency, &crpytonoteProtocol, logger);
  CryptoNoteProtocolQuery protocol;
  BlockchainExplorerDataBuilder blockchainExplorerDataBuilder(core, protocol);

  Transaction transaction = getRandTransaction();
  Crypto::Hash paymentId1;
  ASSERT_TRUE(blockchainExplorerDataBuilder.getPaymentId(transaction, paymentId1));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
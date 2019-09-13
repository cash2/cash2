// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include "P2p/NetNodeCommon.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"
#include "Currency.h"
#include "TransactionPool.h"
#include "Blockchain.h"
#include "CryptoNoteCore/IMinerHandler.h"
#include "CryptoNoteCore/MinerConfig.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/CoreConfig.h"
#include "ICore.h"
#include "ICoreObserver.h"
#include "Common/ObserverManager.h"
#include "System/Dispatcher.h"
#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include <Logging/LoggerMessage.h>

namespace CryptoNote {

class Core : public ICore, public IMinerHandler, public IBlockchainStorageObserver, public ITxPoolObserver {
public:
  Core(const Currency& currency, i_cryptonote_protocol* pprotocol, Logging::ILogger& logger);
  ~Core();

  // Public blockchain functions
  virtual size_t addChain(const std::vector<const IBlock*>& chain) override;
  virtual bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) override;
  std::vector<Crypto::Hash> buildSparseChain() override;
  std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId) override;
  virtual std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount, uint32_t& totalBlockCount, uint32_t& startBlockIndex) override;
  virtual bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins) override;
  virtual bool getBackwardBlocksSizes(uint32_t fromHeight, std::vector<size_t>& sizes, size_t count) override;
  virtual std::unique_ptr<IBlock> getBlock(const Crypto::Hash& blocksId) override;
  virtual bool getBlockByHash(const Crypto::Hash &h, Block &blk) override;
  virtual bool getBlockContainingTx(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight) override;
  virtual bool getBlockCumulativeDifficulty(uint32_t blockIndex, uint64_t& cumulativeDifficulty) override;
  virtual bool getBlockDifficulty(uint32_t height, difficulty_type& difficulty) override;
  virtual bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight) override;
  virtual Crypto::Hash getBlockIdByHeight(uint32_t height) override;
  virtual bool getBlockSize(const Crypto::Hash& hash, size_t& size) override;
  virtual bool getBlocksByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Block>& blocks, uint32_t& blocksNumberWithinTimestamps) override;
  virtual bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions) override;
  virtual uint64_t getMinimalFee() override;
  virtual uint64_t getMinimalFeeForHeight(uint32_t height) override;
  virtual bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& outputReference) override;
  virtual bool getOrphanBlocksByHeight(uint32_t height, std::vector<Block>& blocks) override;
  virtual bool getOutByMSigGIndex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out) override;
  void getTransactions(const std::vector<Crypto::Hash>& txs_ids, std::list<Transaction>& txs, std::list<Crypto::Hash>& missed_txs, bool checkTxPool = false) override;
  virtual bool getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) override;
  virtual void get_blockchain_top(uint32_t& height, Crypto::Hash& top_id) override;
  virtual uint32_t get_current_blockchain_height() override;
  virtual bool get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response& res) override;
  virtual bool get_tx_outputs_gindexes(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexes) override;
  virtual bool handle_block_found(Block& b) override;
  virtual bool handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp) override; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  bool handle_incoming_block_blob(const BinaryArray& block_blob, block_verification_context& bvc, bool control_miner, bool relay_block) override;
  bool have_block(const Crypto::Hash& id) override;
  virtual bool queryBlocks(const std::vector<Crypto::Hash>& block_ids, uint64_t timestamp, uint32_t& start_height, uint32_t& current_height, uint32_t& full_offset, std::vector<BlockFullInfo>& entries) override;
  virtual bool queryBlocksLite(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp, uint32_t& resStartHeight, uint32_t& resCurrentHeight, uint32_t& resFullOffset, std::vector<BlockShortInfo>& entries) override;
  virtual bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) override;
  virtual bool scanOutputkeysForIndexes(const KeyInput& txInToKey, std::list<std::pair<Crypto::Hash, size_t>>& outputReferences) override;
  uint64_t getNextBlockDifficulty();
  uint64_t getTotalGeneratedAmount();
  bool get_alternative_blocks(std::list<Block>& blocks);
  size_t get_alternative_blocks_count();
  size_t get_blockchain_total_transactions();
  bool get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks);
  bool get_blocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs);
  Crypto::Hash get_tail_id();
  void print_blockchain(uint32_t start_index, uint32_t end_index);
  void print_blockchain_index();
  void print_blockchain_outs(const std::string& file);
  void set_checkpoints(Checkpoints&& chk_pts);
  bool set_genesis_block(const Block& b);

  template<class t_ids_container, class t_blocks_container, class t_missed_container>
  bool get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs)
  {
    return m_blockchain.getBlocks(block_ids, blocks, missed_bs);
  }

  // Public mempool functions
  std::list<CryptoNote::tx_memory_pool::TransactionDetails> getMemoryPool() const;
  virtual bool getPoolChanges(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) override;
  virtual void getPoolChanges(const std::vector<Crypto::Hash>& knownTxsIds, std::vector<Transaction>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) override;
  virtual bool getPoolChangesLite(const Crypto::Hash& tailBlockId, const std::vector<Crypto::Hash>& knownTxsIds, std::vector<TransactionPrefixInfo>& addedTxs, std::vector<Crypto::Hash>& deletedTxsIds) override;
  std::vector<Transaction> getPoolTransactions() override;
  virtual bool getPoolTransactionsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t transactionsNumberLimit, std::vector<Transaction>& transactions, uint64_t& transactionsNumberWithinTimestamps) override;
  virtual bool get_block_template(Block& b, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& blockchainHeight, const BinaryArray& ex_nonce) override;
  size_t get_pool_transactions_count();
  virtual bool handleIncomingTransaction(const Transaction& tx, const Crypto::Hash& txHash, size_t blobSize, tx_verification_context& tvc, bool keptByBlock, uint32_t blockHeight) override;
  virtual bool handle_incoming_tx(const BinaryArray& tx_blob, tx_verification_context& tvc, bool kept_by_block) override; //Deprecated. Should be removed with CryptoNoteProtocolHandler.
  std::string print_pool(bool short_format);

  // Public observer functions
  bool addObserver(ICoreObserver* observer) override;
  bool removeObserver(ICoreObserver* observer) override;

  // Public mining functions
  void on_synchronized() override;
  void pause_mining() override;
  void update_block_template_and_resume_mining() override;

  // Other public functions
  const Currency& currency() const { return m_currency; }
  bool deinit();
  virtual std::error_code executeLocked(const std::function<std::error_code()>& func) override;
  virtual bool getBlockReward1(size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint64_t& reward, int64_t& emissionChange) override;
  virtual bool getBlockReward2(uint32_t blockHeight, size_t currentBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint64_t& reward, int64_t& emissionChange) override;
  miner& get_miner() { return *m_miner; }
  virtual i_cryptonote_protocol* get_protocol() override {return m_pprotocol;}
  bool get_stat_info(core_stat_info& st_inf) override;
  bool init(const CoreConfig& config, const MinerConfig& minerConfig, bool load_existing);
  static void init_options(boost::program_options::options_description& desc); // no definition
  bool on_idle() override;
  void set_cryptonote_protocol(i_cryptonote_protocol* pprotocol);

private:

  // Private blockchain functions
  std::vector<Crypto::Hash> findIdsForShortBlocks(uint32_t startOffset, uint32_t startFullOffset);
  bool findStartAndFullOffsets(const std::vector<Crypto::Hash>& knownBlockIds, uint64_t timestamp, uint32_t& startOffset, uint32_t& startFullOffset);
  bool handle_incoming_block(const Block& b, block_verification_context& bvc, bool control_miner, bool relay_block);
  
  // Private mempool functions
  bool add_new_tx(const Transaction& tx, const Crypto::Hash& tx_hash, size_t blob_size, tx_verification_context& tvc, bool kept_by_block);
  bool check_tx_fee(const Transaction& tx, size_t blobSize, tx_verification_context& tvc, bool kept_by_block, uint32_t blockHeight);
  bool check_tx_inputs_keyimages_diff(const Transaction& tx);
  bool check_tx_inputs_keyimages_domain(const Transaction& tx) const;
  bool check_tx_mixin(const Transaction& tx);
  bool check_tx_semantic(const Transaction& tx, bool kept_by_block, uint32_t blockHeight);
  bool check_tx_syntax(const Transaction& tx);
  bool parse_tx_from_blob(Transaction& tx, Crypto::Hash& tx_hash, Crypto::Hash& tx_prefix_hash, const BinaryArray& blob);

  // Private observer functions
  virtual void blockchainUpdated() override;
  void poolUpdated();
  virtual void txDeletedFromPool() override;

  // Private mining functions
  bool update_miner_block_template();
  
  // Other private functions
  bool handle_command_line(const boost::program_options::variables_map& vm);
  bool load_state_data(); // no definition
    
  const Currency& m_currency;
  Logging::LoggerRef logger;
  CryptoNote::RealTimeProvider m_timeProvider;
  tx_memory_pool m_mempool;
  Blockchain m_blockchain;
  i_cryptonote_protocol* m_pprotocol;
  std::unique_ptr<miner> m_miner;
  std::string m_config_folder;
  cryptonote_protocol_stub m_protocol_stub;
  friend class tx_validate_inputs;
  std::atomic<bool> m_starter_message_showed;
  Tools::ObserverManager<ICoreObserver> m_observerManager;

}; // end class Core

} // end namespace CryptoNote

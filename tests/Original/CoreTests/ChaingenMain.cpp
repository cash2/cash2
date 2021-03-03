// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Chaingen.h"

#include "Common/CommandLine.h"

#include "BlockReward.h"
#include "BlockValidation.h"
#include "ChainSplit1.h"
#include "ChainSwitch1.h"
#include "Chaingen001.h"
#include "DoubleSpend.h"
#include "IntegerOverflow.h"
#include "RingSignature.h"
#include "TransactionTests.h"
#include "TransactionValidation.h"
#include "RandomOuts.h"

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_test_data_path              = {"test_data_path", "", ""};
  const command_line::arg_descriptor<bool>        arg_generate_test_data          = {"generate_test_data", ""};
  const command_line::arg_descriptor<bool>        arg_play_test_data              = {"play_test_data", ""};
  const command_line::arg_descriptor<bool>        arg_generate_and_play_test_data = {"generate_and_play_test_data", ""};
  const command_line::arg_descriptor<bool>        arg_test_transactions           = {"test_transactions", ""};
}

int main(int argc, char* argv[])
{
  try {

  po::options_description desc_options("Allowed options");
  command_line::add_arg(desc_options, command_line::arg_help);
  command_line::add_arg(desc_options, arg_test_data_path);
  command_line::add_arg(desc_options, arg_generate_test_data);
  command_line::add_arg(desc_options, arg_play_test_data);
  command_line::add_arg(desc_options, arg_generate_and_play_test_data);
  command_line::add_arg(desc_options, arg_test_transactions);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << desc_options << std::endl;
    return 0;
  }

  size_t tests_count = 0;
  std::vector<std::string> failed_tests;
  std::string tests_folder = command_line::get_arg(vm, arg_test_data_path);
  if (command_line::get_arg(vm, arg_generate_test_data))
  {
    GENERATE("chain001.dat", gen_simple_chain_001);
  }
  else if (command_line::get_arg(vm, arg_play_test_data))
  {
    PLAY("chain001.dat", gen_simple_chain_001);
  }
  else if (command_line::get_arg(vm, arg_generate_and_play_test_data))
  {
    // GENERATE_AND_PLAY(gen_simple_chain_001); // works
    // GENERATE_AND_PLAY(gen_simple_chain_split_1); // works
    // GENERATE_AND_PLAY(one_block); // works
    // GENERATE_AND_PLAY(gen_chain_switch_1); // works
    // GENERATE_AND_PLAY(gen_ring_signature_1); // doesn't work
    // GENERATE_AND_PLAY(gen_ring_signature_2); // works
    // //GENERATE_AND_PLAY(gen_ring_signature_big); // Takes up to XXX hours (if CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW == 10)

    //// Block verification tests
    // GENERATE_AND_PLAY(gen_block_ts_not_checked); // works
    // GENERATE_AND_PLAY(gen_block_ts_in_past); // works
    // GENERATE_AND_PLAY(gen_block_ts_in_future_rejected); // works
    // GENERATE_AND_PLAY(gen_block_ts_in_future_accepted); // works
    // GENERATE_AND_PLAY(gen_block_invalid_prev_id); // works
    // GENERATE_AND_PLAY(gen_block_invalid_nonce); // works
    // GENERATE_AND_PLAY(gen_block_no_miner_tx); // works
    // GENERATE_AND_PLAY(gen_block_unlock_time_is_low); // works
    // GENERATE_AND_PLAY(gen_block_unlock_time_is_high); // works
    // GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_past); // works
    // GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_future); // works
    // GENERATE_AND_PLAY(gen_block_height_is_low); // works
    // GENERATE_AND_PLAY(gen_block_height_is_high); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_has_2_tx_gen_in); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_has_2_in); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_with_txin_to_key); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_out_is_small); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_out_is_big); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_has_no_out); // works
    // GENERATE_AND_PLAY(gen_block_miner_tx_has_out_to_alice); // works
    // GENERATE_AND_PLAY(gen_block_has_invalid_tx); // works
    // GENERATE_AND_PLAY(gen_block_is_too_big); // works
    // GENERATE_AND_PLAY(TestBlockCumulativeSizeExceedsLimit); // doesn't work
    // //GENERATE_AND_PLAY_EX_2VER(gen_block_invalid_binary_format); // Takes up to 30 minutes, if CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW == 10

    // // Transaction verification tests
    // GENERATE_AND_PLAY(gen_tx_big_version); // works
    // GENERATE_AND_PLAY(gen_tx_unlock_time); // works
    // GENERATE_AND_PLAY(gen_tx_no_inputs_no_outputs); // works
    // GENERATE_AND_PLAY(gen_tx_no_inputs_has_outputs); // works
    // GENERATE_AND_PLAY(gen_tx_has_inputs_no_outputs); // works
    // GENERATE_AND_PLAY(gen_tx_invalid_input_amount); // works
    // GENERATE_AND_PLAY(gen_tx_in_to_key_wo_key_offsets); // works
    // GENERATE_AND_PLAY(gen_tx_sender_key_offest_not_exist); // works
    // GENERATE_AND_PLAY(gen_tx_key_offest_points_to_foreign_key); // works
    // GENERATE_AND_PLAY(gen_tx_mixed_key_offest_not_exist); // works
    // GENERATE_AND_PLAY(gen_tx_key_image_not_derive_from_tx_key); // works
    // GENERATE_AND_PLAY(gen_tx_key_image_is_invalid); // works
    // GENERATE_AND_PLAY(gen_tx_check_input_unlock_time); // works
    // GENERATE_AND_PLAY(gen_tx_txout_to_key_has_invalid_key); // works
    // GENERATE_AND_PLAY(gen_tx_output_with_zero_amount); // works
    // GENERATE_AND_PLAY(gen_tx_signatures_are_invalid); // works
    // GENERATE_AND_PLAY_EX(GenerateTransactionWithZeroFee(false)); // doesn't work
    // GENERATE_AND_PLAY_EX(GenerateTransactionWithZeroFee(true)); // works

    // // multisignature output
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(1, 1, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(2, 2, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(3, 2, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(0, 0, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(1, 0, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(0, 1, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(1, 2, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_OutputSignatures(2, 3, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_InvalidOutputSignature()); // works

    // // multisignature input
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(1, 1, 1, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(2, 1, 1, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(3, 2, 2, true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(1, 1, 0, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(2, 2, 1, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_Input(3, 2, 1, false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_BadInputSignature()); // works

    // // Double spend
    // GENERATE_AND_PLAY(gen_double_spend_in_tx<false>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_tx<true>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_the_same_block<false>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_the_same_block<true>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_different_blocks<false>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_different_blocks<true>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_different_chains); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_the_same_block<false>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_the_same_block<true>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_different_blocks<false>); // works
    // GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_different_blocks<true>); // works

    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendInTx(false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendInTx(true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendSameBlock(false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendSameBlock(true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendDifferentBlocks(false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendDifferentBlocks(true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendAltChainSameBlock(false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendAltChainSameBlock(true)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendAltChainDifferentBlocks(false)); // works
    // GENERATE_AND_PLAY_EX(MultiSigTx_DoubleSpendAltChainDifferentBlocks(true)); // works

    // GENERATE_AND_PLAY(gen_uint_overflow_1); // doesn't work
    // GENERATE_AND_PLAY(gen_uint_overflow_2); // doesn't work

    // GENERATE_AND_PLAY(gen_block_reward); // doesn't work
    // GENERATE_AND_PLAY(GetRandomOutputs); // doesn't work

    std::cout << (failed_tests.empty() ? concolor::green : concolor::magenta);
    std::cout << "\nREPORT:\n";
    std::cout << "  Test run: " << tests_count << '\n';
    std::cout << "  Failures: " << failed_tests.size() << '\n';
    if (!failed_tests.empty())
    {
      std::cout << "FAILED TESTS:\n";
      BOOST_FOREACH(auto test_name, failed_tests)
      {
        std::cout << "  " << test_name << '\n';
      }
    }
    std::cout << concolor::normal << std::endl;
  }
  else if (command_line::get_arg(vm, arg_test_transactions))
  {
    CALL_TEST("TRANSACTIONS TESTS", test_transactions);
  }
  else
  {
    std::cout << concolor::magenta << "Wrong arguments" << concolor::normal << std::endl;
    std::cout << desc_options << std::endl;
    return 2;
  }

  return failed_tests.empty() ? 0 : 1;

  } catch (std::exception& e) {
    std::cout << "Exception in main(): " << e.what() << std::endl;
  }
}

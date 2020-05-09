// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "helperFunctions.h"
#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include "System/Dispatcher.h"

#include <random>

using namespace CryptoNote;

/*

My Notes

class MessageQueue {
public
  MessageQueue()
  front()
  pop()
  push()
  stop()
  getHook()
  
private
  wait()
  std::queue<MessageType> messageQueue
  System::Event event
  bool stopped
  typename IntrusiveLinkedList<MessageQueue<MessageType>>::hook hook
}

class MesageQueueGuard {
public
  MesageQueueGuard()
  ~MesageQueueGuard()

private
  MessageQueueContainer& container
  MessageQueue<MessageType>& messageQueue
}

MessageQueue()
wait()
front()
pop()
push()
stop()
getHook()

*/

// constructor
TEST(MessageQueue, 1)
{
  System::Dispatcher dispatcher;

  MessageQueue<BlockchainMessage> messageQueue(dispatcher);
}

// push()
// NewBlockMessage
TEST(MessageQueue, 2)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hash = getRandHash();
  NewBlockMessage newBlockMessage(hash);
  ASSERT_NO_THROW(messageQueue.push(std::move(newBlockMessage)));
}

// push()
// NewAlternativeBlockMessage
TEST(MessageQueue, 3)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hash = getRandHash();
  NewAlternativeBlockMessage newAlternativeBlockMessage(hash);
  ASSERT_NO_THROW(messageQueue.push(std::move(newAlternativeBlockMessage)));
}

// push()
// ChainSwitchMessage
TEST(MessageQueue, 4)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hash = getRandHash();
  std::vector<Crypto::Hash> hashes;
  hashes.push_back(hash);
  ChainSwitchMessage chainSwitchMessage(std::move(hashes));
  ASSERT_NO_THROW(messageQueue.push(std::move(chainSwitchMessage)));
}

// front()
// NewBlockMessage
TEST(MessageQueue, 5)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hashInput = getRandHash();
  NewBlockMessage newBlockMessage(hashInput);
  messageQueue.push(std::move(newBlockMessage));

  BlockchainMessage blockchainMessage = messageQueue.front();

  Crypto::Hash hashOutput;
  ASSERT_TRUE(blockchainMessage.getNewBlockHash(hashOutput));
  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));

  BlockchainMessage::MessageType type = blockchainMessage.getType();
  ASSERT_EQ(type, BlockchainMessage::MessageType::NEW_BLOCK_MESSAGE);
}

// front()
// NewAlternativeBlockMessage
TEST(MessageQueue, 6)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hashInput = getRandHash();
  NewAlternativeBlockMessage newAlternativeBlockMessage(hashInput);
  messageQueue.push(std::move(newAlternativeBlockMessage));

  BlockchainMessage blockchainMessage = messageQueue.front();

  Crypto::Hash hashOutput;
  ASSERT_TRUE(blockchainMessage.getNewAlternativeBlockHash(hashOutput));
  ASSERT_TRUE(hashesEqual(hashInput, hashOutput));

  BlockchainMessage::MessageType type = blockchainMessage.getType();
  ASSERT_EQ(type, BlockchainMessage::MessageType::NEW_ALTERNATIVE_BLOCK_MESSAGE);
}

// front()
// ChainSwitchMessage
TEST(MessageQueue, 7)
{
  System::Dispatcher dispatcher;
  MessageQueue<BlockchainMessage> messageQueue(dispatcher);

  Crypto::Hash hash = getRandHash();
  std::vector<Crypto::Hash> hashesInput;
  hashesInput.push_back(hash);
  std::vector<Crypto::Hash> hashesInputCopy = hashesInput;
  ChainSwitchMessage chainSwitchMessage(std::move(hashesInputCopy));
  ASSERT_NO_THROW(messageQueue.push(std::move(chainSwitchMessage)));

  BlockchainMessage blockchainMessage = messageQueue.front();

  std::vector<Crypto::Hash> hashesOutput;
  ASSERT_TRUE(blockchainMessage.getChainSwitch(hashesOutput));
  ASSERT_TRUE(hashesEqual(hashesInput[0], hashesOutput[0]));

  BlockchainMessage::MessageType type = blockchainMessage.getType();
  ASSERT_EQ(type, BlockchainMessage::MessageType::CHAIN_SWITCH_MESSAGE);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/ConnectionContext.h"

using namespace CryptoNote;

// get_protocol_state_string()
TEST(ConnectionContext, 1)
{
  CryptoNoteConnectionContext context;
  std::string stateStr = get_protocol_state_string(context.m_state);
  ASSERT_EQ("state_before_handshake", stateStr);

  context.m_state = CryptoNoteConnectionContext::state_synchronizing;
  ASSERT_EQ("state_synchronizing", get_protocol_state_string(context.m_state));

  context.m_state = CryptoNoteConnectionContext::state_idle;
  ASSERT_EQ("state_idle", get_protocol_state_string(context.m_state));

  context.m_state = CryptoNoteConnectionContext::state_normal;
  ASSERT_EQ("state_normal", get_protocol_state_string(context.m_state));

  context.m_state = CryptoNoteConnectionContext::state_sync_required;
  ASSERT_EQ("state_sync_required", get_protocol_state_string(context.m_state));

  context.m_state = CryptoNoteConnectionContext::state_pool_sync_required;
  ASSERT_EQ("state_pool_sync_required", get_protocol_state_string(context.m_state));

  context.m_state = CryptoNoteConnectionContext::state_shutdown;
  ASSERT_EQ("state_shutdown", get_protocol_state_string(context.m_state));
}

// operator<<()
TEST(ConnectionContext, 2)
{
  CryptoNoteConnectionContext context;
  context.m_remote_ip = 1234567890; //0100 1001 1001 0110 0000 0010 1101 0010 = 0x499602D2 = 210.002.150.73
  context.m_remote_port = 8080;
  context.m_is_income = true;

  std::stringstream stream;
  stream << context;
  ASSERT_EQ("[210.2.150.73:8080 INC] ", stream.str());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
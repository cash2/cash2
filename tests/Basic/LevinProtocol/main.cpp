// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/LevinProtocol.h"
#include "P2p/P2pProtocolDefinitions.h"
#include "System/TcpConnector.h"
#include "System/TcpConnection.h"
#include "System/TcpListener.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"
#include "System/ContextGroupTimeout.h"
#include "System/Context.h"

/*

My Notes

class LevinProtocol
public
  LevinProtocol()
  invoke()
  notify()
  readCommand()
  sendMessage()
  sendReply()
  decode()
  encode()

*/

using namespace CryptoNote;
using namespace System;

// constructor
TEST(LevinProtocol, 1)
{
  TcpConnection connection;
  LevinProtocol levinProtocol(connection);
}

// invoke()
TEST(LevinProtocol, 2)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = listener.accept();

  COMMAND_PING::request req;
  COMMAND_PING::response rsp;
  Context<> context1(dispatcher, [&] {
    LevinProtocol levinProtocol(sender);
    levinProtocol.invoke(COMMAND_PING::ID, req, rsp);
  });

  Context<> context2(dispatcher, [&] { context1.get(); });  
}

// notify()
TEST(LevinProtocol, 3)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection connection = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);

  COMMAND_PING::request req;
  LevinProtocol levinProtocol(connection);
  levinProtocol.notify(COMMAND_PING::ID, req, 1);
}

// readCommand()
TEST(LevinProtocol, 4)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = listener.accept();

  Context<> context1(dispatcher, [&] {
    LevinProtocol levinProtocol(sender);
    LevinProtocol::Command cmd;
    cmd.command = 1;
    cmd.isNotify = false;
    cmd.isResponse = false;
    cmd.buf = {1, 2, 3, 4};
    ASSERT_TRUE(levinProtocol.readCommand(cmd));
  });

  Context<> context2(dispatcher, [&] { context1.get(); });  
}

// sendMessage()
TEST(LevinProtocol, 5)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = listener.accept();

  Context<> context1(dispatcher, [&] {
    LevinProtocol levinProtocol(sender);
    uint32_t command = 0;
    BinaryArray out = {1, 2, 3, 4};
    bool needResponse = false;
    levinProtocol.sendMessage(command, out, needResponse);
  });

  Context<> context2(dispatcher, [&] { context1.get(); });  
}

// sendReply()
TEST(LevinProtocol, 6)
{
  Dispatcher dispatcher;
  Ipv4Address LISTEN_ADDRESS("127.0.0.1");
  uint16_t LISTEN_PORT = 6666;
  TcpListener listener(dispatcher, LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection sender = TcpConnector(dispatcher).connect(LISTEN_ADDRESS, LISTEN_PORT);
  TcpConnection receiver = listener.accept();

  Context<> context1(dispatcher, [&] {
    LevinProtocol levinProtocol(sender);
    uint32_t command = 0;
    BinaryArray out = {1, 2, 3, 4};
    int returnCode = 1;
    levinProtocol.sendReply(command, out, returnCode);
  });

  Context<> context2(dispatcher, [&] { context1.get(); });  
}

// encode() and decode
TEST(LevinProtocol, 7)
{
  TcpConnection tcpConnection;
  LevinProtocol levinProtocol(tcpConnection);
  COMMAND_PING::response res1 = boost::value_initialized<COMMAND_PING::response>();
  BinaryArray binaryArray = LevinProtocol::encode(res1);

  // binaryArray = 
  //     {
  //        0x80, 0xb0, 0x6d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8,
  //        0x6, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0xa, 0x0, 0x7,
  //        0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x5, 0x0, 0x0,
  //        0x0, 0x0, 0x0, 0x0, 0x0, 0x0
  //      }

  COMMAND_PING::response res2;
  ASSERT_TRUE(LevinProtocol::decode(binaryArray, res2));
  
  ASSERT_EQ(res1.status, res2.status);
  ASSERT_EQ(res1.peer_id, res2.peer_id);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
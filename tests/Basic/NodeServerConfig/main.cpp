// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/NodeServerConfig.h"

/*

My Notes

class NodeServerConfig
public
  *NodeServerConfig()
  *initOptions()
  init()
  *getP2pStateFilename()
  *getTestnet()
  *getBindIp()
  *getBindPort()
  *getExternalPort()
  *getAllowLocalIp()
  *getPeers()
  *getPriorityNodes()
  *getExclusiveNodes()
  *getSeedNodes()
  *getHideMyPort()
  *getConfigFolder()
  *setP2pStateFilename()
  *setTestnet()
  *setBindIp()
  *setBindPort()
  *setExternalPort()
  *setAllowLocalIp()
  *setPeers()
  *setPriorityNodes()
  *setExclusiveNodes()
  *setSeedNodes()
  *setHideMyPort()
  *setConfigFolder()

*/

using namespace CryptoNote;

// constructor
TEST(NodeServerConfig, 1)
{
  NodeServerConfig();
}

// init_options()
TEST(NodeServerConfig, 2)
{
  boost::program_options::options_description desc("Allowed options");
  desc.add_options()
    ("help", "produce help message")
    ("optimization", "optimization level")
    ("verbose, v", "enable verbosity (optionally specify level)")
    ("listen, l", "listen on a port.")
    ("include-path, I", "include path")
    ("input-file", "input file")
  ;

  NodeServerConfig::initOptions(desc);
}

// init()
// cannot initialize the variables map
TEST(NodeServerConfig, 3)
{
  // NodeServerConfig nodeServerConfig;
  // boost::program_options::variables_map vm;
  // ASSERT_TRUE(nodeServerConfig.init(vm));
}

// setP2pStateFilename() and getP2pStateFilename()
TEST(NodeServerConfig, 4)
{
  NodeServerConfig nodeServerConfig;

  std::string filename = "Hello World";
  ASSERT_NO_THROW(nodeServerConfig.setP2pStateFilename(filename));

  std::string filenameRet = nodeServerConfig.getP2pStateFilename();

  ASSERT_EQ(filename, filenameRet);
}

// setTestnet() and getTestnet()
TEST(NodeServerConfig, 5)
{
  NodeServerConfig nodeServerConfig;

  ASSERT_NO_THROW(nodeServerConfig.setTestnet(true));
  ASSERT_TRUE(nodeServerConfig.getTestnet());

  ASSERT_NO_THROW(nodeServerConfig.setTestnet(false));
  ASSERT_FALSE(nodeServerConfig.getTestnet());
}

// setBindIp() and getBindIp()
TEST(NodeServerConfig, 6)
{
  NodeServerConfig nodeServerConfig;

  std::string ip = "123.123.123.123";
  ASSERT_NO_THROW(nodeServerConfig.setBindIp(ip));

  std::string ipRet = nodeServerConfig.getBindIp();

  ASSERT_EQ(ip, ipRet);
}

// setBindPort() and getBindPort()
TEST(NodeServerConfig, 7)
{
  NodeServerConfig nodeServerConfig;

  uint16_t port = 100;
  ASSERT_NO_THROW(nodeServerConfig.setBindPort(port));

  uint16_t portRet = nodeServerConfig.getBindPort();

  ASSERT_EQ(port, portRet);
}

// setExternalPort() and getExternalPort()
TEST(NodeServerConfig, 8)
{
  NodeServerConfig nodeServerConfig;

  uint16_t port = 100;
  ASSERT_NO_THROW(nodeServerConfig.setExternalPort(port));

  uint16_t portRet = nodeServerConfig.getExternalPort();

  ASSERT_EQ(port, portRet);
}

// setAllowLocalIp() and getAllowLocalIp()
TEST(NodeServerConfig, 9)
{
  NodeServerConfig nodeServerConfig;

  ASSERT_NO_THROW(nodeServerConfig.setAllowLocalIp(true));
  ASSERT_TRUE(nodeServerConfig.getAllowLocalIp());

  ASSERT_NO_THROW(nodeServerConfig.setAllowLocalIp(false));
  ASSERT_FALSE(nodeServerConfig.getAllowLocalIp());
}

// setPeers() and getPeers()
TEST(NodeServerConfig, 10)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;
  PeerIdType peerIdType = 3000;
  uint64_t lastSeen = 4000;

  PeerlistEntry peerlistEntry;
  peerlistEntry.adr = networkAddress;
  peerlistEntry.id = peerIdType;
  peerlistEntry.last_seen = lastSeen;

  std::vector<PeerlistEntry> peerList;
  peerList.push_back(peerlistEntry);
  
  NodeServerConfig nodeServerConfig;
  ASSERT_NO_THROW(nodeServerConfig.setPeers(peerList));

  std::vector<PeerlistEntry> peerListRet = nodeServerConfig.getPeers();

  ASSERT_EQ(1, peerListRet.size());
  ASSERT_EQ(1000, peerListRet[0].adr.ip);
  ASSERT_EQ(2000, peerListRet[0].adr.port);
  ASSERT_EQ(3000, peerListRet[0].id);
  ASSERT_EQ(4000, peerListRet[0].last_seen);
}

// setPriorityNodes() and getPriorityNodes()
TEST(NodeServerConfig, 11)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NodeServerConfig nodeServerConfig;
  ASSERT_NO_THROW(nodeServerConfig.setPriorityNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = nodeServerConfig.getPriorityNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setExclusiveNodes() and getExclusiveNodes()
TEST(NodeServerConfig, 12)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NodeServerConfig nodeServerConfig;
  ASSERT_NO_THROW(nodeServerConfig.setExclusiveNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = nodeServerConfig.getExclusiveNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setSeedNodes() and getSeedNodes()
TEST(NodeServerConfig, 13)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NodeServerConfig nodeServerConfig;
  ASSERT_NO_THROW(nodeServerConfig.setSeedNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = nodeServerConfig.getSeedNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setHideMyPort() and getHideMyPort()
TEST(NodeServerConfig, 14)
{
  NodeServerConfig nodeServerConfig;

  ASSERT_NO_THROW(nodeServerConfig.setHideMyPort(true));
  ASSERT_TRUE(nodeServerConfig.getHideMyPort());

  ASSERT_NO_THROW(nodeServerConfig.setHideMyPort(false));
  ASSERT_FALSE(nodeServerConfig.getHideMyPort());
}

// setConfigFolder() and getConfigFolder()
TEST(NodeServerConfig, 15)
{
  NodeServerConfig nodeServerConfig;

  std::string folder = "Hello World";
  ASSERT_NO_THROW(nodeServerConfig.setConfigFolder(folder));

  std::string folderRet = nodeServerConfig.getConfigFolder();

  ASSERT_EQ(folder, folderRet);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "P2p/NetNodeConfig.h"

/*

My Notes

class NetNodeConfig
public
  *NetNodeConfig()
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
TEST(NetNodeConfig, 1)
{
  NetNodeConfig();
}

// init_options()
TEST(NetNodeConfig, 2)
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

  NetNodeConfig::initOptions(desc);
}

// init()
// cannot initialize the variables map
TEST(NetNodeConfig, 3)
{
  // NetNodeConfig netNodeConfig;
  // boost::program_options::variables_map vm;
  // ASSERT_TRUE(netNodeConfig.init(vm));
}

// setP2pStateFilename() and getP2pStateFilename()
TEST(NetNodeConfig, 4)
{
  NetNodeConfig netNodeConfig;

  std::string filename = "Hello World";
  ASSERT_NO_THROW(netNodeConfig.setP2pStateFilename(filename));

  std::string filenameRet = netNodeConfig.getP2pStateFilename();

  ASSERT_EQ(filename, filenameRet);
}

// setTestnet() and getTestnet()
TEST(NetNodeConfig, 5)
{
  NetNodeConfig netNodeConfig;

  ASSERT_NO_THROW(netNodeConfig.setTestnet(true));
  ASSERT_TRUE(netNodeConfig.getTestnet());

  ASSERT_NO_THROW(netNodeConfig.setTestnet(false));
  ASSERT_FALSE(netNodeConfig.getTestnet());
}

// setBindIp() and getBindIp()
TEST(NetNodeConfig, 6)
{
  NetNodeConfig netNodeConfig;

  std::string ip = "123.123.123.123";
  ASSERT_NO_THROW(netNodeConfig.setBindIp(ip));

  std::string ipRet = netNodeConfig.getBindIp();

  ASSERT_EQ(ip, ipRet);
}

// setBindPort() and getBindPort()
TEST(NetNodeConfig, 7)
{
  NetNodeConfig netNodeConfig;

  uint16_t port = 100;
  ASSERT_NO_THROW(netNodeConfig.setBindPort(port));

  uint16_t portRet = netNodeConfig.getBindPort();

  ASSERT_EQ(port, portRet);
}

// setExternalPort() and getExternalPort()
TEST(NetNodeConfig, 8)
{
  NetNodeConfig netNodeConfig;

  uint16_t port = 100;
  ASSERT_NO_THROW(netNodeConfig.setExternalPort(port));

  uint16_t portRet = netNodeConfig.getExternalPort();

  ASSERT_EQ(port, portRet);
}

// setAllowLocalIp() and getAllowLocalIp()
TEST(NetNodeConfig, 9)
{
  NetNodeConfig netNodeConfig;

  ASSERT_NO_THROW(netNodeConfig.setAllowLocalIp(true));
  ASSERT_TRUE(netNodeConfig.getAllowLocalIp());

  ASSERT_NO_THROW(netNodeConfig.setAllowLocalIp(false));
  ASSERT_FALSE(netNodeConfig.getAllowLocalIp());
}

// setPeers() and getPeers()
TEST(NetNodeConfig, 10)
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
  
  NetNodeConfig netNodeConfig;
  ASSERT_NO_THROW(netNodeConfig.setPeers(peerList));

  std::vector<PeerlistEntry> peerListRet = netNodeConfig.getPeers();

  ASSERT_EQ(1, peerListRet.size());
  ASSERT_EQ(1000, peerListRet[0].adr.ip);
  ASSERT_EQ(2000, peerListRet[0].adr.port);
  ASSERT_EQ(3000, peerListRet[0].id);
  ASSERT_EQ(4000, peerListRet[0].last_seen);
}

// setPriorityNodes() and getPriorityNodes()
TEST(NetNodeConfig, 11)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NetNodeConfig netNodeConfig;
  ASSERT_NO_THROW(netNodeConfig.setPriorityNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = netNodeConfig.getPriorityNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setExclusiveNodes() and getExclusiveNodes()
TEST(NetNodeConfig, 12)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NetNodeConfig netNodeConfig;
  ASSERT_NO_THROW(netNodeConfig.setExclusiveNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = netNodeConfig.getExclusiveNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setSeedNodes() and getSeedNodes()
TEST(NetNodeConfig, 13)
{
  NetworkAddress networkAddress;
  networkAddress.ip = 1000;
  networkAddress.port = 2000;

  std::vector<NetworkAddress> networkAddresses;
  networkAddresses.push_back(networkAddress);
  
  NetNodeConfig netNodeConfig;
  ASSERT_NO_THROW(netNodeConfig.setSeedNodes(networkAddresses));

  std::vector<NetworkAddress> networkAddressesRet = netNodeConfig.getSeedNodes();

  ASSERT_EQ(1, networkAddressesRet.size());
  ASSERT_EQ(1000, networkAddressesRet[0].ip);
  ASSERT_EQ(2000, networkAddressesRet[0].port);
}

// setHideMyPort() and getHideMyPort()
TEST(NetNodeConfig, 14)
{
  NetNodeConfig netNodeConfig;

  ASSERT_NO_THROW(netNodeConfig.setHideMyPort(true));
  ASSERT_TRUE(netNodeConfig.getHideMyPort());

  ASSERT_NO_THROW(netNodeConfig.setHideMyPort(false));
  ASSERT_FALSE(netNodeConfig.getHideMyPort());
}

// setConfigFolder() and getConfigFolder()
TEST(NetNodeConfig, 15)
{
  NetNodeConfig netNodeConfig;

  std::string folder = "Hello World";
  ASSERT_NO_THROW(netNodeConfig.setConfigFolder(folder));

  std::string folderRet = netNodeConfig.getConfigFolder();

  ASSERT_EQ(folder, folderRet);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
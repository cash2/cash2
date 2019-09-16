add_definitions(-DSTATICLIB)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ../version)

file(GLOB_RECURSE NodeServer NodeServer/*)

source_group("" FILES ${NodeServer})

add_executable(NodeServer ${NodeServer})

target_link_libraries(NodeServer gtest_main P2p CryptoNoteCore BlockchainExplorer Crypto Serialization Logging System Common upnpc-static ${Boost_LIBRARIES})

add_custom_target(Basic DEPENDS NodeServer)

set_property(TARGET Basic NodeServer PROPERTY FOLDER "Basic")

set_property(TARGET NodeServer PROPERTY OUTPUT_NAME "NodeServer")

if(NOT MSVC)
  # suppress warnings from gtest
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-undef -Wno-sign-compare -O0")
endif()
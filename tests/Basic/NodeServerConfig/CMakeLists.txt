add_definitions(-DSTATICLIB)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ../version)

file(GLOB_RECURSE NodeServerConfig NodeServerConfig/*)

source_group("" FILES ${NodeServerConfig})

add_executable(NodeServerConfig ${NodeServerConfig})

target_link_libraries(NodeServerConfig gtest_main P2p CryptoNoteCore Crypto Serialization Logging System Common upnpc-static ${Boost_LIBRARIES})

add_custom_target(Basic DEPENDS NodeServerConfig)

set_property(TARGET Basic NodeServerConfig PROPERTY FOLDER "Basic")

set_property(TARGET NodeServerConfig PROPERTY OUTPUT_NAME "NodeServerConfig")

if(NOT MSVC)
  # suppress warnings from gtest
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-undef -Wno-sign-compare -O0")
endif()
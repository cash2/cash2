add_definitions(-DSTATICLIB)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ../version)

file(GLOB_RECURSE Difficulty Difficulty/*)

source_group("" FILES ${Difficulty})

add_executable(Difficulty ${Difficulty})

target_link_libraries(Difficulty gtest_main Crypto Common)

add_custom_target(Basic DEPENDS Difficulty)

set_property(TARGET Basic Difficulty PROPERTY FOLDER "Basic")

set_property(TARGET Difficulty PROPERTY OUTPUT_NAME "Difficulty")

if(NOT MSVC)
  # suppress warnings from gtest
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-undef -Wno-sign-compare -O0")
endif()
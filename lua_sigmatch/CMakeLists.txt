# CMakeList.txt : CMake project for lua_sigmatch, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (lua_sigmatch "lua_sigmatch.cpp" "lua_sigmatch.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET lua_sigmatch PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.

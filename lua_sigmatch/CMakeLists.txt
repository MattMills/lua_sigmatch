# CMakeList.txt : builds the `sigmatch` Lua module, and a static library for hosts that embed
# Lua and want to link the bindings in directly.
#
# Targets:
#   lua_sigmatch         (alias lua_sigmatch::module)  sigmatch.so / sigmatch.dll for require()
#   lua_sigmatch_static  (alias lua_sigmatch::static)  register `luaopen_sigmatch` yourself

if (NOT WIN32 AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "sigmatch only supports Windows and Linux, not ${CMAKE_SYSTEM_NAME}.")
endif()

option(LUA_SIGMATCH_GHIDRA_FORMAT "Accept Ghidra style signature bytes such as [01..1...]" ON)
option(LUA_SIGMATCH_STORE_EACH_READING_FAILURE_WARNING "Add a warning to the result for every failed block read" OFF)
option(LUA_SIGMATCH_BUILD_MODULE "Build the loadable module (sigmatch.so / sigmatch.dll)" ON)
option(LUA_SIGMATCH_BUILD_STATIC "Build lua_sigmatch_static as part of the default target" OFF)
set(LUA_SIGMATCH_LUA_INCLUDE_DIR "" CACHE PATH "Lua headers to build against. Empty: the LuaJIT submodule in lib/luajit")
set(LUA_SIGMATCH_LUA_LIBRARY "" CACHE FILEPATH "Lua library to link: by the module on Windows, by the embedding test everywhere")
set(LUA_SIGMATCH_LUA_INTERPRETER "" CACHE FILEPATH "Lua interpreter that runs the tests")
set(LUA_SIGMATCH_LUAJIT_MAKE_ARGS "" CACHE STRING "Extra arguments for building the LuaJIT submodule with make")

find_package(Threads REQUIRED)

#
# Lua
#
# lua_include_dir   headers
# lua_library       what the module links against (Windows only, Linux modules resolve Lua
#                   symbols from the host process)
# lua_link_library  a library a host executable can link (for the embedding test)
# lua_interpreter   runs the tests
#

if (LUA_SIGMATCH_LUA_INCLUDE_DIR)
  set(lua_include_dir "${LUA_SIGMATCH_LUA_INCLUDE_DIR}")
  set(lua_link_library "${LUA_SIGMATCH_LUA_LIBRARY}")
  set(lua_interpreter "${LUA_SIGMATCH_LUA_INTERPRETER}")
  if (WIN32)
    set(lua_library "${LUA_SIGMATCH_LUA_LIBRARY}")
    if (LUA_SIGMATCH_BUILD_MODULE AND NOT lua_library)
      message(FATAL_ERROR
        "The module needs LUA_SIGMATCH_LUA_LIBRARY on Windows (the import library of the Lua DLL, "
        "e.g. lua51.lib). Hosts that only link lua_sigmatch_static can set LUA_SIGMATCH_BUILD_MODULE=OFF.")
    endif()
  endif()
elseif (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lib/luajit/src/lua.h")
  include(ExternalProject)

  set(lua_include_dir "${CMAKE_CURRENT_SOURCE_DIR}/lib/luajit/src")
  set(luajit_dir "${CMAKE_CURRENT_BINARY_DIR}/luajit")

  if (MSVC)
    set(luajit_build_command ${CMAKE_COMMAND} -E chdir "${luajit_dir}/src" cmd /c msvcbuild.bat)
    set(lua_library "${luajit_dir}/src/lua51.lib")
    set(lua_link_library "${lua_library}")
    set(lua_interpreter "${luajit_dir}/src/luajit.exe")
  else()
    find_program(LUA_SIGMATCH_MAKE NAMES gmake make mingw32-make REQUIRED)
    cmake_host_system_information(RESULT cores QUERY NUMBER_OF_LOGICAL_CORES)
    set(luajit_make_args ${LUA_SIGMATCH_LUAJIT_MAKE_ARGS})

    if (WIN32) # MinGW
      if (CMAKE_CROSSCOMPILING)
        get_filename_component(cc_name "${CMAKE_C_COMPILER}" NAME)
        string(REGEX REPLACE "gcc.*$" "" cross_prefix "${cc_name}")
        list(APPEND luajit_make_args HOST_CC=gcc CROSS=${cross_prefix} TARGET_SYS=Windows)
      endif()
      set(lua_library "${luajit_dir}/src/lua51.dll")
      set(lua_link_library "${lua_library}")
      set(lua_interpreter "${luajit_dir}/src/luajit.exe")
    else()
      set(lua_library "")
      set(lua_link_library "${luajit_dir}/src/libluajit.a" ${CMAKE_DL_LIBS} m)
      set(lua_interpreter "${luajit_dir}/src/luajit")
    endif()

    set(luajit_build_command ${LUA_SIGMATCH_MAKE} -C "${luajit_dir}/src" -j${cores} ${luajit_make_args})
  endif()

  # Built from a copy so that the submodule's work tree stays clean.
  ExternalProject_Add(lua_sigmatch_luajit
    SOURCE_DIR "${luajit_dir}"
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/lib/luajit" "${luajit_dir}"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${luajit_build_command}
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${lua_library} ${lua_interpreter} "${luajit_dir}/src/libluajit.a"
  )
  set(lua_dependency lua_sigmatch_luajit)
else()
  message(FATAL_ERROR
    "The LuaJIT submodule is missing. Run `git submodule update --init`, "
    "or point LUA_SIGMATCH_LUA_INCLUDE_DIR at the Lua headers to build against.")
endif()

#
# Build settings shared by the module and the static library. Linked privately: consumers of
# the static library only see lua_sigmatch.h and the Lua headers, not C++20 or sigmatch.
#

add_library(lua_sigmatch_config INTERFACE)
target_include_directories(lua_sigmatch_config INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/lib/sigmatch/include"
  "${lua_include_dir}"
)
target_compile_features(lua_sigmatch_config INTERFACE cxx_std_20)
target_compile_definitions(lua_sigmatch_config INTERFACE
  SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING
  LUA_SIGMATCH_VERSION="${lua_sigmatch_VERSION}"
  $<$<BOOL:${LUA_SIGMATCH_GHIDRA_FORMAT}>:SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT>
  $<$<BOOL:${LUA_SIGMATCH_STORE_EACH_READING_FAILURE_WARNING}>:SIGMATCH_STORE_EACH_READING_FAILURE_WARNING_MESSAGE>
)
target_link_libraries(lua_sigmatch_config INTERFACE Threads::Threads)
if (MSVC)
  target_compile_options(lua_sigmatch_config INTERFACE /utf-8 /Zc:__cplusplus)
endif()

if (MSVC)
  set(lua_sigmatch_warnings /W4)
else()
  set(lua_sigmatch_warnings -Wall -Wextra -Wpedantic)
endif()

#
# Lua module: require("sigmatch")
#

if (LUA_SIGMATCH_BUILD_MODULE)
  add_library(lua_sigmatch MODULE "lua_sigmatch.cpp" "lua_sigmatch.h")
  add_library(lua_sigmatch::module ALIAS lua_sigmatch)
  set_target_properties(lua_sigmatch PROPERTIES
    OUTPUT_NAME "sigmatch"
    PREFIX ""
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
  target_compile_definitions(lua_sigmatch PRIVATE LUA_SIGMATCH_BUILDING)
  target_compile_options(lua_sigmatch PRIVATE ${lua_sigmatch_warnings})
  target_link_libraries(lua_sigmatch PRIVATE lua_sigmatch_config)
  if (lua_library)
    target_link_libraries(lua_sigmatch PRIVATE "${lua_library}")
  endif()
  if (MINGW)
    # No libstdc++ / libgcc / winpthread DLLs needed next to sigmatch.dll
    target_link_options(lua_sigmatch PRIVATE -static)
  endif()
  if (lua_dependency)
    add_dependencies(lua_sigmatch ${lua_dependency})
  endif()
endif()

#
# Static library: link it into a host and register `luaopen_sigmatch`
#

add_library(lua_sigmatch_static STATIC "lua_sigmatch.cpp" "lua_sigmatch.h")
add_library(lua_sigmatch::static ALIAS lua_sigmatch_static)
set_target_properties(lua_sigmatch_static PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(lua_sigmatch_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${lua_include_dir}")
target_compile_definitions(lua_sigmatch_static PUBLIC LUA_SIGMATCH_STATIC)
target_compile_options(lua_sigmatch_static PRIVATE ${lua_sigmatch_warnings})
target_link_libraries(lua_sigmatch_static PRIVATE lua_sigmatch_config)
if (NOT LUA_SIGMATCH_BUILD_STATIC)
  set_target_properties(lua_sigmatch_static PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

#
# Tests
#

if (LUA_SIGMATCH_BUILD_TESTS)
  add_subdirectory(tests)
endif()

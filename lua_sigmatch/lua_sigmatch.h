// lua_sigmatch.h : Lua bindings for the sigmatch signature search library.
//
// Built as a Lua module, `require("sigmatch")` finds `luaopen_sigmatch` on its own. When the
// static library is linked into a host instead (define LUA_SIGMATCH_STATIC), register it with
// e.g. `luaL_requiref(L, "sigmatch", luaopen_sigmatch, 0)` or by storing `luaopen_sigmatch` in
// `package.preload["sigmatch"]`.

#pragma once

#if defined(__cplusplus)
    #include <lua.hpp>
#else
    #include <lua.h>
#endif

#if defined(LUA_SIGMATCH_STATIC)
    #define LUA_SIGMATCH_API
#elif defined(_WIN32)
    #if defined(LUA_SIGMATCH_BUILDING)
        #define LUA_SIGMATCH_API __declspec(dllexport)
    #else
        #define LUA_SIGMATCH_API __declspec(dllimport)
    #endif
#else
    #define LUA_SIGMATCH_API __attribute__((visibility("default")))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// Pushes the module table and returns 1.
LUA_SIGMATCH_API int luaopen_sigmatch(lua_State *L);

#if defined(__cplusplus)
}
#endif

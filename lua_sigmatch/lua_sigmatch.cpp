// lua_sigmatch.cpp : Defines the entry point for the application.
//

#include "lua_sigmatch.h"

using namespace std;

sigmatch_signature_search(lua_State* L) {



}

static const struct luaL_reg sigmatchlib[] = {
	{"signature_search", sigmatch_signature_search},
	{NULL, NULL}
};

int luaopen_sigmatch(lua_State* L) {

};
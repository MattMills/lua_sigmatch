# lua_sigmatch

Lua bindings for [sigmatch](https://github.com/SpriteOvO/sigmatch), a C++20 signature
match / search library: find byte patterns (with wildcards) in the current process, in other
processes and in files, from Lua.

- The whole sigmatch API is exposed: signatures, readers, targets, search contexts, the blocking and
  multi-threaded searchers, and search results. Readers and targets can also be written in Lua.
- It works with LuaJIT and Lua 5.1 to 5.4.
- It runs on Windows and Linux. Upstream sigmatch is Windows-only; the copy in this repo adds a
  Linux port (see [Vendored sigmatch](#vendored-sigmatch)).
- It builds as a loadable module (`sigmatch.dll` / `sigmatch.so`) or as a static library to link
  into a host that embeds Lua.

```lua
local sigmatch = require("sigmatch")
local ffi = require("ffi")

local target = sigmatch.this_process_target()
local result = target:in_module("stellaris.exe", "rx"):search("48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??")

if result:has_error() then
    error(table.concat(result:error_messages(), "; "))
end
for _, address in ipairs(result:matches()) do
    local code = ffi.cast("uint8_t *", address) -- addresses are plain numbers
    print(string.format("match at 0x%x, first byte %02X", address, code[0]))
end
```

## Building

```sh
git clone --recursive https://github.com/MattMills/lua_sigmatch.git   # or: git submodule update --init
cmake --preset linux-debug            # Windows: x64-debug / x64-release from a VS developer prompt
cmake --build out/build/linux-debug
ctest --test-dir out/build/linux-debug --output-on-failure
```

By default this builds LuaJIT from the `lua_sigmatch/lib/luajit` submodule (the
[MattMills/LuaJIT](https://github.com/MattMills/LuaJIT) fork), then the module against it. It uses
`make` on Linux and MinGW, and `msvcbuild.bat` with MSVC. A C++20 compiler is required (MSVC 2022,
GCC 13, Clang 16 or newer).

| Target                | Output                         | Use                                         |
|-----------------------|--------------------------------|---------------------------------------------|
| `lua_sigmatch`        | `sigmatch.dll` / `sigmatch.so` | `require("sigmatch")`                       |
| `lua_sigmatch_static` | static library                 | link into a host, register `luaopen_sigmatch` |

On Windows the module links against `lua51.dll`, and the host must load that same DLL. On Linux
the module doesn't link Lua at all and takes the symbols from the host process, the usual
convention for Lua modules.

| CMake option                                      | Default | Meaning                                                    |
|---------------------------------------------------|---------|------------------------------------------------------------|
| `LUA_SIGMATCH_LUA_INCLUDE_DIR`                    | empty   | Lua headers to build against instead of the submodule      |
| `LUA_SIGMATCH_LUA_LIBRARY`                        | empty   | Lua library: the module links it on Windows, the embedding test everywhere |
| `LUA_SIGMATCH_LUA_INTERPRETER`                    | empty   | interpreter for the module test (the submodule's `luajit` by default) |
| `LUA_SIGMATCH_BUILD_MODULE`                       | `ON`    | build `sigmatch.dll` / `sigmatch.so`                       |
| `LUA_SIGMATCH_BUILD_STATIC`                       | `OFF`   | build `lua_sigmatch_static` by default (it builds on demand anyway) |
| `LUA_SIGMATCH_GHIDRA_FORMAT`                      | `ON`    | accept Ghidra bytes like `[01..1...]` (`.` is also a wildcard) |
| `LUA_SIGMATCH_STORE_EACH_READING_FAILURE_WARNING` | `OFF`   | one warning per failed block read instead of a single summary |
| `LUA_SIGMATCH_BUILD_TESTS`                        | `ON` when top level | register the tests with CTest                  |

For example, against the system's Lua 5.4:

```sh
cmake -B build -DLUA_SIGMATCH_LUA_INCLUDE_DIR=/usr/include/lua5.4 \
      -DLUA_SIGMATCH_LUA_INTERPRETER=/usr/bin/lua5.4 \
      -DLUA_SIGMATCH_LUA_LIBRARY=/usr/lib/x86_64-linux-gnu/liblua5.4.so
```

### Embedding in a host (e.g. stellar-injected)

A host that links LuaJIT statically can't `require` a separate `sigmatch.dll` built against
`lua51.dll`, because the process would end up with two Lua runtimes. Link the static library
instead and register the bindings yourself:

```cmake
set(LUA_SIGMATCH_LUA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/luajit/src" CACHE PATH "")
set(LUA_SIGMATCH_BUILD_MODULE OFF CACHE BOOL "")
add_subdirectory(lib/lua_sigmatch)
target_link_libraries(stellar-injected PRIVATE lua_sigmatch::static)   # plus your LuaJIT
```

```cpp
#include <lua_sigmatch.h>

// package.preload["sigmatch"] = luaopen_sigmatch, so scripts can require("sigmatch")
lua_getglobal(L, "package");
lua_getfield(L, -1, "preload");
lua_pushcfunction(L, luaopen_sigmatch);
lua_setfield(L, -2, "sigmatch");
lua_pop(L, 2);
```

The static library only exposes `lua_sigmatch.h` and the Lua headers, so the host can stay on an
older C++ standard. Its copy of sigmatch lives in its own namespace, so it can coexist with another
copy of sigmatch in the same binary.

## Lua API

Names and behaviour follow the C++ library. `sig` arguments accept a `signature`, a signature
string or a byte table. `reader` arguments are reader objects.

**Errors.** Bad arguments raise Lua errors. Problems while searching are reported in the
returned `search_result`, as in C++: a missing module, a file that can't be opened, unreadable
memory. Check `result:has_error()` and `result:has_warning()`.

**Addresses** are integers on Lua 5.3+ and numbers on Lua 5.1 / LuaJIT (exact up to 2^53, which
covers user-space addresses). Address arguments also accept light userdata. With the LuaJIT FFI,
use `ffi.cast("uint8_t *", address)`, and `tonumber(ffi.cast("uintptr_t", pointer))` to pass a
pointer in. For file targets, addresses are file offsets.

### Module

| Field | |
|---|---|
| `_VERSION`, `sigmatch_version` | `"lua_sigmatch 0.1.0"`, `"0.2.0"` (the sigmatch release) |
| `platform` | `"windows"` or `"linux"` |
| `ghidra_format` | whether Ghidra bytes are accepted |
| `block_size`, `multi_threaded_search_size_threshold`, `hardware_concurrency` | the searcher defaults |
| `mem_prot` | `{ read = 1, write = 2, execute = 4 }` |
| `_` | the wildcard placeholder (`sigmatch::_`) |
| `current_process_id()` | the current process id |

### Signatures

```lua
sigmatch.signature("1A ?? 3C ** 5* ?F [01..1...]")   -- raises on malformed input
sigmatch.signature.parse(text)                      -- signature, or nil and a message
sigmatch.signature({ 0x7D, 0xDC, { sigmatch._, 0xB }, { 0x9, sigmatch._ }, sigmatch._, 0x24 })
sigmatch.signature(other)                            -- copy; sigmatch.signature() is empty
```

- **Text.** Two hex digits per byte, separated by whitespace. `?` or `*` stand for a nibble or a
  whole byte, and with Ghidra format `[01..1...]` gives a bit pattern where `.` is a wildcard.
  Error messages name the bad byte, e.g. `invalid signature: bad byte '1G' at position 3`.
- **Tables.** Each element mirrors a C++ `sig_byte` constructor: `0x1A`, `sigmatch._`, `{high, _}`,
  `{_, low}`, `{value, mask}`, a token string like `"?F"`, or a `sig_byte`.
- **Methods.** `sig:size()` / `#sig`, `sig:bytes()` (a list of `sig_byte`), `sig[i]`,
  `sig1 == sig2`, `tostring(sig)`.

`sigmatch.sig_byte(value [, mask])`, `sig_byte(high, _)`, `sig_byte(_, low)`, `sig_byte(_)` or
`sig_byte("1?")` builds a single byte, with `:value()`, `:mask()`, `:match(byte)`, `==` and
`tostring`. A `value` with bits outside `mask` is rejected, because such a byte can never match.

### Targets and search contexts

| Constructor | Methods |
|---|---|
| `this_process_target([reader])` | `in_range`, `in_module`, `pid`, `error`, `reader` |
| `external_process_target(pid [, reader])` | `in_range`, `in_module`, `pid`, `error`, `reader` |
| `file_target(path [, reader])` | `in_range(offset, size)`, `in_whole`, `error`, `reader` |
| `access_memory_target(reader)` | `in_range`, `error`, `reader`, a base for custom memory targets |
| `access_file_target(reader)` | `in_range(offset, size)`, `error`, `reader`, a base for custom file targets |

- **`in_range`** on memory targets takes `(address, size)` or a list of ranges:
  `{ {address, size}, {address = a, size = n}, ... }`. Ranges are searched independently.
- **`in_module(name [, prot])`** searches a loaded module. Names are matched without regard to
  case.
  - `prot` is a sum of `mem_prot` flags or a string like `"r"`, `"rw"`, `"rx"`.
  - As in sigmatch, it selects pages whose protection is *exactly* that: `"r"` means read-only
    pages, `"rx"` means executable read-only code, and `"w"` alone means read-write.
- **`error()`** returns the target's error message, or nil.
- **`reader()`** returns the target's reader object.

Each of these returns a **search context**. You can also build one yourself:

- `sigmatch.search_context(address, size, reader)` or `sigmatch.search_context(ranges, reader)`
- `sigmatch.search_context.make_error(message)`

A context has three methods:

- `ctx:search(sig)` searches with the default (blocking) searcher.
- `ctx:select(sigmatch.blocking_searcher [, block_size])` and
  `ctx:select(sigmatch.multi_threaded_searcher [, threads_max_count [, block_size]])` return an
  executor with `:search(sig)`. Pass `nil` to keep a default value; the names as strings work too.
- `ctx:error()` returns the context's error message, or nil.

The multi-threaded searcher only splits ranges larger than
`multi_threaded_search_size_threshold` (64 KiB) per thread.

### Readers

| Constructor | |
|---|---|
| `this_process_memory_reader()` | raw `memcpy`; the default for `this_process_target` |
| `external_process_memory_reader(pid)` | `ReadProcessMemory` / `/proc/<pid>/mem` |
| `file_content_reader(path)` | file contents, offsets as addresses |
| `reader(function(address, size) ... end)` | a reader written in Lua |
| `reader({ read = function(self, address, size) end, error = function(self) end })` | the same, as an object |

Every reader has `reader:read(address, size)`, which returns a string or nil, and
`reader:error()`.

A Lua reader returns exactly `size` bytes, or nil / false (or a shorter string) when the read
fails. If its `error` method returns a message, searches report it as their error. Errors raised
inside the callbacks propagate out of the search call. Lua readers run on the thread that started
the search, so the multi-threaded searcher refuses them.

> `this_process_memory_reader` copies memory directly, like the C++ library. Ranges in
> `in_module` are safe, but an `in_range` over unmapped memory crashes the process. For checked
> reads of your own process, use
> `this_process_target(sigmatch.external_process_memory_reader(sigmatch.current_process_id()))`.

### Searchers and results

- `sigmatch.blocking_searcher(reader [, block_size])` and
  `sigmatch.multi_threaded_searcher(reader [, threads_max_count [, block_size]])` can be used
  directly: `searcher:search(address, size, sig [, result])` or
  `searcher:search(ranges, sig [, result])`. If you pass a `result`, the matches are appended to it.
- `search_result` has `:matches()`, `:error_messages()`, `:warning_messages()`, `:has_error()` and
  `:has_warning()`. `#result` and `result[i]` give the matches, and results support `==` and
  `tostring`. You can create one with `sigmatch.search_result()`,
  `sigmatch.search_result.make_error(msg)` or `sigmatch.search_result.make_warning(msg)`.

### Linux notes

- A module is a file-backed mapping, found by its file name (`"libc.so.6"`, or the executable's
  name).
- ELF images have inaccessible gaps between segments, so `in_module(name)` searches only the
  readable parts.
- Reading another process needs ptrace permission: the same user, plus whatever the
  `kernel.yama.ptrace_scope` setting requires.

## Tests

`ctest` runs `lua_sigmatch/tests/test_sigmatch.lua` twice: with the module loaded by `require`,
and with the static library linked into a small host program
(`lua_sigmatch/tests/embed_host.cpp`). The suite covers:

- signature parsing (upstream's vectors included) and matching across block and thread
  boundaries
- every searcher configuration producing identical results
- process, file and custom targets, and module protections
- Lua readers (errors, coroutines, nesting, garbage collection)
- the bugs fixed in the vendored sigmatch
- with LuaJIT, FFI buffers

It passes on Linux with LuaJIT, Lua 5.1 and Lua 5.4 (GCC and Clang, also under ASan + UBSan), and
with a MinGW Windows build run under Wine. The MSVC build hasn't been run yet.

## Vendored sigmatch

`lua_sigmatch/lib/sigmatch` holds sigmatch v0.2.0 (upstream commit `9157152`), committed unmodified
and then patched in separate commits:

- It builds with GCC, Clang and MinGW, not just MSVC.
- It has a Linux implementation: `/proc/<pid>/maps` for modules and protections,
  `/proc/<pid>/mem` for reads.
- Bug fixes:
  - The process handle closer only closed *invalid* handles.
  - The executor dereferenced the reader before null-checking it.
  - `file_content_reader` broke for good after any read hit the end of the file.
  - The blocking searcher stitched data from both sides of a failed read into false matches.
  - `target` had no virtual destructor.

Upstream's own test suite passes against the patched header.

## License

lua_sigmatch is licensed under the GPLv3 (see `LICENSE.txt`). sigmatch is MIT or Apache-2.0
(`lua_sigmatch/lib/sigmatch/LICENSE-*`), and LuaJIT is MIT.

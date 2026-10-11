// lua_sigmatch.cpp : Lua bindings for the sigmatch signature search library.
//
// Every public class of sigmatch is exposed as a userdata type, see README.md for the Lua API.
//
// Two rules keep the binding safe in a host process:
//
// - Lua errors are only raised while no C++ object that owns resources is alive. With PUC Lua
//   built as C, errors are longjmp()s that skip destructors. Arguments are checked before such
//   objects exist, and objects handed to Lua are placed in their userdata before being filled.
// - C++ exceptions never cross into Lua: `guarded()` turns them into Lua errors.

#if !defined(SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING)
    #define SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING
#endif

#include "lua_sigmatch.h"

#include <sigmatch/sigmatch.hpp>

#include <cmath>
#include <cstdlib>
#include <limits>
#include <new>
#include <utility>

#if !defined(LUA_SIGMATCH_VERSION)
    #define LUA_SIGMATCH_VERSION "0.0.0"
#endif

namespace {

//////////////////////////////////////////////////
// Lua 5.1 / LuaJIT / 5.2 / 5.3 / 5.4 compatibility
//

namespace compat {

int absindex(lua_State *L, int idx)
{
    return idx > 0 || idx <= LUA_REGISTRYINDEX ? idx : lua_gettop(L) + idx + 1;
}

size_t rawlen(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    return lua_rawlen(L, idx);
#else
    return lua_objlen(L, idx);
#endif
}

void setfuncs(lua_State *L, const luaL_Reg *funcs)
{
    for (; funcs->name != nullptr; ++funcs) {
        lua_pushcfunction(L, funcs->func);
        lua_setfield(L, -2, funcs->name);
    }
}

void *testudata(lua_State *L, int idx, const char *tname)
{
    void *p = lua_touserdata(L, idx);
    if (p == nullptr || !lua_getmetatable(L, idx)) {
        return nullptr;
    }
    luaL_getmetatable(L, tname);
    const bool same = lua_rawequal(L, -1, -2);
    lua_pop(L, 2);
    return same ? p : nullptr;
}

void *newuserdata(lua_State *L, size_t size)
{
#if LUA_VERSION_NUM >= 504
    return lua_newuserdatauv(L, size, 1);
#else
    return lua_newuserdata(L, size);
#endif
}

// Pops a table and makes it the user value of the userdata at `idx`.
void setuservalue(lua_State *L, int idx)
{
    idx = absindex(L, idx);
#if LUA_VERSION_NUM >= 504
    lua_setiuservalue(L, idx, 1);
#elif LUA_VERSION_NUM >= 502
    lua_setuservalue(L, idx);
#else
    lua_setfenv(L, idx);
#endif
}

void getuservalue(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 504
    lua_getiuservalue(L, idx, 1);
#elif LUA_VERSION_NUM >= 502
    lua_getuservalue(L, idx);
#else
    lua_getfenv(L, idx);
#endif
}

} // namespace compat

//////////////////////////////////////////////////
// error handling
//

// Returned by a `guarded()` body when it has pushed an error value that should be raised.
constexpr int raise_pushed_error = -1;

// Runs `body`, converting C++ exceptions into Lua errors. Errors are raised after `body` has
// returned, so its locals are destroyed first.
template <class F>
int guarded(lua_State *L, F &&body)
{
    char message[512] = "";
    int results = 0;
    try {
        results = body();
    }
    catch (const std::exception &e) {
        std::snprintf(message, sizeof(message), "sigmatch: %s", e.what());
        results = raise_pushed_error - 1;
    }

    if (results == raise_pushed_error - 1) {
        return luaL_error(L, "%s", message);
    }
    if (results == raise_pushed_error) {
        return lua_error(L);
    }
    return results;
}

[[noreturn]] void type_error(lua_State *L, int idx, const char *expected)
{
    luaL_argerror(L, idx, lua_pushfstring(L, "%s expected, got %s", expected, luaL_typename(L, idx)));
    std::abort(); // unreachable, luaL_argerror does not return
}

const char *error_text(lua_State *L, int idx)
{
    const char *text = lua_tostring(L, idx);
    return text != nullptr ? text : "(error object is not a string)";
}

//////////////////////////////////////////////////
// numbers
//

void push_unsigned(lua_State *L, uint64_t value)
{
#if LUA_VERSION_NUM >= 503
    lua_pushinteger(L, static_cast<lua_Integer>(value));
#else
    lua_pushnumber(L, static_cast<lua_Number>(value));
#endif
}

void push_address(lua_State *L, const void *address)
{
    push_unsigned(L, reinterpret_cast<uintptr_t>(address));
}

// A non-negative integral number, or nothing.
std::optional<uint64_t> to_unsigned(lua_State *L, int idx)
{
    if (lua_type(L, idx) != LUA_TNUMBER) {
        return std::nullopt;
    }
#if LUA_VERSION_NUM >= 503
    if (lua_isinteger(L, idx)) {
        const lua_Integer value = lua_tointeger(L, idx);
        if (value < 0) {
            return std::nullopt;
        }
        return static_cast<uint64_t>(value);
    }
#endif
    const lua_Number value = lua_tonumber(L, idx);
    if (!(value >= 0) || value >= 18446744073709551616.0 || std::floor(value) != value) {
        return std::nullopt;
    }
    return static_cast<uint64_t>(value);
}

uint64_t check_unsigned(lua_State *L, int idx, uint64_t max, const char *what)
{
    const auto value = to_unsigned(L, idx);
    if (!value.has_value() || value.value() > max) {
        if (lua_type(L, idx) != LUA_TNUMBER) {
            type_error(L, idx, what);
        }
        luaL_argerror(L, idx, lua_pushfstring(L, "%s out of range", what));
    }
    return value.value();
}

// An address is an integer (as returned by searches) or a light userdata.
uintptr_t check_address(lua_State *L, int idx)
{
    if (lua_islightuserdata(L, idx)) {
        return reinterpret_cast<uintptr_t>(lua_touserdata(L, idx));
    }
#if LUA_VERSION_NUM >= 503
    if (lua_isinteger(L, idx)) {
        // Wraps like `push_unsigned()` does for addresses above the lua_Integer range.
        return static_cast<uintptr_t>(lua_tointeger(L, idx));
    }
#endif
    return static_cast<uintptr_t>(
        check_unsigned(L, idx, std::numeric_limits<uintptr_t>::max(), "address"));
}

size_t check_size(lua_State *L, int idx, const char *what = "size")
{
    return static_cast<size_t>(check_unsigned(L, idx, std::numeric_limits<size_t>::max(), what));
}

// `nil` (or nothing) selects sigmatch's default value.
sigmatch::allow_default<size_t> opt_size(lua_State *L, int idx, const char *what)
{
    if (lua_isnoneornil(L, idx)) {
        return sigmatch::default_value;
    }
    return check_size(L, idx, what);
}

//////////////////////////////////////////////////
// userdata types
//

struct signature_box
{
    sigmatch::signature sig;
};

struct sig_byte_box
{
    sigmatch::sig_byte byte;
};

struct result_box
{
    sigmatch::search_result result;
};

struct reader_box
{
    std::shared_ptr<sigmatch::reader> reader;
};

enum class target_kind : int
{
    this_process,
    external_process,
    file,
    access_memory,
    access_file,
};

constexpr const char *target_kind_names[] = {
    "this_process_target", "external_process_target", "file_target", "access_memory_target",
    "access_file_target",
};

struct target_box
{
    std::shared_ptr<sigmatch::target> target;
    target_kind kind;
};

struct context_box
{
    sigmatch::search_context context;
    std::shared_ptr<sigmatch::reader> reader; // the reader of `context`, which keeps it private
};

using blocking_executor = sigmatch::search_context::executor<sigmatch::blocking_searcher>;
using multi_threaded_executor =
    sigmatch::search_context::executor<sigmatch::multi_threaded_searcher>;

struct executor_box
{
    std::variant<std::monostate, blocking_executor, multi_threaded_executor> executor;
    std::shared_ptr<sigmatch::reader> reader;
};

struct searcher_box
{
    std::variant<std::monostate, sigmatch::blocking_searcher, sigmatch::multi_threaded_searcher>
        searcher;
};

template <class T>
struct udata;

#define LUA_SIGMATCH_UDATA(type, tname)                                                            \
    template <>                                                                                    \
    struct udata<type>                                                                             \
    {                                                                                              \
        static constexpr const char *name = tname;                                                 \
    }

LUA_SIGMATCH_UDATA(signature_box, "sigmatch.signature");
LUA_SIGMATCH_UDATA(sig_byte_box, "sigmatch.sig_byte");
LUA_SIGMATCH_UDATA(result_box, "sigmatch.search_result");
LUA_SIGMATCH_UDATA(reader_box, "sigmatch.reader");
LUA_SIGMATCH_UDATA(target_box, "sigmatch.target");
LUA_SIGMATCH_UDATA(context_box, "sigmatch.search_context");
LUA_SIGMATCH_UDATA(executor_box, "sigmatch.executor");
LUA_SIGMATCH_UDATA(searcher_box, "sigmatch.searcher");

// Registry key of the wildcard placeholder
constexpr const char *wildcard_key = "sigmatch._";

template <class T, class... ArgsT>
T *push_object(lua_State *L, ArgsT &&...args)
{
    // Lua 5.1 and LuaJIT only guarantee 8-byte alignment for userdata.
    static_assert(alignof(T) <= 8);

    void *memory = compat::newuserdata(L, sizeof(T));
    T *object = new (memory) T{std::forward<ArgsT>(args)...};
    luaL_getmetatable(L, udata<T>::name);
    lua_setmetatable(L, -2);
    return object;
}

template <class T>
T *test_object(lua_State *L, int idx)
{
    return static_cast<T *>(compat::testudata(L, idx, udata<T>::name));
}

template <class T>
T *check_object(lua_State *L, int idx)
{
    T *object = test_object<T>(L, idx);
    if (object == nullptr) {
        type_error(L, idx, udata<T>::name);
    }
    return object;
}

template <class T>
int gc_object(lua_State *L)
{
    if (T *object = test_object<T>(L, 1)) {
        object->~T();
    }
    return 0;
}

// Makes the userdata on the top of the stack share the user value table of the one at `from`.
void share_uservalue(lua_State *L, int from)
{
    compat::getuservalue(L, from);
    compat::setuservalue(L, -2);
}

// Gives the userdata on the top of the stack a new user value table, holding the reader userdata
// at `reader_idx` (if not 0) so that it lives as long as the object using it.
void set_reader_uservalue(lua_State *L, int reader_idx)
{
    lua_newtable(L);
    if (reader_idx != 0) {
        lua_pushvalue(L, reader_idx);
        lua_setfield(L, -2, "reader");
    }
    compat::setuservalue(L, -2);
}

bool is_wildcard(lua_State *L, int idx)
{
    idx = compat::absindex(L, idx);
    lua_getfield(L, LUA_REGISTRYINDEX, wildcard_key);
    const bool result = lua_rawequal(L, idx, -1);
    lua_pop(L, 1);
    return result;
}

//////////////////////////////////////////////////
// Lua readers
//

// Calls `impl:<method>(args...)` with stack = [impl, method name, args...]. A function `impl` is
// called as `impl(args...)` for "read". Missing methods return nil.
int call_reader_method(lua_State *L)
{
    const int nargs = lua_gettop(L) - 2;

    if (lua_isfunction(L, 1)) {
        if (std::strcmp(lua_tostring(L, 2), "read") != 0) {
            return 0;
        }
        lua_remove(L, 2);
        lua_call(L, nargs, 1);
        return 1;
    }

    lua_getfield(L, 1, lua_tostring(L, 2));
    if (lua_isnil(L, -1)) {
        return 0;
    }
    lua_insert(L, 1);
    lua_remove(L, 3);
    lua_call(L, nargs + 1, 1);
    return 1;
}

// A reader implemented in Lua by a `read` function or an object with `read` / `error` methods.
//
// It can only call into Lua while a binding function that searches (or otherwise uses the reader)
// is running, on that thread, see `reader_activation`. Errors raised by the callbacks are recorded
// and raised again once that binding function is done with C++.
class lua_reader final : public sigmatch::reader
{
public:
    explicit lua_reader(int ref) noexcept : _ref{ref} {}

    [[nodiscard]] std::optional<std::string> error() const override
    {
        if (_ref == LUA_NOREF) {
            return "The Lua reader has been garbage collected.";
        }
        if (!usable()) {
            return "The Lua reader can only be used from the Lua thread that started the search.";
        }
        if (!_failure.empty()) {
            return _failure;
        }

        lua_State *L = _L;
        if (!lua_checkstack(L, 4)) {
            fail("Lua reader: stack overflow");
            return _failure;
        }

        const int top = lua_gettop(L);
        lua_pushcfunction(L, call_reader_method);
        lua_rawgeti(L, LUA_REGISTRYINDEX, _ref);
        lua_pushliteral(L, "error");

        std::optional<std::string> result;
        if (lua_pcall(L, 2, 1, 0) != 0) {
            fail(std::format("Lua reader: {}", error_text(L, -1)));
            result = _failure;
        }
        else if (lua_type(L, -1) == LUA_TSTRING) {
            size_t length = 0;
            const char *text = lua_tolstring(L, -1, &length);
            result.emplace(text, length);
        }
        else if (!lua_isnil(L, -1) && !(lua_isboolean(L, -1) && !lua_toboolean(L, -1))) {
            fail(std::format(
                "Lua reader: error() must return nil, false or a string, got {}",
                luaL_typename(L, -1)));
            result = _failure;
        }
        lua_settop(L, top);
        return result;
    }

    [[nodiscard]] bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const override
    {
        if (!usable() || !_failure.empty()) {
            return false;
        }

        lua_State *L = _L;
        if (!lua_checkstack(L, 6)) {
            fail("Lua reader: stack overflow");
            return false;
        }

        const int top = lua_gettop(L);
        lua_pushcfunction(L, call_reader_method);
        lua_rawgeti(L, LUA_REGISTRYINDEX, _ref);
        lua_pushliteral(L, "read");
        push_address(L, address);
        push_unsigned(L, size);

        bool succeeded = false;
        if (lua_pcall(L, 4, 1, 0) != 0) {
            fail(std::format("Lua reader: {}", error_text(L, -1)));
        }
        else if (lua_type(L, -1) == LUA_TSTRING) {
            size_t length = 0;
            const char *data = lua_tolstring(L, -1, &length);
            if (length == size) {
                result.resize(size);
                std::memcpy(result.data(), data, size);
                succeeded = true;
            }
            else if (length > size) {
                fail(std::format(
                    "Lua reader: read() returned {} bytes but {} were requested", length, size));
            }
            // A shorter string is a failed (partial) read, like a native reader reports it.
        }
        else if (!lua_isnil(L, -1) && !(lua_isboolean(L, -1) && !lua_toboolean(L, -1))) {
            fail(std::format(
                "Lua reader: read() must return a string, nil or false, got {}",
                luaL_typename(L, -1)));
        }
        lua_settop(L, top);
        return succeeded;
    }

    void release(lua_State *L) noexcept
    {
        luaL_unref(L, LUA_REGISTRYINDEX, _ref);
        _ref = LUA_NOREF;
    }

private:
    friend class reader_activation;

    int _ref;
    mutable lua_State *_L{nullptr};
    mutable std::thread::id _thread;
    mutable std::string _failure; // the first error raised by a callback

    [[nodiscard]] bool usable() const noexcept
    {
        return _L != nullptr && _ref != LUA_NOREF && std::this_thread::get_id() == _thread;
    }

    void fail(std::string message) const
    {
        if (_failure.empty()) {
            _failure = std::move(message);
        }
    }
};

bool is_lua_reader(const std::shared_ptr<sigmatch::reader> &reader) noexcept
{
    return dynamic_cast<const lua_reader *>(reader.get()) != nullptr;
}

// Lets a Lua reader call into `L` while in scope. Nesting (a reader callback that searches with
// the same reader) restores the outer state on exit.
class reader_activation
{
public:
    reader_activation(lua_State *L, const std::shared_ptr<sigmatch::reader> &reader) noexcept
        : _reader{dynamic_cast<lua_reader *>(reader.get())}
    {
        if (_reader != nullptr) {
            _saved_L = std::exchange(_reader->_L, L);
            _saved_thread = std::exchange(_reader->_thread, std::this_thread::get_id());
            _saved_failure = std::exchange(_reader->_failure, std::string{});
        }
    }

    reader_activation(const reader_activation &) = delete;
    reader_activation &operator=(const reader_activation &) = delete;

    ~reader_activation()
    {
        if (_reader != nullptr) {
            _reader->_L = _saved_L;
            _reader->_thread = _saved_thread;
            _reader->_failure = std::move(_saved_failure);
        }
    }

    // Pushes the error raised by a reader callback, if any.
    [[nodiscard]] bool push_failure(lua_State *L) const
    {
        if (_reader == nullptr || _reader->_failure.empty()) {
            return false;
        }
        lua_pushlstring(L, _reader->_failure.data(), _reader->_failure.size());
        return true;
    }

private:
    lua_reader *_reader;
    lua_State *_saved_L{nullptr};
    std::thread::id _saved_thread;
    std::string _saved_failure;
};

//////////////////////////////////////////////////
// sig_byte
//

void format_sig_byte(const sigmatch::sig_byte &byte, char (&out)[11])
{
    static constexpr char hex[] = "0123456789ABCDEF";
    const auto value = std::to_integer<unsigned>(byte.value());
    const auto mask = std::to_integer<unsigned>(byte.mask());

    switch (mask) {
    case 0xFF:
        out[0] = hex[value >> 4], out[1] = hex[value & 0xF], out[2] = '\0';
        break;
    case 0xF0:
        out[0] = hex[value >> 4], out[1] = '?', out[2] = '\0';
        break;
    case 0x0F:
        out[0] = '?', out[1] = hex[value & 0xF], out[2] = '\0';
        break;
    case 0x00:
        out[0] = '?', out[1] = '?', out[2] = '\0';
        break;
    default: // Ghidra format
        out[0] = '[';
        for (int bit = 0; bit < 8; ++bit) {
            const unsigned flag = 0x80u >> bit;
            out[bit + 1] = (mask & flag) == 0 ? '.' : (value & flag) != 0 ? '1' : '0';
        }
        out[9] = ']', out[10] = '\0';
        break;
    }
}

// Builds a sig_byte from one or two Lua values, mirroring the C++ constructors:
//   value | value, mask | high, _ | _, low | _ | "token" (e.g. "1A", "?F", "[01..1...]")
sigmatch::sig_byte make_sig_byte(lua_State *L, int first, int second, const char *what)
{
    const auto byte_value = [&](int idx, unsigned max) {
        const auto value = to_unsigned(L, idx);
        if (!value.has_value() || value.value() > max) {
            luaL_error(L, "bad %s (integer in [0, %d] expected)", what, static_cast<int>(max));
        }
        return static_cast<unsigned char>(value.value());
    };

    if (second == 0) {
        if (is_wildcard(L, first)) {
            return sigmatch::_;
        }
        if (const auto *box = test_object<sig_byte_box>(L, first)) {
            return box->byte;
        }
        if (lua_type(L, first) == LUA_TSTRING) {
            size_t length = 0;
            const char *token = lua_tolstring(L, first, &length);
            const auto byte = length == 0 ? std::nullopt
                                          : sigmatch::impl::parse_sig_byte({token, length});
            if (!byte.has_value()) {
                luaL_error(L, "bad %s (invalid token '%s')", what, token);
            }
            return byte.value();
        }
        return sigmatch::sig_byte{byte_value(first, 0xFF)};
    }

    const bool first_wildcard = is_wildcard(L, first), second_wildcard = is_wildcard(L, second);
    if (first_wildcard && second_wildcard) {
        luaL_error(L, "bad %s (only one half can be a wildcard, use sigmatch._ alone)", what);
    }
    if (first_wildcard) {
        return sigmatch::sig_byte{sigmatch::_, byte_value(second, 0xF)};
    }
    if (second_wildcard) {
        return sigmatch::sig_byte{byte_value(first, 0xF), sigmatch::_};
    }

    const auto value = byte_value(first, 0xFF), mask = byte_value(second, 0xFF);
    if ((value & ~mask & 0xFF) != 0) {
        // C++ accepts it, but such a byte can never match anything.
        char message[96];
        std::snprintf(
            message, sizeof(message), "bad %s (value 0x%02X has bits outside mask 0x%02X)", what,
            value, mask);
        luaL_error(L, "%s", message);
    }
    return sigmatch::sig_byte{value, mask};
}

int sig_byte_new(lua_State *L)
{
    lua_remove(L, 1); // called through __call
    if (lua_isnoneornil(L, 1)) {
        type_error(L, 1, "integer, string, sigmatch._ or sig_byte");
    }
    const auto byte = make_sig_byte(L, 1, lua_isnoneornil(L, 2) ? 0 : 2, "sig_byte");
    push_object<sig_byte_box>(L, byte);
    return 1;
}

int sig_byte_value(lua_State *L)
{
    push_unsigned(L, std::to_integer<unsigned>(check_object<sig_byte_box>(L, 1)->byte.value()));
    return 1;
}

int sig_byte_mask(lua_State *L)
{
    push_unsigned(L, std::to_integer<unsigned>(check_object<sig_byte_box>(L, 1)->byte.mask()));
    return 1;
}

int sig_byte_match(lua_State *L)
{
    const auto *box = check_object<sig_byte_box>(L, 1);
    const auto value = static_cast<unsigned char>(check_unsigned(L, 2, 0xFF, "byte"));
    lua_pushboolean(L, box->byte.match(value));
    return 1;
}

int sig_byte_eq(lua_State *L)
{
    const auto *lhs = test_object<sig_byte_box>(L, 1), *rhs = test_object<sig_byte_box>(L, 2);
    lua_pushboolean(L, lhs != nullptr && rhs != nullptr && lhs->byte == rhs->byte);
    return 1;
}

int sig_byte_tostring(lua_State *L)
{
    char text[11];
    format_sig_byte(check_object<sig_byte_box>(L, 1)->byte, text);
    lua_pushstring(L, text);
    return 1;
}

//////////////////////////////////////////////////
// signature
//

void describe_signature_error(std::string_view text, char *buffer, size_t size)
{
    const auto tokens = sigmatch::impl::string_split(text, " ");
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!sigmatch::impl::parse_sig_byte(tokens[i]).has_value()) {
            std::snprintf(
                buffer, size, "bad byte '%.*s' at position %zu",
                static_cast<int>((std::min)(tokens[i].size(), size_t{32})), tokens[i].data(),
                i + 1);
            return;
        }
    }
    std::snprintf(buffer, size, "malformed signature");
}

// Parses at runtime. Tabs and line breaks count as spaces.
std::optional<sigmatch::signature>
parse_signature(std::string_view text, char *error, size_t error_size)
{
    std::string normalized{text};
    std::replace_if(
        normalized.begin(), normalized.end(),
        [](char ch) { return ch == '\t' || ch == '\r' || ch == '\n'; }, ' ');

    auto sig = sigmatch::signature::parse(normalized);
    if (!sig.has_value()) {
        describe_signature_error(normalized, error, error_size);
    }
    return sig;
}

sigmatch::signature signature_from_string(lua_State *L, int idx)
{
    size_t length = 0;
    const char *text = lua_tolstring(L, idx, &length);

    char error[128] = "";
    std::optional<sigmatch::signature> sig = parse_signature({text, length}, error, sizeof(error));
    if (!sig.has_value()) {
        // `sig` is empty, nothing is leaked if the error longjmp()s.
        luaL_error(L, "invalid signature: %s", error);
    }
    return std::move(sig.value());
}

sigmatch::signature signature_from_table(lua_State *L, int idx)
{
    idx = compat::absindex(L, idx);
    const size_t count = compat::rawlen(L, idx);

    const auto element = [&](size_t i) {
        char what[48];
        std::snprintf(what, sizeof(what), "signature byte #%zu", i);

        lua_rawgeti(L, idx, static_cast<int>(i));
        sigmatch::sig_byte byte = sigmatch::_;
        if (lua_type(L, -1) == LUA_TTABLE && !is_wildcard(L, -1)) {
            if (compat::rawlen(L, -1) != 2) {
                luaL_error(L, "bad %s (a table needs exactly 2 elements)", what);
            }
            lua_rawgeti(L, -1, 1);
            lua_rawgeti(L, -2, 2);
            byte = make_sig_byte(L, compat::absindex(L, -2), compat::absindex(L, -1), what);
            lua_pop(L, 2);
        }
        else if (lua_isnil(L, -1)) {
            luaL_error(L, "bad %s (got nil)", what);
        }
        else {
            byte = make_sig_byte(L, compat::absindex(L, -1), 0, what);
        }
        lua_pop(L, 1);
        return byte;
    };

    // Validate first: the second pass cannot raise errors while the vector is alive.
    for (size_t i = 1; i <= count; ++i) {
        element(i);
    }

    std::vector<sigmatch::sig_byte> bytes;
    bytes.reserve(count);
    for (size_t i = 1; i <= count; ++i) {
        bytes.emplace_back(element(i));
    }
    return sigmatch::signature{std::move(bytes)};
}

// Accepts a signature, a signature string or a byte table. Strings and tables are converted in
// place, the stack slot then holds the new signature userdata, keeping it alive.
const sigmatch::signature &check_signature(lua_State *L, int idx)
{
    idx = compat::absindex(L, idx);
    if (const auto *box = test_object<signature_box>(L, idx)) {
        return box->sig;
    }

    const int type = lua_type(L, idx);
    if (type != LUA_TSTRING && type != LUA_TTABLE) {
        type_error(L, idx, "signature, string or table");
    }

    auto *box = push_object<signature_box>(L);
    box->sig = type == LUA_TSTRING ? signature_from_string(L, idx) : signature_from_table(L, idx);
    lua_replace(L, idx);
    return box->sig;
}

int signature_new(lua_State *L)
{
    lua_remove(L, 1); // called through __call
    if (lua_isnoneornil(L, 1)) {
        push_object<signature_box>(L);
        return 1;
    }
    if (const auto *box = test_object<signature_box>(L, 1)) {
        push_object<signature_box>(L, box->sig);
        return 1;
    }
    check_signature(L, 1);
    lua_settop(L, 1);
    return 1;
}

// signature.parse(text) -> signature | nil, message
int signature_parse(lua_State *L)
{
    size_t length = 0;
    const char *text = luaL_checklstring(L, 1, &length);

    auto *box = push_object<signature_box>(L);
    char error[128] = "";
    bool parsed = false;
    {
        auto sig = parse_signature({text, length}, error, sizeof(error));
        if (sig.has_value()) {
            box->sig = std::move(sig.value());
            parsed = true;
        }
    }
    if (!parsed) {
        lua_pushnil(L);
        lua_pushfstring(L, "invalid signature: %s", error);
        return 2;
    }
    return 1;
}

int signature_size(lua_State *L)
{
    push_unsigned(L, check_object<signature_box>(L, 1)->sig.size());
    return 1;
}

int signature_bytes(lua_State *L)
{
    const auto &bytes = check_object<signature_box>(L, 1)->sig.bytes();
    lua_createtable(L, static_cast<int>(bytes.size()), 0);
    for (size_t i = 0; i < bytes.size(); ++i) {
        push_object<sig_byte_box>(L, bytes[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
}

int signature_index(lua_State *L)
{
    const auto *box = check_object<signature_box>(L, 1);
    if (lua_type(L, 2) == LUA_TNUMBER) {
        const auto i = to_unsigned(L, 2);
        if (i.has_value() && i.value() >= 1 && i.value() <= box->sig.size()) {
            push_object<sig_byte_box>(L, box->sig.bytes()[i.value() - 1]);
        }
        else {
            lua_pushnil(L);
        }
        return 1;
    }
    lua_pushvalue(L, 2);
    lua_rawget(L, lua_upvalueindex(1));
    return 1;
}

int signature_eq(lua_State *L)
{
    const auto *lhs = test_object<signature_box>(L, 1), *rhs = test_object<signature_box>(L, 2);
    lua_pushboolean(L, lhs != nullptr && rhs != nullptr && lhs->sig == rhs->sig);
    return 1;
}

int signature_tostring(lua_State *L)
{
    const auto &bytes = check_object<signature_box>(L, 1)->sig.bytes();
    luaL_Buffer buffer;
    luaL_buffinit(L, &buffer);
    for (size_t i = 0; i < bytes.size(); ++i) {
        char text[11];
        format_sig_byte(bytes[i], text);
        if (i != 0) {
            luaL_addchar(&buffer, ' ');
        }
        luaL_addstring(&buffer, text);
    }
    luaL_pushresult(&buffer);
    return 1;
}

//////////////////////////////////////////////////
// search_result
//

void push_strings(lua_State *L, const std::vector<std::string> &strings)
{
    lua_createtable(L, static_cast<int>(strings.size()), 0);
    for (size_t i = 0; i < strings.size(); ++i) {
        lua_pushlstring(L, strings[i].data(), strings[i].size());
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
}

int result_new(lua_State *L)
{
    push_object<result_box>(L);
    return 1;
}

int result_make_error(lua_State *L)
{
    size_t length = 0;
    const char *message = luaL_checklstring(L, 1, &length);
    auto *box = push_object<result_box>(L);
    return guarded(L, [&] {
        box->result = sigmatch::search_result::make_error({message, length});
        return 1;
    });
}

int result_make_warning(lua_State *L)
{
    size_t length = 0;
    const char *message = luaL_checklstring(L, 1, &length);
    auto *box = push_object<result_box>(L);
    return guarded(L, [&] {
        box->result = sigmatch::search_result::make_warning({message, length});
        return 1;
    });
}

int result_matches(lua_State *L)
{
    const auto &matches = check_object<result_box>(L, 1)->result.matches();
    lua_createtable(L, static_cast<int>(matches.size()), 0);
    for (size_t i = 0; i < matches.size(); ++i) {
        push_address(L, matches[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
}

int result_error_messages(lua_State *L)
{
    push_strings(L, check_object<result_box>(L, 1)->result.error_messages());
    return 1;
}

int result_warning_messages(lua_State *L)
{
    push_strings(L, check_object<result_box>(L, 1)->result.warning_messages());
    return 1;
}

int result_has_error(lua_State *L)
{
    lua_pushboolean(L, check_object<result_box>(L, 1)->result.has_error());
    return 1;
}

int result_has_warning(lua_State *L)
{
    lua_pushboolean(L, check_object<result_box>(L, 1)->result.has_warning());
    return 1;
}

int result_len(lua_State *L)
{
    push_unsigned(L, check_object<result_box>(L, 1)->result.matches().size());
    return 1;
}

int result_index(lua_State *L)
{
    const auto *box = check_object<result_box>(L, 1);
    if (lua_type(L, 2) == LUA_TNUMBER) {
        const auto &matches = box->result.matches();
        const auto i = to_unsigned(L, 2);
        if (i.has_value() && i.value() >= 1 && i.value() <= matches.size()) {
            push_address(L, matches[i.value() - 1]);
        }
        else {
            lua_pushnil(L);
        }
        return 1;
    }
    lua_pushvalue(L, 2);
    lua_rawget(L, lua_upvalueindex(1));
    return 1;
}

int result_eq(lua_State *L)
{
    const auto *lhs = test_object<result_box>(L, 1), *rhs = test_object<result_box>(L, 2);
    lua_pushboolean(L, lhs != nullptr && rhs != nullptr && lhs->result == rhs->result);
    return 1;
}

int result_tostring(lua_State *L)
{
    const auto &result = check_object<result_box>(L, 1)->result;
    lua_pushfstring(
        L, "sigmatch.search_result (%d matches, %d errors, %d warnings)",
        static_cast<int>(result.matches().size()), static_cast<int>(result.error_messages().size()),
        static_cast<int>(result.warning_messages().size()));
    return 1;
}

//////////////////////////////////////////////////
// ranges
//

// Reads `address, size` (two arguments) or a list of `{address, size}` / `{address = ...,
// size = ...}` entries (one argument) at `idx`, into `out` if given. Returns the index of the
// argument after the range(s). Errors are raised only when `out` is null, so validate first.
int check_ranges(lua_State *L, int idx, std::vector<sigmatch::const_byte_span> *out)
{
    const auto add = [&](int address_idx, int size_idx) {
        const uintptr_t address = check_address(L, address_idx);
        const size_t size = check_size(L, size_idx);
        if (size > std::numeric_limits<uintptr_t>::max() - address) {
            luaL_argerror(L, size_idx, "range exceeds the address space");
        }
        if (out != nullptr) {
            out->emplace_back(reinterpret_cast<const void *>(address), size);
        }
    };

    if (lua_type(L, idx) != LUA_TTABLE) {
        add(idx, idx + 1);
        return idx + 2;
    }

    const size_t count = compat::rawlen(L, idx);
    if (out != nullptr) {
        out->reserve(count);
    }
    for (size_t i = 1; i <= count; ++i) {
        lua_rawgeti(L, idx, static_cast<int>(i));
        if (lua_type(L, -1) != LUA_TTABLE) {
            luaL_argerror(L, idx, lua_pushfstring(L, "range #%d is not a table", static_cast<int>(i)));
        }
        lua_rawgeti(L, -1, 1);
        if (!lua_isnil(L, -1)) {
            lua_rawgeti(L, -2, 2);
        }
        else {
            lua_pop(L, 1);
            lua_pushliteral(L, "address");
            lua_rawget(L, -2);
            lua_pushliteral(L, "size");
            lua_rawget(L, -3);
        }
        add(compat::absindex(L, -2), compat::absindex(L, -1));
        lua_pop(L, 3);
    }
    return idx + 1;
}

//////////////////////////////////////////////////
// readers
//

int new_reader(lua_State *L, std::shared_ptr<sigmatch::reader> reader)
{
    push_object<reader_box>(L, std::move(reader));
    return 1;
}

std::filesystem::path to_path(lua_State *L, int idx)
{
    size_t length = 0;
    const char *text = luaL_checklstring(L, idx, &length);
    // UTF-8 on every platform (a plain `std::string` would be the ANSI code page on Windows)
    return std::filesystem::path{std::u8string{text, text + length}};
}

sigmatch::process_id check_pid(lua_State *L, int idx)
{
    return static_cast<sigmatch::process_id>(
        check_unsigned(L, idx, std::numeric_limits<sigmatch::process_id>::max(), "process id"));
}

int reader_this_process(lua_State *L)
{
    return guarded(
        L, [&] { return new_reader(L, std::make_shared<sigmatch::this_process_memory_reader>()); });
}

int reader_external_process(lua_State *L)
{
    const auto pid = check_pid(L, 1);
    return guarded(L, [&] {
        return new_reader(L, std::make_shared<sigmatch::external_process_memory_reader>(pid));
    });
}

int reader_file_content(lua_State *L)
{
    luaL_checkstring(L, 1);
    return guarded(L, [&] {
        return new_reader(L, std::make_shared<sigmatch::file_content_reader>(to_path(L, 1)));
    });
}

// sigmatch.reader(impl): `impl` is a function `read(address, size)` or an object with methods
// `impl:read(address, size)` and, optionally, `impl:error()`.
int reader_lua(lua_State *L)
{
    const int type = lua_type(L, 1);
    if (type != LUA_TFUNCTION && type != LUA_TTABLE && type != LUA_TUSERDATA) {
        type_error(L, 1, "function or object with a read method");
    }
    if (type != LUA_TFUNCTION) {
        lua_getfield(L, 1, "read");
        if (lua_isnil(L, -1)) {
            luaL_argerror(L, 1, "the reader object has no 'read' method");
        }
        lua_pop(L, 1);
    }

    lua_settop(L, 1);
    const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    return guarded(L, [&] {
        std::shared_ptr<sigmatch::reader> reader;
        try {
            reader = std::make_shared<lua_reader>(ref);
        }
        catch (const std::exception &) {
            luaL_unref(L, LUA_REGISTRYINDEX, ref);
            throw;
        }
        return new_reader(L, std::move(reader));
    });
}

int reader_gc(lua_State *L)
{
    if (auto *box = test_object<reader_box>(L, 1)) {
        // Every object using a Lua reader holds its userdata (in its user value), so when the
        // userdata is collected, they are unreachable too.
        if (auto *reader = dynamic_cast<lua_reader *>(box->reader.get())) {
            reader->release(L);
        }
        box->~reader_box();
    }
    return 0;
}

int reader_error(lua_State *L)
{
    auto *box = check_object<reader_box>(L, 1);
    return guarded(L, [&] {
        reader_activation activation{L, box->reader};
        const auto error = box->reader->error();
        if (activation.push_failure(L)) {
            return raise_pushed_error;
        }
        if (error.has_value()) {
            lua_pushlstring(L, error->data(), error->size());
        }
        else {
            lua_pushnil(L);
        }
        return 1;
    });
}

// reader:read(address, size) -> string | nil
int reader_read(lua_State *L)
{
    auto *box = check_object<reader_box>(L, 1);
    const auto address = check_address(L, 2);
    const auto size = check_size(L, 3);
    return guarded(L, [&] {
        bool succeeded = false;
        {
            std::vector<std::byte> buffer;
            reader_activation activation{L, box->reader};
            succeeded = box->reader->read(reinterpret_cast<const void *>(address), size, buffer);
            if (activation.push_failure(L)) {
                return raise_pushed_error;
            }
            if (succeeded) {
                lua_pushlstring(L, reinterpret_cast<const char *>(buffer.data()), buffer.size());
            }
        }
        if (!succeeded) {
            lua_pushnil(L);
        }
        return 1;
    });
}

int reader_tostring(lua_State *L)
{
    const auto *reader = check_object<reader_box>(L, 1)->reader.get();
    const char *kind = "reader";
    if (dynamic_cast<const sigmatch::this_process_memory_reader *>(reader) != nullptr) {
        kind = "this_process_memory_reader";
    }
    else if (dynamic_cast<const sigmatch::external_process_memory_reader *>(reader) != nullptr) {
        kind = "external_process_memory_reader";
    }
    else if (dynamic_cast<const sigmatch::file_content_reader *>(reader) != nullptr) {
        kind = "file_content_reader";
    }
    else if (dynamic_cast<const lua_reader *>(reader) != nullptr) {
        kind = "lua reader";
    }
    lua_pushfstring(L, "sigmatch.reader (%s)", kind);
    return 1;
}

//////////////////////////////////////////////////
// targets
//

// Index of an optional reader argument (0 if absent).
int opt_reader_index(lua_State *L, int idx)
{
    if (lua_isnoneornil(L, idx)) {
        return 0;
    }
    check_object<reader_box>(L, idx);
    return idx;
}

std::shared_ptr<sigmatch::reader> reader_at(lua_State *L, int idx)
{
    return idx != 0 ? check_object<reader_box>(L, idx)->reader : nullptr;
}

sigmatch::allow_default<std::shared_ptr<sigmatch::reader>> default_if_null(
    std::shared_ptr<sigmatch::reader> reader)
{
    if (!reader) {
        return sigmatch::default_value;
    }
    return reader;
}

int new_target(
    lua_State *L, std::shared_ptr<sigmatch::target> target, target_kind kind, int reader_idx)
{
    push_object<target_box>(L, std::move(target), kind);
    set_reader_uservalue(L, reader_idx);
    return 1;
}

int target_this_process(lua_State *L)
{
    const int reader_idx = opt_reader_index(L, 1);
    return guarded(L, [&] {
        auto target = std::make_shared<sigmatch::this_process_target>(
            default_if_null(reader_at(L, reader_idx)));
        return new_target(L, std::move(target), target_kind::this_process, reader_idx);
    });
}

int target_external_process(lua_State *L)
{
    const auto pid = check_pid(L, 1);
    const int reader_idx = opt_reader_index(L, 2);
    return guarded(L, [&] {
        auto target = std::make_shared<sigmatch::external_process_target>(
            pid, default_if_null(reader_at(L, reader_idx)));
        return new_target(L, std::move(target), target_kind::external_process, reader_idx);
    });
}

int target_file(lua_State *L)
{
    luaL_checkstring(L, 1);
    const int reader_idx = opt_reader_index(L, 2);
    return guarded(L, [&] {
        auto target = std::make_shared<sigmatch::file_target>(
            to_path(L, 1), default_if_null(reader_at(L, reader_idx)));
        return new_target(L, std::move(target), target_kind::file, reader_idx);
    });
}

int target_access_memory(lua_State *L)
{
    check_object<reader_box>(L, 1);
    return guarded(L, [&] {
        auto target = std::make_shared<sigmatch::access_memory_target>(reader_at(L, 1));
        return new_target(L, std::move(target), target_kind::access_memory, 1);
    });
}

int target_access_file(lua_State *L)
{
    check_object<reader_box>(L, 1);
    return guarded(L, [&] {
        auto target = std::make_shared<sigmatch::access_file_target>(reader_at(L, 1));
        return new_target(L, std::move(target), target_kind::access_file, 1);
    });
}

template <class T>
T &check_target(lua_State *L, int idx, const char *expected)
{
    auto *box = check_object<target_box>(L, idx);
    auto *target = dynamic_cast<T *>(box->target.get());
    if (target == nullptr) {
        luaL_argerror(
            L, idx,
            lua_pushfstring(
                L, "%s expected, got %s", expected,
                target_kind_names[static_cast<int>(box->kind)]));
    }
    return *target;
}

// Pushes an empty search context that uses the target's reader. The caller fills it in.
context_box *push_target_context(lua_State *L, const sigmatch::target &target)
{
    auto *box = push_object<context_box>(L);
    box->reader = target.reader();
    share_uservalue(L, 1);
    return box;
}

int target_error(lua_State *L)
{
    const auto &target = check_target<sigmatch::target>(L, 1, "target");
    return guarded(L, [&] {
        reader_activation activation{L, target.reader()};
        const auto error = target.error();
        if (activation.push_failure(L)) {
            return raise_pushed_error;
        }
        if (error.has_value()) {
            lua_pushlstring(L, error->data(), error->size());
        }
        else {
            lua_pushnil(L);
        }
        return 1;
    });
}

int target_reader(lua_State *L)
{
    const auto &target = check_target<sigmatch::target>(L, 1, "target");
    compat::getuservalue(L, 1);
    lua_getfield(L, -1, "reader");
    if (!lua_isnil(L, -1)) {
        return 1;
    }
    lua_pop(L, 1);
    push_object<reader_box>(L, target.reader());
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, "reader");
    return 1;
}

int target_pid(lua_State *L)
{
    push_unsigned(L, check_target<sigmatch::process_target>(L, 1, "process target").pid());
    return 1;
}

// memory targets: in_range(address, size) | in_range({{address, size}, ...})
int target_in_memory_range(lua_State *L)
{
    const auto &target = check_target<sigmatch::access_memory_target>(L, 1, "memory target");
    check_ranges(L, 2, nullptr);
    auto *box = push_target_context(L, target);
    return guarded(L, [&] {
        std::vector<sigmatch::const_byte_span> ranges;
        check_ranges(L, 2, &ranges);
        box->context = target.in_range(std::move(ranges));
        return 1;
    });
}

// file targets: in_range(offset, size)
int target_in_file_range(lua_State *L)
{
    const auto &target = check_target<sigmatch::access_file_target>(L, 1, "file target");
    const size_t offset = check_size(L, 2, "offset");
    const size_t size = check_size(L, 3);
    auto *box = push_target_context(L, target);
    return guarded(L, [&] {
        box->context = target.in_range(offset, size);
        return 1;
    });
}

// A number of sigmatch.mem_prot flags, or a string of "r", "w", "x" (and "-").
sigmatch::enum_flags<sigmatch::mem_prot> check_prot(lua_State *L, int idx)
{
    if (lua_type(L, idx) == LUA_TSTRING) {
        sigmatch::enum_flags<sigmatch::mem_prot> flags;
        for (const char *ch = lua_tostring(L, idx); *ch != '\0'; ++ch) {
            switch (*ch) {
            case 'r':
                flags |= sigmatch::mem_prot::read;
                break;
            case 'w':
                flags |= sigmatch::mem_prot::write;
                break;
            case 'x':
                flags |= sigmatch::mem_prot::execute;
                break;
            case '-':
                break;
            default:
                luaL_argerror(L, idx, "protection string may only contain 'r', 'w', 'x' and '-'");
            }
        }
        return flags;
    }
    return static_cast<sigmatch::mem_prot>(check_unsigned(L, idx, 0b111, "protection flags"));
}

// in_module(name [, prot])
int target_in_module(lua_State *L)
{
    const auto &target = check_target<sigmatch::process_target>(L, 1, "process target");
    size_t length = 0;
    const char *name = luaL_checklstring(L, 2, &length);
    const bool has_prot = !lua_isnoneornil(L, 3);
    const auto prot = has_prot ? check_prot(L, 3) : sigmatch::enum_flags<sigmatch::mem_prot>{};

    auto *box = push_target_context(L, target);
    return guarded(L, [&] {
        reader_activation activation{L, target.reader()};
        const sigmatch::platform_string module_name{std::string{name, length}};
        box->context = has_prot ? target.in_module(module_name, prot) : target.in_module(module_name);
        if (activation.push_failure(L)) {
            return raise_pushed_error;
        }
        return 1;
    });
}

int target_in_whole(lua_State *L)
{
    const auto &target = check_target<sigmatch::file_target>(L, 1, "file_target");
    auto *box = push_target_context(L, target);
    return guarded(L, [&] {
        reader_activation activation{L, target.reader()};
        box->context = target.in_whole();
        if (activation.push_failure(L)) {
            return raise_pushed_error;
        }
        return 1;
    });
}

int target_index(lua_State *L)
{
    const auto *box = check_object<target_box>(L, 1);
    lua_rawgeti(L, lua_upvalueindex(1), static_cast<int>(box->kind) + 1);
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    return 1;
}

int target_tostring(lua_State *L)
{
    const auto *box = check_object<target_box>(L, 1);
    const char *kind = target_kind_names[static_cast<int>(box->kind)];
    if (const auto *process = dynamic_cast<const sigmatch::process_target *>(box->target.get())) {
        lua_pushfstring(
            L, "sigmatch.%s (pid %d)", kind, static_cast<int>(process->pid()));
    }
    else {
        lua_pushfstring(L, "sigmatch.%s", kind);
    }
    return 1;
}

//////////////////////////////////////////////////
// searchers / executors / search contexts
//

int searcher_blocking(lua_State *L);
int searcher_multi_threaded(lua_State *L);

enum class searcher_type
{
    blocking,
    multi_threaded,
};

// sigmatch.blocking_searcher / sigmatch.multi_threaded_searcher (or their names), nil = blocking
searcher_type check_searcher_type(lua_State *L, int idx)
{
    if (lua_isnoneornil(L, idx)) {
        return searcher_type::blocking;
    }

    if (lua_type(L, idx) == LUA_TSTRING) {
        const std::string_view name = lua_tostring(L, idx);
        if (name == "blocking_searcher" || name == "blocking") {
            return searcher_type::blocking;
        }
        if (name == "multi_threaded_searcher" || name == "multi_threaded") {
            return searcher_type::multi_threaded;
        }
    }
    else if (const lua_CFunction function = lua_tocfunction(L, idx)) {
        if (function == searcher_blocking) {
            return searcher_type::blocking;
        }
        if (function == searcher_multi_threaded) {
            return searcher_type::multi_threaded;
        }
    }
    luaL_argerror(L, idx, "sigmatch.blocking_searcher or sigmatch.multi_threaded_searcher expected");
    return searcher_type::blocking; // unreachable
}

void check_not_lua_reader(lua_State *L, const std::shared_ptr<sigmatch::reader> &reader)
{
    if (is_lua_reader(reader)) {
        luaL_error(
            L, "multi_threaded_searcher cannot be used with a Lua reader, a Lua state can't be "
               "entered from other threads");
    }
}

template <class SearcherT>
const char *searcher_name()
{
    if constexpr (std::is_same_v<SearcherT, sigmatch::multi_threaded_searcher>) {
        return "multi_threaded_searcher";
    }
    else {
        return "blocking_searcher";
    }
}

int searcher_blocking(lua_State *L)
{
    check_object<reader_box>(L, 1);
    const auto block_size = opt_size(L, 2, "block size");
    auto *box = push_object<searcher_box>(L);
    set_reader_uservalue(L, 1);
    return guarded(L, [&] {
        box->searcher.emplace<sigmatch::blocking_searcher>(reader_at(L, 1), block_size);
        return 1;
    });
}

int searcher_multi_threaded(lua_State *L)
{
    check_object<reader_box>(L, 1);
    check_not_lua_reader(L, reader_at(L, 1));
    const auto threads_max_count = opt_size(L, 2, "threads max count");
    const auto block_size = opt_size(L, 3, "block size");
    auto *box = push_object<searcher_box>(L);
    set_reader_uservalue(L, 1);
    return guarded(L, [&] {
        box->searcher.emplace<sigmatch::multi_threaded_searcher>(
            reader_at(L, 1), threads_max_count, block_size);
        return 1;
    });
}

// searcher:search(address, size, sig [, result]) | searcher:search(ranges, sig [, result])
// Appends to `result` if given, returns the result.
int searcher_search(lua_State *L)
{
    auto *box = check_object<searcher_box>(L, 1);
    const int sig_idx = check_ranges(L, 2, nullptr);
    const auto &sig = check_signature(L, sig_idx);

    auto *result = test_object<result_box>(L, sig_idx + 1);
    if (result != nullptr) {
        lua_pushvalue(L, sig_idx + 1);
    }
    else if (lua_isnoneornil(L, sig_idx + 1)) {
        result = push_object<result_box>(L);
    }
    else {
        type_error(L, sig_idx + 1, udata<result_box>::name);
    }

    return guarded(L, [&] {
        std::vector<sigmatch::const_byte_span> ranges;
        check_ranges(L, 2, &ranges);

        return std::visit(
            [&](auto &searcher) {
                using T = std::decay_t<decltype(searcher)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    return 1;
                }
                else {
                    reader_activation activation{L, searcher.reader()};
                    searcher.search(ranges, sig, result->result);
                    return activation.push_failure(L) ? raise_pushed_error : 1;
                }
            },
            box->searcher);
    });
}

int searcher_reader(lua_State *L)
{
    check_object<searcher_box>(L, 1);
    compat::getuservalue(L, 1);
    lua_getfield(L, -1, "reader");
    return 1;
}

int searcher_tostring(lua_State *L)
{
    const auto *box = check_object<searcher_box>(L, 1);
    const char *name = std::visit(
        [](const auto &searcher) {
            using T = std::decay_t<decltype(searcher)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                return "searcher";
            }
            else {
                return searcher_name<T>();
            }
        },
        box->searcher);
    lua_pushfstring(L, "sigmatch.%s", name);
    return 1;
}

// sigmatch.search_context(address, size, reader) | sigmatch.search_context(ranges, reader)
int context_new(lua_State *L)
{
    lua_remove(L, 1); // called through __call
    const int reader_idx = check_ranges(L, 1, nullptr);
    check_object<reader_box>(L, reader_idx);

    auto *box = push_object<context_box>(L);
    box->reader = reader_at(L, reader_idx);
    set_reader_uservalue(L, reader_idx);
    return guarded(L, [&] {
        std::vector<sigmatch::const_byte_span> ranges;
        check_ranges(L, 1, &ranges);
        box->context = sigmatch::search_context{std::move(ranges), box->reader};
        return 1;
    });
}

int context_make_error(lua_State *L)
{
    size_t length = 0;
    const char *message = luaL_checklstring(L, 1, &length);
    auto *box = push_object<context_box>(L);
    set_reader_uservalue(L, 0);
    return guarded(L, [&] {
        box->context = sigmatch::search_context::make_error({message, length});
        return 1;
    });
}

int context_error(lua_State *L)
{
    const auto *box = check_object<context_box>(L, 1);
    return guarded(L, [&] {
        const auto error = box->context.error();
        if (error.has_value()) {
            lua_pushlstring(L, error->data(), error->size());
        }
        else {
            lua_pushnil(L);
        }
        return 1;
    });
}

// context:select([searcher [, args...]]) -> executor
//   select(sigmatch.blocking_searcher [, block_size])
//   select(sigmatch.multi_threaded_searcher [, threads_max_count [, block_size]])
int context_select(lua_State *L)
{
    const auto *ctx = check_object<context_box>(L, 1);
    const auto type = check_searcher_type(L, 2);

    sigmatch::allow_default<size_t> first, second;
    if (type == searcher_type::blocking) {
        first = opt_size(L, 3, "block size");
        luaL_argcheck(L, lua_isnoneornil(L, 4), 4, "blocking_searcher takes only a block size");
    }
    else {
        check_not_lua_reader(L, ctx->reader);
        first = opt_size(L, 3, "threads max count");
        second = opt_size(L, 4, "block size");
    }

    auto *box = push_object<executor_box>(L);
    box->reader = ctx->reader;
    share_uservalue(L, 1);
    return guarded(L, [&] {
        if (type == searcher_type::blocking) {
            box->executor.emplace<blocking_executor>(
                ctx->context.select<sigmatch::blocking_searcher>(first));
        }
        else {
            box->executor.emplace<multi_threaded_executor>(
                ctx->context.select<sigmatch::multi_threaded_searcher>(first, second));
        }
        return 1;
    });
}

// Searches with `search(sig)` of `searchable` (a context or an executor) into a new result.
template <class SearchableT>
int search_into_result(
    lua_State *L, const SearchableT &searchable, const std::shared_ptr<sigmatch::reader> &reader)
{
    const auto &sig = check_signature(L, 2);
    auto *result = push_object<result_box>(L);
    return guarded(L, [&] {
        reader_activation activation{L, reader};
        result->result = searchable.search(sig);
        return activation.push_failure(L) ? raise_pushed_error : 1;
    });
}

int context_search(lua_State *L)
{
    const auto *box = check_object<context_box>(L, 1);
    return search_into_result(L, box->context, box->reader);
}

int context_tostring(lua_State *L)
{
    const auto *box = check_object<context_box>(L, 1);
    return guarded(L, [&] {
        const auto error = box->context.error();
        if (error.has_value()) {
            lua_pushfstring(L, "sigmatch.search_context (error: %s)", error->c_str());
        }
        else {
            lua_pushliteral(L, "sigmatch.search_context");
        }
        return 1;
    });
}

int executor_search(lua_State *L)
{
    const auto *box = check_object<executor_box>(L, 1);
    if (const auto *executor = std::get_if<blocking_executor>(&box->executor)) {
        return search_into_result(L, *executor, box->reader);
    }
    if (const auto *executor = std::get_if<multi_threaded_executor>(&box->executor)) {
        return search_into_result(L, *executor, box->reader);
    }
    return luaL_error(L, "uninitialized executor");
}

int executor_tostring(lua_State *L)
{
    const auto *box = check_object<executor_box>(L, 1);
    lua_pushfstring(
        L, "sigmatch.executor (%s)",
        std::holds_alternative<multi_threaded_executor>(box->executor)
            ? searcher_name<sigmatch::multi_threaded_searcher>()
            : searcher_name<sigmatch::blocking_searcher>());
    return 1;
}

//////////////////////////////////////////////////
// module
//

int current_process_id(lua_State *L)
{
    push_unsigned(L, sigmatch::current_process_id());
    return 1;
}

int wildcard_tostring(lua_State *L)
{
    lua_pushliteral(L, "sigmatch._");
    return 1;
}

// Creates the metatable of T. `index`, if given, is the __index function and receives the methods
// table as upvalue 1; otherwise the methods table is the __index.
template <class T>
void register_type(
    lua_State *L, const luaL_Reg *methods, const luaL_Reg *metamethods,
    lua_CFunction index = nullptr, lua_CFunction gc = gc_object<T>)
{
    luaL_newmetatable(L, udata<T>::name);
    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");
    lua_pushstring(L, udata<T>::name);
    lua_setfield(L, -2, "__metatable"); // protects __gc from being called again
    if (metamethods != nullptr) {
        compat::setfuncs(L, metamethods);
    }
    lua_newtable(L);
    compat::setfuncs(L, methods);
    if (index != nullptr) {
        lua_pushcclosure(L, index, 1);
    }
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
}

void register_target_type(lua_State *L)
{
    const luaL_Reg metamethods[] = {{"__tostring", target_tostring}, {nullptr, nullptr}};
    const luaL_Reg no_methods[] = {{nullptr, nullptr}};
    register_type<target_box>(L, no_methods, metamethods);

    const luaL_Reg common[] = {
        {"error", target_error}, {"reader", target_reader}, {nullptr, nullptr}};
    const luaL_Reg memory[] = {{"in_range", target_in_memory_range}, {nullptr, nullptr}};
    const luaL_Reg file[] = {{"in_range", target_in_file_range}, {nullptr, nullptr}};
    const luaL_Reg process[] = {
        {"in_module", target_in_module}, {"pid", target_pid}, {nullptr, nullptr}};
    const luaL_Reg file_target[] = {{"in_whole", target_in_whole}, {nullptr, nullptr}};

    // Methods per target_kind, in enum order
    const luaL_Reg *const kinds[][3] = {
        {common, memory, process}, // this_process
        {common, memory, process}, // external_process
        {common, file, file_target}, // file
        {common, memory, nullptr}, // access_memory
        {common, file, nullptr}, // access_file
    };

    luaL_getmetatable(L, udata<target_box>::name);
    lua_createtable(L, static_cast<int>(std::size(kinds)), 0);
    for (size_t i = 0; i < std::size(kinds); ++i) {
        lua_newtable(L);
        for (const auto *methods : kinds[i]) {
            if (methods != nullptr) {
                compat::setfuncs(L, methods);
            }
        }
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    lua_pushcclosure(L, target_index, 1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
}

// Sets t[name] to a table that is callable through `call` and has the functions `statics`.
void set_class(lua_State *L, const char *name, lua_CFunction call, const luaL_Reg *statics)
{
    lua_newtable(L);
    if (statics != nullptr) {
        compat::setfuncs(L, statics);
    }
    lua_createtable(L, 0, 1);
    lua_pushcfunction(L, call);
    lua_setfield(L, -2, "__call");
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, name);
}

int result_call(lua_State *L)
{
    return result_new(L);
}

} // namespace

extern "C" LUA_SIGMATCH_API int luaopen_sigmatch(lua_State *L)
{
    {
        const luaL_Reg methods[] = {
            {"value", sig_byte_value}, {"mask", sig_byte_mask}, {"match", sig_byte_match},
            {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {
            {"__eq", sig_byte_eq}, {"__tostring", sig_byte_tostring}, {nullptr, nullptr}};
        register_type<sig_byte_box>(L, methods, metamethods);
    }
    {
        const luaL_Reg methods[] = {
            {"size", signature_size}, {"bytes", signature_bytes}, {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {
            {"__len", signature_size},
            {"__eq", signature_eq},
            {"__tostring", signature_tostring},
            {nullptr, nullptr}};
        register_type<signature_box>(L, methods, metamethods, signature_index);
    }
    {
        const luaL_Reg methods[] = {
            {"matches", result_matches},
            {"error_messages", result_error_messages},
            {"warning_messages", result_warning_messages},
            {"has_error", result_has_error},
            {"has_warning", result_has_warning},
            {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {
            {"__len", result_len},
            {"__eq", result_eq},
            {"__tostring", result_tostring},
            {nullptr, nullptr}};
        register_type<result_box>(L, methods, metamethods, result_index);
    }
    {
        const luaL_Reg methods[] = {
            {"error", reader_error}, {"read", reader_read}, {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {{"__tostring", reader_tostring}, {nullptr, nullptr}};
        register_type<reader_box>(L, methods, metamethods, nullptr, reader_gc);
    }
    register_target_type(L);
    {
        const luaL_Reg methods[] = {
            {"error", context_error},
            {"select", context_select},
            {"search", context_search},
            {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {{"__tostring", context_tostring}, {nullptr, nullptr}};
        register_type<context_box>(L, methods, metamethods);
    }
    {
        const luaL_Reg methods[] = {{"search", executor_search}, {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {{"__tostring", executor_tostring}, {nullptr, nullptr}};
        register_type<executor_box>(L, methods, metamethods);
    }
    {
        const luaL_Reg methods[] = {
            {"search", searcher_search}, {"reader", searcher_reader}, {nullptr, nullptr}};
        const luaL_Reg metamethods[] = {{"__tostring", searcher_tostring}, {nullptr, nullptr}};
        register_type<searcher_box>(L, methods, metamethods);
    }

    const luaL_Reg functions[] = {
        {"current_process_id", current_process_id},
        {"this_process_memory_reader", reader_this_process},
        {"external_process_memory_reader", reader_external_process},
        {"file_content_reader", reader_file_content},
        {"reader", reader_lua},
        {"this_process_target", target_this_process},
        {"external_process_target", target_external_process},
        {"file_target", target_file},
        {"access_memory_target", target_access_memory},
        {"access_file_target", target_access_file},
        {"blocking_searcher", searcher_blocking},
        {"multi_threaded_searcher", searcher_multi_threaded},
        {nullptr, nullptr}};

    lua_newtable(L);
    compat::setfuncs(L, functions);

    {
        const luaL_Reg statics[] = {{"parse", signature_parse}, {nullptr, nullptr}};
        set_class(L, "signature", signature_new, statics);
    }
    set_class(L, "sig_byte", sig_byte_new, nullptr);
    {
        const luaL_Reg statics[] = {
            {"make_error", result_make_error},
            {"make_warning", result_make_warning},
            {nullptr, nullptr}};
        set_class(L, "search_result", result_call, statics);
    }
    {
        const luaL_Reg statics[] = {{"make_error", context_make_error}, {nullptr, nullptr}};
        set_class(L, "search_context", context_new, statics);
    }

    // The wildcard placeholder, `sigmatch::_`
    lua_getfield(L, LUA_REGISTRYINDEX, wildcard_key);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_createtable(L, 0, 2);
        lua_pushcfunction(L, wildcard_tostring);
        lua_setfield(L, -2, "__tostring");
        lua_pushliteral(L, "sigmatch._");
        lua_setfield(L, -2, "__metatable");
        lua_setmetatable(L, -2);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, wildcard_key);
    }
    lua_setfield(L, -2, "_");

    lua_createtable(L, 0, 3);
    push_unsigned(L, static_cast<uint32_t>(sigmatch::mem_prot::read));
    lua_setfield(L, -2, "read");
    push_unsigned(L, static_cast<uint32_t>(sigmatch::mem_prot::write));
    lua_setfield(L, -2, "write");
    push_unsigned(L, static_cast<uint32_t>(sigmatch::mem_prot::execute));
    lua_setfield(L, -2, "execute");
    lua_setfield(L, -2, "mem_prot");

    push_unsigned(L, SIGMATCH_BLOCK_SIZE);
    lua_setfield(L, -2, "block_size");
    push_unsigned(L, SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD);
    lua_setfield(L, -2, "multi_threaded_search_size_threshold");
    push_unsigned(L, std::thread::hardware_concurrency());
    lua_setfield(L, -2, "hardware_concurrency");

#if defined(SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT)
    lua_pushboolean(L, true);
#else
    lua_pushboolean(L, false);
#endif
    lua_setfield(L, -2, "ghidra_format");

#if defined(SIGMATCH_PLATFORM_WINDOWS)
    lua_pushliteral(L, "windows");
#elif defined(SIGMATCH_PLATFORM_LINUX)
    lua_pushliteral(L, "linux");
#endif
    lua_setfield(L, -2, "platform");

    lua_pushliteral(L, "0.2.0");
    lua_setfield(L, -2, "sigmatch_version");
    lua_pushliteral(L, "lua_sigmatch " LUA_SIGMATCH_VERSION);
    lua_setfield(L, -2, "_VERSION");

    return 1;
}

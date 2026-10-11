//
// Copyright 2021 SpriteOvO
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

///
/// @file
///
/// @brief **sigmatch** library header file
///

///
/// @mainpage Documentation
///
/// @section Introduction Introduction
///
/// **sigmatch** is a C++ library designed to match / search signatures in a modern and
/// user-friendly way.
///
/// This library consists of the following main components:
///
/// - sigmatch::signature     Used to represent byte signatures.
/// - sigmatch::reader        Used to read the target data, which is an abstract class.
/// - sigmatch::searcher      Used to search with signatures from the data, which is an abstract
///                           class.
/// - sigmatch::target        Used to represent data targets, which is an abstract class.
/// - sigmatch::search_result Used to represent search results.
///
/// The code in the directory "/examples" will help you get started with **sigmatch** quickly.
///
/// @section Using-in-CMake Using in CMake
///
/// @code{.cmake}
///
///     cmake_minimum_required(VERSION 3.14)
///
///     include(FetchContent)
///
///     FetchContent_Declare(
///         sigmatch
///         GIT_REPOSITORY "https://github.com/SpriteOvO/sigmatch.git"
///     )
///     FetchContent_MakeAvailable(sigmatch)
///
///     target_link_libraries(${YOUR_TARGET_NAME} PRIVATE sigmatch::sigmatch)
///
/// @endcode
///
/// @section Note Note
///
/// - The library will try to keep the documented API compatible in future versions, but not for
///   undocumented.
///
/// - If you have any questions, suggestions or corrections to the library code or documentation,
///   please feel free to submit them to
///   [Issues Tracker](https://github.com/SpriteOvO/sigmatch/issues).
///

#pragma once

///
/// @cond
///

#include <span>
#include <tuple>
#include <mutex>
#include <array>
#include <chrono>
#include <memory>
#include <vector>
#include <string>
#include <format>
#include <thread>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <variant>
#include <fstream>
#include <cassert>
#include <optional>
#include <algorithm>
#include <functional>
#include <filesystem>
#include <string_view>

//////////////////////////////////////////////////
// macros
//

#define SIGMATCH_UNUSED(...) static_cast<void>(__VA_ARGS__)

#if defined linux || defined __linux || defined __linux__
    #define SIGMATCH_PLATFORM_LINUX
#elif defined WIN32 || defined __WIN32__ || defined _WIN32 || defined __MINGW32__
    #define SIGMATCH_PLATFORM_WINDOWS
#endif

// CT stands for compile-time, RT stands for runtime
#define SIGMATCH_CT_RT_ASSERT(c, msg)                                                              \
    do {                                                                                           \
        if (!(c)) {                                                                                \
            if (std::is_constant_evaluated()) {                                                    \
                throw msg;                                                                         \
            }                                                                                      \
            else {                                                                                 \
                return std::nullopt;                                                               \
            }                                                                                      \
        }                                                                                          \
    } while (false)

//////////////////////////////////////////////////
// platform headers
//

#if defined SIGMATCH_PLATFORM_WINDOWS
    #if !defined(WIN32_LEAN_AND_MEAN)
        #define WIN32_LEAN_AND_MEAN
    #endif
    #if !defined(NOMINMAX)
        #define NOMINMAX
    #endif
    #include <windows.h>
    #include <tlhelp32.h>
#elif defined SIGMATCH_PLATFORM_LINUX
    #include <cerrno>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/types.h>
#endif

///
/// @endcond
///

//////////////////////////////////////////////////
// configurations
//

#if defined SIGMATCH_DOXYGEN

    //
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //
    // Note that the following configuration macros are not really defined, they are just for
    // Doxygen to generate documentation. If you want to use these configuration macros, please
    // define them before including this header file, or pass them in the compilation arguments.
    //
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    //

    ///
    /// @brief A configuration macro to control debug mode
    ///
    /// If defined, some non-essential runtime assertion checks will be enabled.
    ///
    #define SIGMATCH_DEBUG

    ///
    /// @brief A configuration macro to control the block size
    ///
    /// If defined, the user-defined value will be used.
    ///
    /// This macro specifies the default size of the block to be read each time. The default value
    /// is `PAGE_SIZE`, or 0x1000 if `PAGE_SIZE` is not defined.
    ///
    /// @sa sigmatch::blocking_searcher
    ///
    #define SIGMATCH_BLOCK_SIZE (0x1000)

    ///
    /// @brief A configuration macro to control the multi-threaded search range threshold
    ///
    /// If defined, the user-defined value will be used.
    ///
    /// The multi-threaded search task assignment will refer to this value, if the total size is
    /// less than or equal to this macro value, the search will be performed with only one thread.
    ///
    /// @sa sigmatch::multi_threaded_searcher
    ///
    #define SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD (0x10000)

    ///
    /// @brief A configuration macro to control whether to store each reading failure warning
    ///        message
    ///
    /// If defined, each reading failure warning message will be stored in search_result.
    ///
    /// @note If searching in an unreliable range or using an unreliable reader there will be a lot
    ///       of reading failure warning messages stored, which may affect performance and memory
    ///       usage.
    ///
    /// @sa sigmatch::search_result
    ///
    #define SIGMATCH_STORE_EACH_READING_FAILURE_WARNING_MESSAGE

    ///
    /// @brief A configuration macro to control whether to enable experimental Ghidra signature
    /// format
    ///
    /// If defined, Ghidra signature format (e.g. `"[01001...]"`, `"[..100100]"`, `"[00...101]"`,
    /// `"[........]"`) will be supported.
    ///
    /// The binary sequence of one byte is enclosed in square brackets, and `.` will be treated as a
    /// wildcard.
    ///
    /// @remark
    /// Some examples of legitimate literal signature strings after Ghidra signature format enabled:
    /// @code{.cpp}
    ///     "[01001...] 89 5c [..100100] 08 [01001...]"_sig
    ///     "23 [...1..0.] 64 *A [........]"_sig
    ///     "64 6? 6* 6. [**..??10] [*.?*.?*.]"_sig
    /// @endcode
    ///
    #define SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT

    ///
    /// @brief A configuration macro to control whether to enable signature runtime parsing
    ///
    /// Note that with this macro enabled, users will be able to parse runtime signature strings
    /// using sigmatch::signature::parse(std::string_view sig). However, these strings will be
    /// retained in the compiled binary, and they will take extra time to parse at runtime compared
    /// to compile-time parsing. Signatures created using `sigmatch_literals::operator ""_sig()`
    /// will still be parsed at compile-time.
    ///
    /// @sa sigmatch::signature::parse(std::string_view sig) sigmatch_literals::operator ""_sig()
    ///
    #define SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING
#endif

///
/// @cond
///

#if defined SIGMATCH_DEBUG
    #define SIGMATCH_DEBUG_ASSERT(c) assert(c)
#else
    #define SIGMATCH_DEBUG_ASSERT(c)
#endif

#if !defined SIGMATCH_BLOCK_SIZE
    #if defined PAGE_SIZE
        #define SIGMATCH_BLOCK_SIZE PAGE_SIZE
    #else
        #define SIGMATCH_BLOCK_SIZE (0x1000)
    #endif
#endif

#if !defined SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD
    #define SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD (0x10000)
#endif

///
/// @endcond
///

///
/// @brief Library namespace
///
namespace sigmatch {

using namespace std::chrono_literals;

//////////////////////////////////////////////////
// assertions
//

static_assert(sizeof(std::byte) == 1);

//////////////////////////////////////////////////
// foundations
//

///
/// @brief A class for providing flags features to enumerations.
///
/// @tparam T The scoped enum class type.
///
template <class T, std::enable_if_t<std::is_enum_v<T>, int> = 0>
class enum_flags
{
public:
    ///
    /// @brief The enumeration type
    ///
    using enum_type = T;

    ///
    /// @brief The underlying type of the enum_type
    ///
    using underlying_type = std::underlying_type_t<T>;

    static_assert(
        sizeof(T) >= sizeof(uint32_t) && sizeof(underlying_type) >= sizeof(uint32_t),
        "It is recommended that the size of the underlying type be greater than 32 bits.");

    static_assert(
        std::is_unsigned_v<underlying_type>,
        "It is recommended that the underlying type is unsigned.");

private:
    template <class U>
    static constexpr inline bool is_operable_v =
        std::is_same_v<U, enum_flags> || std::is_same_v<U, enum_type>;

public:
    ///
    /// @brief Default constructor
    ///
    enum_flags() noexcept = default;

    ///
    /// @brief Constructor for an enumerator
    ///
    /// @param[in] value The enumerator value.
    ///
    constexpr enum_flags(enum_type value) noexcept : _value{static_cast<underlying_type>(value)} {}

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    /// @return bool Whether they are equal.
    ///
    [[nodiscard]] constexpr bool operator==(const enum_flags &rhs) const noexcept = default;

    ///
    /// @brief Bitwise OR operator
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags The arithmetic result.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    [[nodiscard]] constexpr enum_flags operator|(RhsT rhs) const noexcept
    {
        if constexpr (std::same_as<RhsT, enum_flags>) {
            return enum_flags{static_cast<enum_type>(_value | rhs._value)};
        }
        else {
            return enum_flags{static_cast<enum_type>(_value | static_cast<underlying_type>(rhs))};
        }
    }

    ///
    /// @brief Bitwise AND operator
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags The arithmetic result.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    [[nodiscard]] constexpr enum_flags operator&(RhsT rhs) const noexcept
    {
        if constexpr (std::same_as<RhsT, enum_flags>) {
            return enum_flags{static_cast<enum_type>(_value & rhs._value)};
        }
        else {
            return enum_flags{static_cast<enum_type>(_value & static_cast<underlying_type>(rhs))};
        }
    }

    ///
    /// @brief Bitwise XOR operator
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags The arithmetic result.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    [[nodiscard]] constexpr enum_flags operator^(RhsT rhs) const noexcept
    {
        if constexpr (std::same_as<RhsT, enum_flags>) {
            return enum_flags{static_cast<enum_type>(_value ^ rhs._value)};
        }
        else {
            return enum_flags{static_cast<enum_type>(_value ^ static_cast<underlying_type>(rhs))};
        }
    }

    ///
    /// @brief Bitwise NOT operator
    ///
    /// @return enum_flags The arithmetic result.
    ///
    [[nodiscard]] constexpr enum_flags operator~() const noexcept
    {
        return enum_flags{static_cast<enum_type>(~_value)};
    }

    ///
    /// @brief Bitwise OR assignment
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags & `*this`.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    constexpr enum_flags &operator|=(RhsT rhs) noexcept
    {
        *this = *this | rhs;
        return *this;
    }

    ///
    /// @brief Bitwise AND assignment
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags & `*this`.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    constexpr enum_flags &operator&=(RhsT rhs) noexcept
    {
        *this = *this & rhs;
        return *this;
    }

    ///
    /// @brief Bitwise XOR assignment
    ///
    /// @tparam RhsT enum_flags or enum_type.
    ///
    /// @param[in] rhs A rhs value.
    ///
    /// @return enum_flags & `*this`.
    ///
    template <class RhsT, std::enable_if_t<is_operable_v<RhsT>, int> = 0>
    constexpr enum_flags &operator^=(RhsT rhs) noexcept
    {
        *this = *this ^ rhs;
        return *this;
    }

    ///
    /// @brief Test flag(s).
    ///
    /// @param[in] flags A flag(s) value.
    ///
    /// @return bool Whether the given flag is set.
    ///
    [[nodiscard]] constexpr bool test(enum_flags flags) const noexcept
    {
        return (enum_flags{enum_type{_value}} & flags) == flags &&
               (flags._value != 0 || enum_flags{enum_type{_value}} == flags);
    }

private:
    underlying_type _value{0};
};

///
/// @cond
///

// clang-format off
#define SIGMATCH_ENABLE_ENUM_FLAGS_OPERATORS(sc) \
    constexpr enum_flags<sc> operator|(sc lhs, sc rhs) noexcept { return enum_flags<sc>{lhs} | enum_flags<sc>{rhs}; } \
    constexpr enum_flags<sc> operator&(sc lhs, sc rhs) noexcept { return enum_flags<sc>{lhs} & enum_flags<sc>{rhs}; } \
    constexpr enum_flags<sc> operator^(sc lhs, sc rhs) noexcept { return enum_flags<sc>{lhs} ^ enum_flags<sc>{rhs}; } \
    constexpr enum_flags<sc> operator~(sc val) noexcept { return ~enum_flags<sc>{val}; }
// clang-format on

///
/// @endcond
///

//////////////////////////////////////////////////
// enums
//

///
/// @brief Memory protection flags enumeration
///
/// @sa process_target::in_module(const platform_string &,enum_flags<mem_prot>) const
///
enum class mem_prot : uint32_t
{
    // clang-format off
    read    = 0b00000001,
    write   = 0b00000010,
    execute = 0b00000100,
    // clang-format on
};

///
/// @cond
///

SIGMATCH_ENABLE_ENUM_FLAGS_OPERATORS(mem_prot);

///
/// @endcond
///

//////////////////////////////////////////////////
// types
//

///
/// @brief Process ID type.
///
using process_id = uint32_t;

///
/// @cond
///

//////////////////////////////////////////////////
// details
//

namespace details {

class process_handle
{
private:
#if defined SIGMATCH_PLATFORM_WINDOWS
    using underlying_type = HANDLE;
    static constexpr underlying_type invalid_value = nullptr;
#elif defined SIGMATCH_PLATFORM_LINUX
    // A file descriptor of `/proc/<pid>/mem`
    using underlying_type = int;
    static constexpr underlying_type invalid_value = -1;
#else
    #error "Unimplemented."
#endif

public:
    process_handle() noexcept = default;
    constexpr process_handle(std::nullptr_t) noexcept {}
    constexpr process_handle(underlying_type value) noexcept : _value{value} {}

    // Required by `std::unique_ptr` (NullablePointer)
    [[nodiscard]] constexpr bool operator==(const process_handle &rhs) const noexcept = default;

    [[nodiscard]] explicit constexpr operator bool() const noexcept
    {
        return _value != invalid_value;
    }

    [[nodiscard]] constexpr underlying_type value() const noexcept
    {
        return _value;
    }

private:
    underlying_type _value{invalid_value};
};

namespace impl {

struct process_handle_closer
{
    using pointer = process_handle;

    constexpr void operator()(process_handle handle) noexcept
    {
        if (handle) {
#if defined SIGMATCH_PLATFORM_WINDOWS
            CloseHandle(handle.value());
#elif defined SIGMATCH_PLATFORM_LINUX
            ::close(handle.value());
#else
    #error "Unimplemented."
#endif
        }
    }
};

} // namespace impl

using unique_process_handle = std::unique_ptr<process_handle, impl::process_handle_closer>;

template <size_t kCount>
struct consteval_str_buffer
{
    using char_type = char;

    consteval consteval_str_buffer(const char_type (&str)[kCount]) noexcept
    {
        for (size_t i = 0; i < kCount; ++i) {
            data[i] = str[i];
        }
    }

    consteval std::string_view to_string_view() const noexcept
    {
        return std::string_view{data};
    }

    char_type data[kCount];
    constexpr static size_t count = kCount - sizeof(char_type);
};

[[nodiscard]] inline unique_process_handle open_process(process_id pid)
{
#if defined SIGMATCH_PLATFORM_WINDOWS
    return unique_process_handle{
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)};
#elif defined SIGMATCH_PLATFORM_LINUX
    const auto path = std::format("/proc/{}/mem", pid);
    return unique_process_handle{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
#else
    #error "Unimplemented."
#endif
}

template <class VecT>
constexpr void insert_vector(VecT &dest, const VecT &src)
{
    dest.reserve(dest.size() + src.size());
    dest.insert(dest.end(), src.begin(), src.end());
}

template <class VecT>
constexpr void insert_vector(VecT &dest, VecT &&src)
{
    dest.reserve(dest.size() + src.size());
    std::move(src.begin(), src.end(), std::back_inserter(dest));
}

template <class T, size_t kCount>
[[nodiscard]] consteval std::array<T, kCount> friendly_construct_array() noexcept(noexcept(T{}))
{
    return {};
}

namespace text {

[[nodiscard]] constexpr std::string to_lower(std::string source)
{
    std::transform(source.begin(), source.end(), source.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return source;
}

[[nodiscard]] constexpr std::wstring to_lower(std::wstring source)
{
    std::transform(source.begin(), source.end(), source.begin(), &std::towlower);
    return source;
}

[[nodiscard]] constexpr std::string to_upper(std::string source)
{
    std::transform(source.begin(), source.end(), source.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return source;
}

[[nodiscard]] constexpr std::wstring to_upper(std::wstring source)
{
    std::transform(source.begin(), source.end(), source.begin(), &std::towupper);
    return source;
}

namespace convert {

#if defined SIGMATCH_PLATFORM_WINDOWS

[[nodiscard]] inline std::wstring utf8_to_wide_char(const std::u8string_view &utf8)
{
    auto utf8_ptr = reinterpret_cast<const char *>(utf8.data());
    const int utf8_bytes_size = static_cast<int>(utf8.size());
    if (utf8_bytes_size == 0) {
        return {};
    }

    const int needed = MultiByteToWideChar(CP_UTF8, 0, utf8_ptr, utf8_bytes_size, nullptr, 0);
    if (needed == 0) {
        return {};
    }

    std::wstring wstr(needed, L'\0');
    return MultiByteToWideChar(CP_UTF8, 0, utf8_ptr, utf8_bytes_size, wstr.data(), needed) != 0
               ? wstr
               : std::wstring{};
}

[[nodiscard]] inline std::wstring utf8_to_wide_char(const std::string_view &utf8)
{
    return utf8_to_wide_char(
        std::u8string_view{reinterpret_cast<const char8_t *>(utf8.data()), utf8.size()});
}

// clang-format off
template <class T = std::string>
requires(std::same_as<T, std::string> || std::same_as<T, std::u8string>)
[[nodiscard]] inline T wide_char_to_utf8(const std::wstring_view &wstr)
// clang-format on
{
    auto wstr_ptr = reinterpret_cast<const wchar_t *>(wstr.data());
    const int wstr_size = static_cast<int>(wstr.size());
    if (wstr_size == 0) {
        return {};
    }

    const int needed =
        WideCharToMultiByte(CP_UTF8, 0, wstr_ptr, wstr_size, nullptr, 0, nullptr, nullptr);
    if (needed == 0) {
        return {};
    }

    constexpr typename T::value_type end_char = std::same_as<T, std::string> ? '\0' : u8'\0';

    T utf8(needed, end_char);
    return WideCharToMultiByte(
               CP_UTF8, 0, wstr_ptr, wstr_size, reinterpret_cast<char *>(utf8.data()), needed,
               nullptr, nullptr) != 0
               ? utf8
               : T{};
}

#elif defined SIGMATCH_PLATFORM_LINUX

// `wchar_t` is UTF-32 on Linux. Invalid code points are replaced with U+FFFD.
[[nodiscard]] constexpr std::string wide_char_to_utf8(std::wstring_view wstr)
{
    std::string utf8;
    utf8.reserve(wstr.size());

    for (const wchar_t wch : wstr) {
        auto cp = static_cast<uint32_t>(wch);
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            cp = 0xFFFD;
        }

        if (cp < 0x80) {
            utf8.push_back(static_cast<char>(cp));
        }
        else if (cp < 0x800) {
            utf8.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else if (cp < 0x10000) {
            utf8.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        else {
            utf8.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            utf8.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    return utf8;
}

#endif

} // namespace convert
} // namespace text

#if defined SIGMATCH_PLATFORM_LINUX

namespace procfs {

// A line of `/proc/<pid>/maps`
struct map_region
{
    uintptr_t begin{0}, end{0};
    enum_flags<mem_prot> prot;
    uint64_t offset{0};
    std::string path;
};

[[nodiscard]] inline std::optional<std::vector<map_region>> read_maps(process_id pid)
{
    std::ifstream stream{std::format("/proc/{}/maps", pid)};
    if (!stream.is_open()) {
        return std::nullopt;
    }

    std::vector<map_region> regions;
    std::string line;

    // Format: "<begin>-<end> <perms> <offset> <dev> <inode> [<path>]"
    while (std::getline(stream, line)) {
        unsigned long long begin = 0, end = 0, offset = 0;
        char perms[5]{};
        int path_pos = 0;

        if (std::sscanf(
                line.c_str(), "%llx-%llx %4s %llx %*s %*s %n", &begin, &end, perms, &offset,
                &path_pos) < 4) {
            continue;
        }

        map_region region;
        region.begin = static_cast<uintptr_t>(begin);
        region.end = static_cast<uintptr_t>(end);
        region.offset = static_cast<uint64_t>(offset);
        if (perms[0] == 'r') {
            region.prot |= mem_prot::read;
        }
        if (perms[1] == 'w') {
            region.prot |= mem_prot::write;
        }
        if (perms[2] == 'x') {
            region.prot |= mem_prot::execute;
        }
        if (path_pos > 0 && static_cast<size_t>(path_pos) < line.size()) {
            region.path = line.substr(path_pos);
        }

        regions.emplace_back(std::move(region));
    }

    return regions;
}

} // namespace procfs

#endif

} // namespace details

///
/// @endcond
///

///
/// @brief Get the current process id
///
/// @return process_id The current process id.
///
[[nodiscard]] inline process_id current_process_id() noexcept
{
#if defined SIGMATCH_PLATFORM_WINDOWS
    return process_id{GetCurrentProcessId()};
#elif defined SIGMATCH_PLATFORM_LINUX
    return static_cast<process_id>(::getpid());
#else
    #error "Unimplemented."
#endif
}

//////////////////////////////////////////////////
// concepts
//

class searcher;
///
/// @brief A concept to check if a class is a searcher (if it inherits from class `searcher`)
///
template <class T>
concept kind_of_searcher = std::derived_from<T, searcher>;

class reader;
///
/// @brief A concept to check if a class is a reader (if it inherits from class `reader`)
///
template <class T>
concept kind_of_reader = std::derived_from<T, reader>;

class target;
///
/// @brief A concept to check if a class is a target (if it inherits from class `target`)
///
template <class T>
concept kind_of_target = std::derived_from<T, target>;

//////////////////////////////////////////////////

///
/// @brief Default value placeholder type for `allow_default`.
///
/// @sa allow_default default_value
///
using default_value_t = std::nullopt_t;

///
/// @brief Default value placeholder for `allow_default`.
///
/// @sa allow_default
///
constexpr inline default_value_t default_value = std::nullopt;

///
/// @brief A class that can represent the data to allow defaults
///
/// @tparam T The data type.
///
template <class T>
using allow_default = std::optional<T>;

//////////////////////////////////////////////////
///
/// @brief A cross-platform string class
///
/// Accepts utf-8 string or wide string and converts it internally to a platform-friendly string.
///
/// @note
/// **sigmatch** assumes that your code files are always utf-8 encoded, so the no-prefix literal
/// strings in your code should be utf-8 encoded as well.
///
class platform_string
{
public:
#if defined SIGMATCH_PLATFORM_WINDOWS
    using string_type = std::wstring;
#elif defined SIGMATCH_PLATFORM_LINUX
    using string_type = std::string;
#else
    #error "Unimplemented."
#endif

    ///
    /// @brief Constructor for utf-8 string
    ///
    /// @param[in] utf8 A utf-8 string.
    ///
    inline platform_string(const std::u8string &utf8)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = details::text::convert::utf8_to_wide_char(utf8);
#elif defined SIGMATCH_PLATFORM_LINUX
        _str.assign(utf8.begin(), utf8.end());
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @copydoc platform_string(const std::u8string &)
    ///
    inline platform_string(const char8_t *utf8)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = details::text::convert::utf8_to_wide_char(utf8);
#elif defined SIGMATCH_PLATFORM_LINUX
        const std::u8string_view view{utf8};
        _str.assign(view.begin(), view.end());
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @copydoc platform_string(const std::u8string &)
    ///
    inline platform_string(const std::string &utf8)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = details::text::convert::utf8_to_wide_char(utf8);
#elif defined SIGMATCH_PLATFORM_LINUX
        _str = utf8;
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @copydoc platform_string(const std::u8string &)
    ///
    inline platform_string(const char *utf8)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = details::text::convert::utf8_to_wide_char(utf8);
#elif defined SIGMATCH_PLATFORM_LINUX
        _str = utf8;
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @brief Constructor for wide char string
    ///
    /// @param[in] wstr A wide char string.
    ///
    inline platform_string(const std::wstring &wstr)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = wstr;
#elif defined SIGMATCH_PLATFORM_LINUX
        _str = details::text::convert::wide_char_to_utf8(wstr);
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @copydoc platform_string(const std::wstring &)
    ///
    inline platform_string(const wchar_t *wstr)
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        _str = wstr;
#elif defined SIGMATCH_PLATFORM_LINUX
        _str = details::text::convert::wide_char_to_utf8(wstr);
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @brief Copy constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr platform_string(const platform_string &rhs)
    {
        copy_from(rhs);
    }

    ///
    /// @brief Move constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr platform_string(platform_string &&rhs) noexcept
    {
        move_from(std::move(rhs));
    }

    ///
    /// @brief Copy assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr platform_string &operator=(const platform_string &rhs)
    {
        copy_from(rhs);
        return *this;
    }

    ///
    /// @brief Move assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr platform_string &operator=(platform_string &&rhs) noexcept
    {
        move_from(std::move(rhs));
        return *this;
    }

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    /// @return bool Whether they are equal.
    ///
    [[nodiscard]] constexpr bool operator==(const platform_string &rhs) const noexcept = default;

    ///
    /// @cond
    ///

    [[nodiscard]] constexpr const string_type &str() const noexcept
    {
        return _str;
    }

    [[nodiscard]] constexpr string_type &str() noexcept
    {
        return _str;
    }

    [[nodiscard]] inline std::string to_string() const
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        return details::text::convert::wide_char_to_utf8(_str);
#elif defined SIGMATCH_PLATFORM_LINUX
        return _str;
#else
    #error "Unimplemented."
#endif
    }

    ///
    /// @endcond
    ///

private:
    string_type _str;

    constexpr void copy_from(const platform_string &rhs)
    {
        _str = rhs._str;
    }

    constexpr void move_from(platform_string &&rhs) noexcept
    {
        _str = std::move(rhs._str);
    }
};

//////////////////////////////////////////////////
///
/// @brief An extended const byte span class
///
/// In contrast to `std::span<const std::byte>`, it can accept pure pointers and `std::span<const
/// unsigned char>`.
///
class const_byte_span : public std::span<const std::byte>
{
public:
    using std::span<const std::byte>::span;

    ///
    /// @brief Constructor for `std::span<const std::byte>`
    ///
    /// @param[in] range A `std::span<const std::byte>` value.
    ///
    constexpr const_byte_span(const std::span<const std::byte> &range) noexcept
        : std::span<const std::byte>{range}
    {
    }

    ///
    /// @brief Constructor for pure pointer
    ///
    /// @param[in] begin The beginning of a memory range.
    /// @param[in] size  The size of this memory range.
    ///
    constexpr const_byte_span(const void *begin, size_t size) noexcept
        : std::span<const std::byte>{static_cast<const std::byte *>(begin), size}
    {
    }

    ///
    /// @brief Constructor for `std::span<const unsigned char>`
    ///
    /// @param[in] range A `std::span<const unsigned char>` value.
    ///
    constexpr const_byte_span(std::span<const unsigned char> range) noexcept
        : const_byte_span{range.data(), range.size()}
    {
    }
};

//////////////////////////////////////////////////
///
/// @brief A class that is used to represent a wildcard
///
/// @sa _
///
// clang-format off
class wildcard {};
// clang-format on

///
/// @brief A global variable that is used to represent a wildcard
///
/// The following two approaches are equivalent.
/// @code{.cpp}
///     signature sig_from_vector{{0x7D, 0xDC, {_, 0xB}, {0x9, _}, {_, 0xD}, _, _, 0x24}};
///     signature sig_from_literal{"7D DC ?B 9? *D ?? ** 24"_sig};
/// @endcode
///
/// @sa sigmatch_literals::operator ""_sig()
///
constexpr inline wildcard _{};

//////////////////////////////////////////////////
///
/// @brief A signature byte class for storing, matching and allowing wildcards
///
class sig_byte
{
public:
    ///
    /// @brief Constructor for value and mask
    ///
    /// @param[in] value Value to be matched.
    /// @param[in] mask Mask of the value to be matched.
    ///
    constexpr sig_byte(std::byte value, std::byte mask) noexcept : _value{value}, _mask{mask} {}

    ///
    /// @copydoc sig_byte(std::byte, std::byte)
    ///
    constexpr sig_byte(unsigned char value, unsigned char mask) noexcept
        : sig_byte{std::byte{value}, std::byte{mask}}
    {
    }

    ///
    /// @brief Constructor for full match
    ///
    /// @param[in] value A byte value.
    ///
    constexpr sig_byte(std::byte value) noexcept : _value{value}, _mask{std::byte{0xFF}} {}

    ///
    /// @copydoc sig_byte(std::byte)
    ///
    constexpr sig_byte(unsigned char value) noexcept : sig_byte{std::byte{value}} {}

    ///
    /// @brief Constructor for semi-match (high 8-bit)
    ///
    /// @param[in] left A semi-byte value.
    /// @param[in] wc   A wildcard placeholder.
    ///
    /// @sa _
    ///
    constexpr sig_byte(std::byte left, wildcard wc) noexcept
        : _value{left << 4}, _mask{std::byte{0xF0}}
    {
        SIGMATCH_UNUSED(wc);
    }

    ///
    /// @copydoc sig_byte(std::byte,wildcard)
    ///
    constexpr sig_byte(unsigned char left, wildcard wc) noexcept : sig_byte{std::byte{left}, wc} {}

    ///
    /// @brief Constructor for semi-match (low 8-bit)
    ///
    /// @param[in] wc    A wildcard placeholder.
    /// @param[in] right A semi-byte value.
    ///
    /// @sa _
    ///
    constexpr sig_byte(wildcard wc, std::byte right) noexcept
        : _value{right}, _mask{std::byte{0x0F}}
    {
        SIGMATCH_UNUSED(wc);
    }

    ///
    /// @copydoc sig_byte(wildcard,std::byte)
    ///
    constexpr sig_byte(wildcard wc, unsigned char right) noexcept : sig_byte{wc, std::byte{right}}
    {
    }

    ///
    /// @brief Constructor for full wildcard
    ///
    /// @param[in] wc A wildcard placeholder.
    ///
    /// @sa _
    ///
    constexpr sig_byte(wildcard wc) noexcept
    {
        SIGMATCH_UNUSED(wc);
    }

    ///
    /// @brief Copy constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr sig_byte(const sig_byte &rhs) noexcept
    {
        copy_from(rhs);
    }

    ///
    /// @brief Move constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr sig_byte(sig_byte &&rhs) noexcept
    {
        move_from(std::move(rhs));
    }

    ///
    /// @brief Copy assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr sig_byte &operator=(const sig_byte &rhs) noexcept
    {
        copy_from(rhs);
        return *this;
    }

    ///
    /// @brief Move assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr sig_byte &operator=(sig_byte &&rhs) noexcept
    {
        move_from(std::move(rhs));
        return *this;
    }

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    [[nodiscard]] constexpr bool operator==(const sig_byte &rhs) const noexcept = default;

    ///
    /// @brief Equal to byte operator
    ///
    /// @param[in] value A byte value.
    ///
    /// @return bool Whether they are equal.
    ///
    [[nodiscard]] constexpr bool operator==(std::byte value) const noexcept
    {
        return match(value);
    }

    ///
    /// @copydoc operator==(std::byte) const
    ///
    [[nodiscard]] constexpr bool operator==(unsigned char value) const noexcept
    {
        return match(std::byte{value});
    }

    ///
    /// @brief Value to be matched, wildcard bits are filled with 0
    ///
    /// @return std::byte The value to be matched of this `sig_byte`.
    ///
    [[nodiscard]] constexpr std::byte value() const noexcept
    {
        return _value;
    }

    ///
    /// @brief Mask of the value to be matched
    ///
    /// @return std::byte The mask of the value to be matched of this `sig_byte`.
    ///
    [[nodiscard]] constexpr std::byte mask() const noexcept
    {
        return _mask;
    }

    ///
    /// @brief Match this sig_byte with a byte value
    ///
    /// @param[in] value A byte value.
    ///
    /// @return bool Whether they are matching
    ///
    [[nodiscard]] constexpr bool match(std::byte value) const noexcept
    {
        return ((value & _mask) ^ _value) == std::byte{0};
    }

    ///
    /// @copydoc match(std::byte) const
    ///
    [[nodiscard]] constexpr bool match(unsigned char value) const noexcept
    {
        return match(std::byte{value});
    }

private:
    std::byte _value{0}, _mask{0};

    // For friendly calling
    //
    sig_byte() noexcept = default;

    constexpr void copy_from(const sig_byte &rhs) noexcept
    {
        _value = rhs._value;
        _mask = rhs._mask;
    }

    constexpr void move_from(sig_byte &&rhs) noexcept
    {
        _value = std::move(rhs._value);
        _mask = std::move(rhs._mask);
    }

    template <class T, size_t kCount>
    friend consteval std::array<T, kCount>
    details::friendly_construct_array() noexcept(noexcept(T{}));
};

///
/// @cond
///

namespace impl {

[[nodiscard]] constexpr std::optional<std::byte> parse_byte_hex_str(std::string_view str)
{
    unsigned char result = 0;

    for (const char ch : str) {
        // check byte value overflow
        SIGMATCH_CT_RT_ASSERT(result < 0x10, "Please report this bug on the GitHub Issue Tracker.");

        unsigned char ch_value;

        if (ch >= '0' && ch <= '9') {
            ch_value = ch - '0';
        }
        else if (ch >= 'A' && ch <= 'F') {
            ch_value = ch - 'A' + 10;
        }
        else if (ch >= 'a' && ch <= 'f') {
            ch_value = ch - 'a' + 10;
        }
        else {
            SIGMATCH_CT_RT_ASSERT(
                false, "The signature format is wrong. Contains unexpected characters.");
        }

        SIGMATCH_CT_RT_ASSERT(
            ch_value < 0x10, "Please report this bug on the GitHub Issue Tracker.");

        result *= 0x10;
        result += ch_value;
    }

    return std::byte{result};
}

[[nodiscard]] constexpr decltype(auto)
string_split(std::string_view source, std::string_view delimiter, bool exclude_empty = true)
{
    std::vector<std::string_view> result;

    size_t begin_pos = 0, end_pos;
    do {
        end_pos = source.find(delimiter, begin_pos);
        auto token = source.substr(begin_pos, end_pos - begin_pos);
        if (!exclude_empty || !token.empty()) {
            result.emplace_back(std::move(token));
        }
        begin_pos = end_pos + delimiter.size();
    } while (end_pos != std::string_view::npos);

    return result;
}

[[nodiscard]] constexpr bool is_char_wildcard(char ch) noexcept
{
    return ch == '?' || ch == '*'
#if defined SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT
           || ch == '.'
#endif
        ;
}

[[nodiscard]] constexpr size_t count_non_space_char(std::string_view sig) noexcept
{
    size_t result = 0;
    for (size_t i = 0; i < sig.size(); ++i) {
        if (sig.at(i) != ' ') {
            ++result;
        }
    }
    return result;
}

[[nodiscard]] constexpr std::optional<sig_byte> parse_sig_normal(std::string_view byte_str)
{
    SIGMATCH_CT_RT_ASSERT(
        byte_str.size() == 2,
        "Normal signature byte should be represented by 2 hexadecimal digits.");

    const bool is_left_wildcard = is_char_wildcard(byte_str.front()),
               is_right_wildcard = is_char_wildcard(byte_str.back());

    if (!is_left_wildcard && !is_right_wildcard) {
        // full match
        return parse_byte_hex_str(byte_str);
    }
    else if (is_left_wildcard && is_right_wildcard) {
        // full wildcard
        return _;
    }
    else if (is_left_wildcard && !is_right_wildcard) {
        // semi-wildcard (left)
        auto b = parse_byte_hex_str(std::string{byte_str.back()});
        if (!b.has_value()) {
            return std::nullopt;
        }
        return sig_byte{_, b.value()};
    }
    else if (!is_left_wildcard && is_right_wildcard) {
        // semi-wildcard (right)
        auto b = parse_byte_hex_str(std::string{byte_str.front()});
        if (!b.has_value()) {
            return std::nullopt;
        }
        return sig_byte{b.value(), _};
    }
    else {
        SIGMATCH_CT_RT_ASSERT(false, "Please report this bug on the GitHub Issue Tracker.");
    }
}

#if defined SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT
// refer to: https://github.com/NationalSecurityAgency/ghidra/issues/5490#issuecomment-1622277250
[[nodiscard]] constexpr std::optional<sig_byte> parse_sig_ghidra(std::string_view byte_str)
{
    SIGMATCH_CT_RT_ASSERT(
        byte_str.size() == 10 && byte_str.front() == '[' && byte_str.back() == ']',
        "Ghidra signature byte should be represented by 8 binary digits.");

    unsigned char target = 0, mask = 0;

    for (size_t i = 0; i < 8; i++) {
        char ch = byte_str.at(i + 1);

        if (ch == '0') {
            mask |= (0b10000000 >> i);
        }
        else if (ch == '1') {
            mask |= (0b10000000 >> i);
            target |= (0b10000000 >> i);
        }
        else {
            SIGMATCH_CT_RT_ASSERT(
                is_char_wildcard(ch), "Unknown character in Ghidra like signature");
        }
    }

    return sig_byte{std::byte{target}, std::byte{mask}};
}
#endif

[[nodiscard]] constexpr std::optional<sig_byte> parse_sig_byte(std::string_view byte_str)
{
#if defined SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT
    if (byte_str.front() == '[' && byte_str.back() == ']') {
        return parse_sig_ghidra(byte_str);
    }
#endif
    return parse_sig_normal(byte_str);
}

template <details::consteval_str_buffer kSigStrBuf>
[[nodiscard]] consteval decltype(auto) parse_sig_str_compile_time()
{
    constexpr size_t non_space_char_count = count_non_space_char(kSigStrBuf.to_string_view());
    static_assert(non_space_char_count % 2 == 0, "The signature format is wrong.");

    constexpr size_t bytes_count = string_split(kSigStrBuf.to_string_view(), " ").size();
    auto bytes_vec = string_split(kSigStrBuf.to_string_view(), " ");

    auto result = details::friendly_construct_array<sig_byte, bytes_count>();

    for (size_t i = 0; i < bytes_count; ++i) {
        result[i] = parse_sig_byte(bytes_vec[i]).value();
    }

    return result;
}

[[nodiscard]] constexpr std::optional<std::vector<sig_byte>>
parse_sig_str_runtime(std::string_view sig) noexcept
{
    size_t non_space_char_count = count_non_space_char(sig);
    if (non_space_char_count % 2 != 0) {
        // "The signature format is wrong."
        return std::nullopt;
    }

    auto bytes_vec = string_split(sig, " ");

    std::vector<sig_byte> result;
    result.reserve(bytes_vec.size());

    for (size_t i = 0; i < bytes_vec.size(); ++i) {
        auto b = parse_sig_byte(bytes_vec[i]);
        if (!b.has_value()) {
            return std::nullopt;
        }
        result.emplace_back(b.value());
    }

    return result;
}

} // namespace impl

///
/// @endcond
///

//////////////////////////////////////////////////
///
/// @brief A signature class
///
/// @sa sigmatch_literals::operator ""_sig()
///
class signature final
{
public:
    ///
    /// @brief Default constructor
    ///
    signature() noexcept = default;

    ///
    /// @brief Constructor for `std::vector<sig_byte>` initialization
    ///
    /// @param[in] bytes A signature bytes vector.
    ///
    constexpr signature(std::vector<sig_byte> bytes) noexcept : _bytes{std::move(bytes)} {}

    ///
    /// @cond
    ///

    //
    // For internal use with the `_sig` suffix
    //

    // clang-format off
    struct ____literal_place_t{};
    struct ____runtime_place_t{};
    // clang-format on

    template <size_t kCount>
    constexpr signature(____literal_place_t, const std::array<sig_byte, kCount> &bytes)
    {
        _bytes.reserve(bytes.size());
        std::copy(bytes.begin(), bytes.end(), std::back_inserter(_bytes));
    }

    constexpr signature(____runtime_place_t, std::vector<sig_byte> &&bytes)
    {
        _bytes = std::move(bytes);
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Copy constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr signature(const signature &rhs)
    {
        copy_from(rhs);
    }

    ///
    /// @brief Move constructor
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr signature(signature &&rhs) noexcept
    {
        move_from(std::move(rhs));
    }

    ///
    /// @brief Copy assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr signature &operator=(const signature &rhs)
    {
        copy_from(rhs);
        return *this;
    }

    ///
    /// @brief Move assignment
    ///
    /// @param[in] rhs A right hand side value.
    ///
    constexpr signature &operator=(signature &&rhs) noexcept
    {
        move_from(std::move(rhs));
        return *this;
    }

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    [[nodiscard]] constexpr bool operator==(const signature &rhs) const noexcept = default;

#if defined SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING

    ///
    /// @brief Parse signature at runtime
    ///
    /// The strings of the signatures parsed by this function will be retained in the compiled
    /// binary, and they will take extra time to parse at runtime compared to compile-time parsing.
    ///
    /// @sa SIGMATCH_ENABLE_SIGNATURE_RUNTIME_PARSING sigmatch_literals::operator ""_sig()
    ///
    // TODO: better error reporting
    [[nodiscard]] static constexpr std::optional<signature> parse(std::string_view sig) noexcept
    {
        auto bytes = impl::parse_sig_str_runtime(sig);
        if (!bytes.has_value()) {
            return std::nullopt;
        }
        return signature{____runtime_place_t{}, std::move(bytes.value())};
    }

#endif

    ///
    /// @brief Get the bytes vector
    ///
    /// @return const std::vector<sig_byte> & The bytes vector.
    ///
    [[nodiscard]] constexpr const std::vector<sig_byte> &bytes() const noexcept
    {
        return _bytes;
    }

    ///
    /// @brief Get the size / length of this signature.
    ///
    /// @return size_t The size / length of this signature.
    ///
    [[nodiscard]] constexpr size_t size() const noexcept
    {
        return _bytes.size();
    }

private:
    std::vector<sig_byte> _bytes;

    constexpr void copy_from(const signature &rhs)
    {
        _bytes = rhs._bytes;
    }

    constexpr void move_from(signature &&rhs) noexcept
    {
        _bytes = std::move(rhs._bytes);
    }
};

//////////////////////////////////////////////////
///
/// @brief A set of signatures that are searched for together
///
/// Searching for a set reads the data once for all of its signatures instead of once per
/// signature, which matters when there are many of them. The result is the same as searching for
/// each signature separately.
///
/// @sa search_context::search(const signature_set &) const
///
class signature_set final
{
public:
    ///
    /// @brief Default constructor
    ///
    signature_set() noexcept = default;

    ///
    /// @brief Constructor for multiple signatures
    ///
    /// @param[in] signatures The signatures.
    ///
    explicit signature_set(std::vector<signature> signatures) noexcept
        : _signatures{std::move(signatures)}
    {
    }

    ///
    /// @brief Add a signature
    ///
    /// @param[in] sig The signature.
    ///
    /// @return size_t The index of the signature, which is also the index of its result.
    ///
    inline size_t add(signature sig)
    {
        _signatures.emplace_back(std::move(sig));
        return _signatures.size() - 1;
    }

    ///
    /// @brief Get the signatures
    ///
    /// @return const std::vector<signature> & The signatures.
    ///
    [[nodiscard]] constexpr const std::vector<signature> &signatures() const noexcept
    {
        return _signatures;
    }

    ///
    /// @brief Get the number of signatures
    ///
    /// @return size_t The number of signatures.
    ///
    [[nodiscard]] constexpr size_t size() const noexcept
    {
        return _signatures.size();
    }

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    [[nodiscard]] bool operator==(const signature_set &rhs) const noexcept = default;

private:
    std::vector<signature> _signatures;
};

//////////////////////////////////////////////////
// matchers
//
// (for internal use)
//

///
/// @cond
///

class matcher final
{
public:
    explicit constexpr matcher(signature sig) : _sig{std::move(sig)}
    {
        _last_unmatched.reserve((_sig.size() - 1) * 2);
        reset();
    }

    constexpr void reset() noexcept
    {
        _last_unmatched.clear();
    }

    constexpr void match(
        const std::span<std::byte> &data, const std::byte *base,
        std::vector<const std::byte *> &result)
    {
        //
        // handle last unmatched
        //

        if (!_last_unmatched.empty()) {
            if (_last_unmatched.size() + data.size() < _sig.size()) {
                _last_unmatched.insert(_last_unmatched.end(), data.begin(), data.end());
                return;
            }

            const auto copy_count = (std::min)(data.size(), _sig.size() - 1);
            const auto unmatched_count = _last_unmatched.size();
            const auto pop_count = unmatched_count + copy_count - _sig.size() + 1;

            _last_unmatched.insert(_last_unmatched.end(), data.begin(), data.begin() + copy_count);

            search_sig(_last_unmatched, base - unmatched_count, result);

            if (pop_count != unmatched_count) {
                _last_unmatched.erase(_last_unmatched.begin(), _last_unmatched.begin() + pop_count);
                return;
            }

            _last_unmatched.clear();
        }

        //
        // handle new data
        //

        const auto unmatched_begin = search_sig(data, base, result);
        _last_unmatched.insert(_last_unmatched.end(), unmatched_begin, data.end());
    }

private:
    signature _sig;
    std::vector<std::byte> _last_unmatched;

    constexpr std::span<std::byte>::iterator search_sig(
        const std::span<std::byte> &haystack, const std::byte *base,
        std::vector<const std::byte *> &result) const
    {
        const auto &sig_bytes = _sig.bytes();

        auto iter = haystack.begin();

        while (true) {
            if (static_cast<size_t>(haystack.end() - iter) < sig_bytes.size()) {
                return iter;
            }

            const auto sc_iter =
                std::search(iter, haystack.end(), sig_bytes.begin(), sig_bytes.end());
            if (sc_iter == haystack.end()) {
                return haystack.end() - sig_bytes.size() + 1;
            }

            result.emplace_back(base + (sc_iter - haystack.begin()));
            iter = sc_iter + 1;
        }
    }
};

///
/// @endcond
///

//////////////////////////////////////////////////
///
/// @brief A reader class, which is abstract
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class reader
{
public:
    ///
    /// @brief Default virtual destructor
    ///
    virtual ~reader() = default;

    ///
    /// @brief Return optional error message
    ///
    /// This function returns the optional error message before reading.
    ///
    /// @return std::optional<std::string> The optional error message.
    ///
    [[nodiscard]] virtual std::optional<std::string> error() const = 0;

    ///
    /// @brief Perform reading
    ///
    /// The override of this function requires thread safety.
    ///
    /// @param[in]  address The address to be read.
    /// @param[in]  size    The size to be read.
    /// @param[out] result  The vector used to write back the result. No preparation is required
    ///                     from the caller.
    ///
    /// @return bool Whether this read is successful or not.
    ///
    [[nodiscard]] virtual bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const = 0;
};

///
/// @brief A memory reader for this processes
///
class this_process_memory_reader final : public reader
{
public:
    [[nodiscard]] inline std::optional<std::string> error() const override
    {
        return std::nullopt;
    }

    [[nodiscard]] inline bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const override
    {
        result.resize(size);
        std::memcpy(result.data(), address, size);
        return true;
    }
};

///
/// @brief A memory reader for external processes
///
class external_process_memory_reader final : public reader
{
public:
    ///
    /// @brief Constructor
    ///
    /// @param[in] pid The target process id.
    ///
    explicit inline external_process_memory_reader(process_id pid)
        : _pid{std::move(pid)}, _handle{details::open_process(_pid)}
    {
    }

    [[nodiscard]] inline std::optional<std::string> error() const override
    {
        if (_handle) {
            return std::nullopt;
        }
        return std::format("Failed to open process. ({})", _pid);
    }

    [[nodiscard]] inline bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const override
    {
        if (error().has_value()) {
            return false;
        }
        result.resize(size);
#if defined SIGMATCH_PLATFORM_WINDOWS
        size_t read_size = 0;
        return ReadProcessMemory(
                   _handle.get().value(), address, result.data(), size,
                   reinterpret_cast<SIZE_T *>(&read_size)) &&
               size == read_size;
#elif defined SIGMATCH_PLATFORM_LINUX
        const auto base = reinterpret_cast<uintptr_t>(address);
        size_t read_size = 0;
        while (read_size < size) {
    #if defined __USE_LARGEFILE64
            const auto ret = ::pread64(
                _handle.get().value(), result.data() + read_size, size - read_size,
                static_cast<off64_t>(base + read_size));
    #else
            const auto ret = ::pread(
                _handle.get().value(), result.data() + read_size, size - read_size,
                static_cast<off_t>(base + read_size));
    #endif
            if (ret < 0 && errno == EINTR) {
                continue;
            }
            if (ret <= 0) {
                return false;
            }
            read_size += static_cast<size_t>(ret);
        }
        return true;
#else
    #error "Unimplemented."
#endif
    }

private:
    process_id _pid;
    details::unique_process_handle _handle;
};

///
/// @brief A file content reader, suitable for searching in files
///
class file_content_reader final : public reader
{
public:
    ///
    /// @brief Constructor
    ///
    /// @param[in] file_path The target file path.
    ///
    explicit inline file_content_reader(std::filesystem::path file_path)
        : _file_path{std::move(file_path)}, _stream{_file_path, std::ios::binary}
    {
    }

    [[nodiscard]] inline std::optional<std::string> error() const override
    {
        // `is_open()` rather than `good()`: a read that hits EOF sets the stream state, but the
        // file is still usable.
        if (_stream.is_open()) {
            return std::nullopt;
        }
        return std::format("Failed to open file. ({})", _file_path.string());
    }

    [[nodiscard]] inline bool
    read(const void *address, size_t size, std::vector<std::byte> &result) const override
    {
        result.resize(size);

        std::lock_guard<std::mutex> lock{_read_mutex};
        // Clear the state left by a previous failed read, otherwise `seekg` would be a no-op and
        // every following read would fail.
        _stream.clear();
        _stream.seekg(reinterpret_cast<uintptr_t>(address));
        _stream.read(reinterpret_cast<char *>(result.data()), size);
        return _stream.good();
    }

private:
    std::filesystem::path _file_path;
    mutable std::mutex _read_mutex;
    mutable std::ifstream _stream;
};

//////////////////////////////////////////////////
///
/// @brief A search result class where matched addresses, error messages and warning messages will
///        be stored.
///
class search_result
{
public:
    ///
    /// @brief Type of container for matches
    ///
    using matches_type = std::vector<const std::byte *>;

    ///
    /// @brief Type of container for messages
    ///
    using messages_type = std::vector<std::string>;

    ///
    /// @brief Equal to operator
    ///
    /// @param[in] rhs A right hand side value.
    ///
    /// @return bool Whether they are equal.
    ///
    [[nodiscard]] constexpr bool operator==(const search_result &rhs) const noexcept = default;

    ///
    /// @cond
    ///

    constexpr search_result &operator+=(const search_result &rhs) = delete;

    constexpr search_result &operator+=(search_result &&rhs)
    {
        details::insert_vector(_matches, std::move(rhs._matches));
        details::insert_vector(_error_messages, std::move(rhs._error_messages));
        details::insert_vector(_warning_messages, std::move(rhs._warning_messages));

        return *this;
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Get matched addresses
    ///
    /// @return const matches_type & Matched addresses.
    ///
    [[nodiscard]] constexpr const matches_type &matches() const noexcept
    {
        return _matches;
    }

    ///
    /// @cond
    ///

    [[nodiscard]] constexpr matches_type &matches() noexcept
    {
        return _matches;
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Get error messages
    ///
    /// @return const messages_type & Error messages.
    ///
    /// @sa has_error()
    ///
    [[nodiscard]] constexpr const messages_type &error_messages() const noexcept
    {
        return _error_messages;
    }

    ///
    /// @cond
    ///

    [[nodiscard]] constexpr messages_type &error_messages() noexcept
    {
        return _error_messages;
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Get warning messages
    ///
    /// @return const messages_type & Warning messages.
    ///
    /// @sa has_warning()
    ///
    [[nodiscard]] constexpr const messages_type &warning_messages() const noexcept
    {
        return _warning_messages;
    }

    ///
    /// @cond
    ///

    [[nodiscard]] constexpr messages_type &warning_messages() noexcept
    {
        return _warning_messages;
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Check whether there are errors
    ///
    /// @return bool Whether there are errors.
    ///
    /// @sa error_messages()
    ///
    [[nodiscard]] constexpr bool has_error() const noexcept
    {
        return !_error_messages.empty();
    }

    ///
    /// @brief Check whether there are warnings
    ///
    /// @return bool Whether there are warnings.
    ///
    /// @sa warning_messages()
    ///
    [[nodiscard]] constexpr bool has_warning() const noexcept
    {
        return !_warning_messages.empty();
    }

    ///
    /// @brief Make an error result
    ///
    /// @param[in] error The error message.
    ///
    /// @return search_result An search result that contains the error.
    ///
    [[nodiscard]] static constexpr search_result make_error(std::string error)
    {
        search_result result;
        result.error_messages().emplace_back(std::move(error));
        return result;
    }

    ///
    /// @brief Make an warning result
    ///
    /// @param[in] warning The warning message.
    ///
    /// @return search_result An search result that contains the warning.
    ///
    [[nodiscard]] static constexpr search_result make_warning(std::string warning)
    {
        search_result result;
        result.warning_messages().emplace_back(std::move(warning));
        return result;
    }

private:
    matches_type _matches;
    messages_type _error_messages, _warning_messages;
};

//////////////////////////////////////////////////
// signature set matching
//
// (for internal use)
//

///
/// @cond
///

namespace impl {

// Bytes that are very common in x86 / x64 machine code (and padding). Anchors avoid them so that
// fewer positions have to be verified.
inline constexpr std::array<unsigned char, 256> common_code_bytes = [] {
    std::array<unsigned char, 256> table{};
    for (const int value : {0x00, 0x01, 0x08, 0x0F, 0x10, 0x20, 0x24, 0x33, 0x40, 0x41, 0x44,
                            0x45, 0x48, 0x49, 0x4C, 0x4D, 0x74, 0x75, 0x80, 0x83, 0x85, 0x89,
                            0x8B, 0x8D, 0x90, 0xC0, 0xC3, 0xC7, 0xCC, 0xE8, 0xFF}) {
        table[value] = 1;
    }
    return table;
}();

} // namespace impl

// Prepares a signature set for single-pass matching.
//
// Every signature gets an anchor: two consecutive fully specified bytes, or one if it has no such
// pair. A table indexed by those bytes gives, for each position of the data, the few signatures
// that are worth verifying there. Signatures without a fully specified byte are verified at every
// position.
class signature_set_index final
{
public:
    explicit inline signature_set_index(const signature_set &set) : _set{set}
    {
        const auto &sigs = set.signatures();
        _infos.reserve(sigs.size());

        // (signature index, table key)
        std::vector<std::pair<uint32_t, uint32_t>> pair_anchored, byte_anchored;

        for (size_t s = 0; s < sigs.size(); ++s) {
            const auto &bytes = sigs[s].bytes();
            const auto index = static_cast<uint32_t>(s);

            sig_info info{_values.size(), bytes.size(), 0};
            for (const auto &byte : bytes) {
                _values.push_back(byte.value());
                _masks.push_back(byte.mask());
            }
            _max_size = (std::max)(_max_size, bytes.size());

            if (bytes.empty()) {
                _infos.push_back(info);
                continue;
            }

            const auto fixed = [&](size_t j) { return bytes[j].mask() == std::byte{0xFF}; };
            const auto commonness = [&](size_t j) {
                return impl::common_code_bytes[std::to_integer<size_t>(bytes[j].value())];
            };

            size_t best = bytes.size();
            unsigned best_score = ~0u;
            for (size_t j = 0; j + 1 < bytes.size(); ++j) {
                if (fixed(j) && fixed(j + 1) && commonness(j) + commonness(j + 1) < best_score) {
                    best = j;
                    best_score = commonness(j) + commonness(j + 1);
                }
            }
            if (best != bytes.size()) {
                info.anchor = best;
                pair_anchored.emplace_back(
                    index, (std::to_integer<uint32_t>(bytes[best].value()) << 8) |
                               std::to_integer<uint32_t>(bytes[best + 1].value()));
                _infos.push_back(info);
                continue;
            }

            for (size_t j = 0; j < bytes.size(); ++j) {
                if (fixed(j) && commonness(j) < best_score) {
                    best = j;
                    best_score = commonness(j);
                }
            }
            if (best != bytes.size()) {
                info.anchor = best;
                byte_anchored.emplace_back(index, std::to_integer<uint32_t>(bytes[best].value()));
            }
            else {
                _unanchored.push_back(index);
            }
            _infos.push_back(info);
        }

        build_table(_pair_offsets, _pair_entries, 0x10000, pair_anchored);
        build_table(_byte_offsets, _byte_entries, 0x100, byte_anchored);
    }

    [[nodiscard]] constexpr const signature_set &set() const noexcept
    {
        return _set;
    }

    [[nodiscard]] constexpr size_t size() const noexcept
    {
        return _infos.size();
    }

    // The size of the longest signature
    [[nodiscard]] constexpr size_t max_size() const noexcept
    {
        return _max_size;
    }

    // Records, in `results` (one per signature), the matches in `buffer` that end at or after
    // `new_begin`; the ones that end before were recorded with the previous data. `buffer[0]` is
    // at address `base`. Matches of each signature are recorded in ascending order.
    inline void match(
        std::span<const std::byte> buffer, size_t new_begin, const std::byte *base,
        std::vector<search_result> &results) const
    {
        const std::byte *data = buffer.data();
        const size_t size = buffer.size();

        const auto verify = [&](uint32_t s, size_t start) {
            const auto &info = _infos[s];
            const size_t end = start + info.size;
            if (end > size || end <= new_begin) {
                return;
            }
            const std::byte *values = _values.data() + info.begin;
            const std::byte *masks = _masks.data() + info.begin;
            const std::byte *bytes = data + start;
            for (size_t j = 0; j < info.size; ++j) {
                if (((bytes[j] & masks[j]) ^ values[j]) != std::byte{0}) {
                    return;
                }
            }
            results[s].matches().emplace_back(base + start);
        };

        if (!_pair_entries.empty()) {
            for (size_t q = 0; q + 1 < size; ++q) {
                const size_t key =
                    (std::to_integer<size_t>(data[q]) << 8) | std::to_integer<size_t>(data[q + 1]);
                for (uint32_t e = _pair_offsets[key], last = _pair_offsets[key + 1]; e < last; ++e) {
                    const uint32_t s = _pair_entries[e];
                    if (q >= _infos[s].anchor) {
                        verify(s, q - _infos[s].anchor);
                    }
                }
            }
        }

        if (!_byte_entries.empty()) {
            for (size_t q = 0; q < size; ++q) {
                const size_t key = std::to_integer<size_t>(data[q]);
                for (uint32_t e = _byte_offsets[key], last = _byte_offsets[key + 1]; e < last; ++e) {
                    const uint32_t s = _byte_entries[e];
                    if (q >= _infos[s].anchor) {
                        verify(s, q - _infos[s].anchor);
                    }
                }
            }
        }

        for (const uint32_t s : _unanchored) {
            const size_t sig_size = _infos[s].size;
            const size_t first = new_begin >= sig_size ? new_begin - sig_size + 1 : 0;
            for (size_t start = first; start + sig_size <= size; ++start) {
                verify(s, start);
            }
        }
    }

private:
    struct sig_info
    {
        size_t begin; // in `_values` / `_masks`
        size_t size;
        size_t anchor; // offset of the anchor in the signature
    };

    const signature_set &_set;
    std::vector<sig_info> _infos;
    std::vector<std::byte> _values, _masks; // all signatures, concatenated
    size_t _max_size{0};

    // Signatures by anchor, as offsets (one per key, plus one) into the entries
    std::vector<uint32_t> _pair_offsets, _pair_entries;
    std::vector<uint32_t> _byte_offsets, _byte_entries;
    std::vector<uint32_t> _unanchored;

    static inline void build_table(
        std::vector<uint32_t> &offsets, std::vector<uint32_t> &entries, size_t keys,
        const std::vector<std::pair<uint32_t, uint32_t>> &items)
    {
        if (items.empty()) {
            return;
        }
        offsets.assign(keys + 1, 0);
        for (const auto &item : items) {
            ++offsets[item.second + 1];
        }
        for (size_t i = 0; i < keys; ++i) {
            offsets[i + 1] += offsets[i];
        }
        entries.resize(items.size());
        std::vector<uint32_t> next{offsets.begin(), offsets.end() - 1};
        for (const auto &item : items) {
            entries[next[item.second]++] = item.first;
        }
    }
};

// Matches a signature set against data that arrives block by block, keeping the tail of the
// previous blocks for matches that cross block boundaries.
class signature_set_matcher final
{
public:
    explicit inline signature_set_matcher(const signature_set_index &index) noexcept
        : _index{index}
    {
    }

    inline void reset() noexcept
    {
        _buffer.clear();
    }

    // `data` is at address `base`, right after the previous data (unless reset).
    inline void match(
        std::span<const std::byte> data, const std::byte *base, std::vector<search_result> &results)
    {
        const size_t tail = _buffer.size();
        _buffer.insert(_buffer.end(), data.begin(), data.end());
        _index.match(_buffer, tail, base - tail, results);

        // Matches that end in the next block start in its last `max_size() - 1` bytes at most.
        const size_t keep = (std::min)(_buffer.size(), _index.max_size() - 1);
        _buffer.erase(_buffer.begin(), _buffer.end() - static_cast<std::ptrdiff_t>(keep));
    }

private:
    const signature_set_index &_index;
    std::vector<std::byte> _buffer;
};

///
/// @endcond
///

//////////////////////////////////////////////////
///
/// @brief A reader class, which is abstract
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class searcher
{
public:
    ///
    /// @brief Constructor
    ///
    /// @param[in] reader_ The reader.
    ///
    explicit inline searcher(std::shared_ptr<class reader> reader_) noexcept
        : _reader{std::move(reader_)}
    {
    }

    ///
    /// @brief Default virtual destructor
    ///
    virtual ~searcher() = default;

    ///
    /// @brief Get the reader
    ///
    /// @return const std::shared_ptr<reader> & The reader.
    ///
    [[nodiscard]] constexpr const std::shared_ptr<class reader> &reader() const noexcept
    {
        return _reader;
    }

    ///
    /// @brief Perform search with single range
    ///
    /// @param[in]  range  The search range.
    /// @param[in]  sig    The signature to search for.
    /// @param[out] result A search result.
    ///
    virtual void
    search(const const_byte_span &range, const signature &sig, search_result &result) const = 0;

    ///
    /// @brief Perform search with multiple ranges
    ///
    /// @param[in]  ranges The search ranges.
    /// @param[in]  sig    The signature to search for.
    /// @param[out] result A search result.
    ///
    constexpr void search(
        const std::vector<const_byte_span> &ranges, const signature &sig,
        search_result &result) const
    {
        for (const auto &range : ranges) {
            if (range.size() == 0) {
                continue;
            }
            search(range, sig, result);
        }
    }

    ///
    /// @brief Perform search for a signature set with multiple ranges
    ///
    /// The ranges are read once for all signatures of the set.
    ///
    /// @param[in]  ranges  The search ranges.
    /// @param[in]  set     The signatures to search for.
    /// @param[out] results The search results, one per signature, in the order of the set.
    ///
    inline void search(
        const std::vector<const_byte_span> &ranges, const signature_set &set,
        std::vector<search_result> &results) const
    {
        if (results.size() < set.size()) {
            results.resize(set.size());
        }
        const signature_set_index index{set};
        for (const auto &range : ranges) {
            if (range.size() == 0) {
                continue;
            }
            search(range, index, results);
        }
    }

    ///
    /// @cond
    ///

    // Searches a single range for a prepared signature set. This default implementation searches
    // for each signature separately, so that searchers implementing only single signatures keep
    // working; the library's searchers override it to read the range only once.
    virtual void search(
        const const_byte_span &range, const signature_set_index &index,
        std::vector<search_result> &results) const
    {
        const auto &sigs = index.set().signatures();
        for (size_t i = 0; i < sigs.size(); ++i) {
            search(range, sigs[i], results[i]);
        }
    }

    ///
    /// @endcond
    ///

private:
    std::shared_ptr<class reader> _reader;
};

///
/// @brief A blocking (chunking) searcher
///
/// This class will divide the search range into multiple blocks for single-threaded search to
/// reduce the number of reads and increase the search speed.
///
class blocking_searcher : public searcher
{
public:
    using searcher::search;

    ///
    /// @brief Constructor
    ///
    /// @param[in] reader_    The reader.
    /// @param[in] block_size The size of the block to be read each time. The default value is
    ///                       `SIGMATCH_BLOCK_SIZE`.
    ///
    /// @sa SIGMATCH_BLOCK_SIZE
    ///
    explicit inline blocking_searcher(
        std::shared_ptr<class reader> reader_, allow_default<size_t> block_size = default_value)
        : searcher{std::move(reader_)}, _block_size{block_size.value_or(SIGMATCH_BLOCK_SIZE)}
    {
    }

    inline void
    search(const const_byte_span &range, const signature &sig, search_result &result) const override
    {
        if (sig.bytes().empty()) {
            return;
        }

        if (_block_size == 0) {
            result.error_messages().emplace_back("The value of `block_size` cannot be `0`.");
            return;
        }

        bool reading_failed = false;
        matcher matcher_{sig};

        std::vector<std::byte> read_buffer;

        for (size_t i = 0; i < range.size(); i += _block_size) {
            const auto ptr = range.data() + i;
            const auto size = (std::min)(_block_size, range.size() - i);

            if (!reader()->read(ptr, size, read_buffer)) {
                reading_failed = true;
                // The next block is not contiguous with the buffered tail any more.
                matcher_.reset();
#if defined SIGMATCH_STORE_EACH_READING_FAILURE_WARNING_MESSAGE
                result.warning_messages().emplace_back(std::format(
                    "Failed to read {:#x} byte(s) at {}", size, static_cast<const void *>(ptr)));
#endif
            }
            else {
                matcher_.match(read_buffer, ptr, result.matches());
            }
        }

        if (reading_failed) {
            result.warning_messages().emplace_back(
                "Some reads failed, the result may be incomplete.");
        }
    }

    ///
    /// @cond
    ///

    inline void search(
        const const_byte_span &range, const signature_set_index &index,
        std::vector<search_result> &results) const override
    {
        if (index.max_size() == 0) {
            return;
        }

        const auto for_each_result = [&](const auto &callback) {
            for (size_t s = 0; s < index.size(); ++s) {
                callback(results[s]);
            }
        };

        if (_block_size == 0) {
            for_each_result([](search_result &result) {
                result.error_messages().emplace_back("The value of `block_size` cannot be `0`.");
            });
            return;
        }

        bool reading_failed = false;
        signature_set_matcher matcher_{index};

        std::vector<std::byte> read_buffer;

        for (size_t i = 0; i < range.size(); i += _block_size) {
            const auto ptr = range.data() + i;
            const auto size = (std::min)(_block_size, range.size() - i);

            if (!reader()->read(ptr, size, read_buffer)) {
                reading_failed = true;
                matcher_.reset();
#if defined SIGMATCH_STORE_EACH_READING_FAILURE_WARNING_MESSAGE
                const auto message = std::format(
                    "Failed to read {:#x} byte(s) at {}", size, static_cast<const void *>(ptr));
                for_each_result(
                    [&](search_result &result) { result.warning_messages().push_back(message); });
#endif
            }
            else {
                matcher_.match(read_buffer, ptr, results);
            }
        }

        if (reading_failed) {
            for_each_result([](search_result &result) {
                result.warning_messages().emplace_back(
                    "Some reads failed, the result may be incomplete.");
            });
        }
    }

    ///
    /// @endcond
    ///

private:
    size_t _block_size;
};

///
/// @brief A multi-threaded searcher
///
/// This class will launch multiple threads for search to increase the search speed.
///
/// @sa SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD
///
class multi_threaded_searcher : public blocking_searcher
{
private:
    struct thread_info
    {
        std::thread thread;
        const_byte_span range;
        search_result result;
    };

public:
    using searcher::search;

    ///
    /// @brief Constructor
    ///
    /// @param[in] reader_           The reader.
    /// @param[in] threads_max_count The maximum allowed thread count. The default value is
    ///                              `std::thread::hardware_concurrency()`
    /// @param[in] block_size        The size of the block to be read each time. The default value
    ///                              is `SIGMATCH_BLOCK_SIZE`.
    ///
    /// @sa SIGMATCH_BLOCK_SIZE
    ///
    explicit inline multi_threaded_searcher(
        std::shared_ptr<class reader> reader_,
        allow_default<size_t> threads_max_count = default_value,
        allow_default<size_t> block_size = default_value)
        : blocking_searcher{std::move(reader_), std::move(block_size)},
          _threads_max_count{threads_max_count.value_or(std::thread::hardware_concurrency())}
    {
    }

    inline void
    search(const const_byte_span &range, const signature &sig, search_result &result) const override
    {
        if (sig.bytes().empty()) {
            return;
        }

        if (_threads_max_count == 0) {
            result.error_messages().emplace_back("The value of `threads_max_count` cannot be `0`.");
            return;
        }

        std::vector<thread_info> infos = assign_tasks(range, sig);
        if (infos.size() <= 1) {
            blocking_searcher::search(range, sig, result); // search in the current thread directly
            return;
        }

        // launch threads
        for (auto &info : infos) {
            info.thread = std::thread{
                &multi_threaded_searcher::search_thread, this, std::cref(info.range),
                std::cref(sig), std::ref(info.result)};
        }

        size_t matches_count = 0, error_count = 0, warning_count = 0;

        // join threads
        for (auto &info : infos) {
            if (info.thread.joinable()) {
                info.thread.join();
            }
            matches_count += info.result.matches().size();
            error_count += info.result.error_messages().size();
            warning_count += info.result.warning_messages().size();
        }

        // merge
        result.matches().reserve(result.matches().size() + matches_count);
        result.error_messages().reserve(result.error_messages().size() + error_count);
        result.warning_messages().reserve(result.warning_messages().size() + warning_count);

        for (size_t i = 0; i < infos.size(); ++i) {
            auto &&thread_result = std::move(infos[i].result);
            result += std::move(thread_result);
        }

        // sort
        std::sort(result.matches().begin(), result.matches().end(), std::less<>{});
    }

    ///
    /// @cond
    ///

    inline void search(
        const const_byte_span &range, const signature_set_index &index,
        std::vector<search_result> &results) const override
    {
        if (index.max_size() == 0) {
            return;
        }

        if (_threads_max_count == 0) {
            for (size_t s = 0; s < index.size(); ++s) {
                results[s].error_messages().emplace_back(
                    "The value of `threads_max_count` cannot be `0`.");
            }
            return;
        }

        const auto chunks = split_range(range, index.max_size());
        if (chunks.size() <= 1) {
            blocking_searcher::search(range, index, results); // search in the current thread directly
            return;
        }

        std::vector<std::vector<search_result>> chunk_results(
            chunks.size(), std::vector<search_result>(index.size()));

        {
            std::vector<std::thread> threads;
            threads.reserve(chunks.size());

            // Joins the started threads even if starting another one throws.
            struct joiner
            {
                std::vector<std::thread> &threads;
                ~joiner()
                {
                    for (auto &thread : threads) {
                        if (thread.joinable()) {
                            thread.join();
                        }
                    }
                }
            } join_all{threads};

            for (size_t t = 0; t < chunks.size(); ++t) {
                threads.emplace_back([this, &chunks, &index, &chunk_results, t] {
                    blocking_searcher::search(chunks[t], index, chunk_results[t]);
                });
            }
        }

        // merge
        for (size_t t = 0; t < chunks.size(); ++t) {
            // Shorter signatures can match entirely inside the overlap with the next chunk, those
            // matches belong to the next chunk.
            const std::byte *owned_end = t + 1 < chunks.size() ? chunks[t + 1].data() : nullptr;

            for (size_t s = 0; s < index.size(); ++s) {
                auto &from = chunk_results[t][s];
                auto &to = results[s];
                for (const std::byte *match : from.matches()) {
                    if (owned_end == nullptr || match < owned_end) {
                        to.matches().push_back(match);
                    }
                }
                details::insert_vector(to.error_messages(), std::move(from.error_messages()));
                details::insert_vector(to.warning_messages(), std::move(from.warning_messages()));
            }
        }

        // sort, like the single signature search does
        for (size_t s = 0; s < index.size(); ++s) {
            std::sort(results[s].matches().begin(), results[s].matches().end(), std::less<>{});
        }
    }

    ///
    /// @endcond
    ///

private:
    size_t _threads_max_count;

    [[nodiscard]] inline std::vector<thread_info>
    assign_tasks(const const_byte_span &range, const signature &sig) const
    {
        std::vector<thread_info> threads;
        for (const auto &chunk : split_range(range, sig.size())) {
            threads.emplace_back(std::thread{}, chunk);
        }
        return threads;
    }

    // Splits `range` into one chunk per thread. Each chunk overlaps the next one by
    // `sig_size - 1` bytes so that a match crossing their boundary is complete in the first.
    [[nodiscard]] inline std::vector<const_byte_span>
    split_range(const const_byte_span &range, size_t sig_size) const
    {
        const auto [threads_count, average_size] = appropriate_data(range);

        std::vector<const_byte_span> chunks;
        chunks.reserve(threads_count);

        for (size_t i = 0; i < threads_count; ++i) {
            const auto offset = i * average_size;
            const auto ptr = range.data() + offset;
            auto size = (std::min)(average_size + sig_size - 1, range.size() - offset);

            const auto next_size = range.size() - offset - size;
            if (i + 1 == threads_count && next_size > 0) {
                size += next_size;
            }

            chunks.emplace_back(ptr, size);
        }

        return chunks;
    }

    // returns `std::pair<threads_count, average_size>`
    //
    [[nodiscard]] constexpr std::pair<size_t, size_t> appropriate_data(
        const const_byte_span &range,
        size_t min_size_for_one_thread =
            SIGMATCH_MULTI_THREADED_SEARCH_SIZE_THRESHOLD) const noexcept
    {
        size_t threads_count;
        if (range.size() <= _threads_max_count * min_size_for_one_thread) {
            threads_count = (std::max)(range.size() / min_size_for_one_thread, size_t{1});
        }
        else {
            threads_count = _threads_max_count;
        }

        const size_t average_size = range.size() / threads_count;

        return std::make_pair(threads_count, average_size);
    }

    inline void
    search_thread(const const_byte_span &range, const signature &sig, search_result &result) const
    {
        blocking_searcher::search(range, sig, result);
    }
};

///
/// @brief The class represents the search context, which is usually returned by a member function
///        of `target`
///
class search_context
{
public:
    ///
    /// @brief Search executor
    ///
    /// @tparam SearcherT The searcher type.
    ///
    /// @note Users should not construct this class directly.
    ///
    template <kind_of_searcher SearcherT>
    class executor;

    ///
    /// @brief Default constructor
    ///
    search_context() noexcept = default;

    ///
    /// @brief Constructor with single range
    ///
    /// @param[in] range   The search range.
    /// @param[in] reader_ The reader.
    ///
    explicit inline search_context(const_byte_span range, std::shared_ptr<reader> reader_) noexcept
        : search_context{std::vector<const_byte_span>{std::move(range)}, std::move(reader_)}
    {
    }

    ///
    /// @brief Constructor with multiple ranges
    ///
    /// @param[in] ranges  Multiple search ranges.
    /// @param[in] reader_ The reader.
    ///
    explicit inline search_context(
        std::vector<const_byte_span> ranges, std::shared_ptr<reader> reader_) noexcept
        : _ranges{std::move(ranges)}, _reader{std::move(reader_)}
    {
    }

    ///
    /// @brief Make an error context
    ///
    /// It will be written to the search_result if the search is still performed.
    ///
    /// @param[in] error The error message.
    ///
    /// @return search_context An search context that contains the error.
    ///
    [[nodiscard]] static inline search_context make_error(std::string error) noexcept
    {
        search_context result;
        result._error = std::move(error);
        return result;
    }

    ///
    /// @brief Get the optional error.
    ///
    /// @return std::optional<std::string> The optional error.
    ///
    [[nodiscard]] inline std::optional<std::string> error() const
    {
        return _error;
    }

    ///
    /// @brief Select a searcher
    ///
    /// @tparam SearcherT The searcher type.
    ///
    /// @param[in] args Remaining arguments in the constructor of searcher except for the reader,
    ///                 which usually have default values, will be forwarded if user values are
    ///                 specified.
    ///
    /// @return executor<SearcherT> The searcher executor.
    ///
    /// @sa executor
    ///
    template <kind_of_searcher SearcherT = blocking_searcher, class... ArgsT>
    [[nodiscard]] constexpr auto select(ArgsT &&...args) const
    {
        return executor<SearcherT>{*this, SearcherT{_reader, std::forward<ArgsT>(args)...}};
    }

    ///
    /// @brief Perform search with the default searcher
    ///
    /// @param[in] sig The signature.
    ///
    /// @return search_result A search result.
    ///
    /// @sa searcher signature sigmatch_literals::operator ""_sig()
    ///
    [[nodiscard]] inline search_result search(const signature &sig) const;

    ///
    /// @brief Perform search for a signature set with the default searcher
    ///
    /// The ranges are read once for all signatures of the set.
    ///
    /// @param[in] set The signatures.
    ///
    /// @return std::vector<search_result> The search results, one per signature, in the order of
    ///                                    the set.
    ///
    [[nodiscard]] inline std::vector<search_result> search(const signature_set &set) const;

private:
    std::vector<const_byte_span> _ranges;
    std::shared_ptr<reader> _reader;
    std::optional<std::string> _error;
};

///
/// @brief Search executor
///
/// @tparam SearcherT The searcher type.
///
/// @note Users should not construct this class directly.
///
// Defined out of class because it stores a `search_context`, which has to be complete.
template <kind_of_searcher SearcherT>
class search_context::executor
{
public:
    ///
    /// @cond
    ///

    explicit inline executor(search_context ctx, SearcherT searcher_) noexcept
        : _searcher{std::move(searcher_)}, _ctx{std::move(ctx)}
    {
    }

    ///
    /// @endcond
    ///

    ///
    /// @brief Perform search with the selected searcher
    ///
    /// @param[in] sig The signature.
    ///
    /// @return search_result A search result.
    ///
    /// @sa searcher signature sigmatch_literals::operator ""_sig()
    ///
    [[nodiscard]] constexpr search_result search(const signature &sig) const
    {
        if (_ctx._error.has_value()) {
            return search_result::make_error(_ctx._error.value());
        }

        if (!_ctx._reader) {
            return search_result::make_error("No reader.");
        }

        auto reader_error = _ctx._reader->error();
        if (reader_error.has_value()) {
            return search_result::make_error(std::move(reader_error.value()));
        }

        if (_ctx._ranges.empty()) {
            return search_result{};
        }

        search_result result;
        _searcher.search(_ctx._ranges, sig, result);
        return result;
    }

    ///
    /// @brief Perform search for a signature set with the selected searcher
    ///
    /// The ranges are read once for all signatures of the set.
    ///
    /// @param[in] set The signatures.
    ///
    /// @return std::vector<search_result> The search results, one per signature, in the order of
    ///                                    the set.
    ///
    [[nodiscard]] inline std::vector<search_result> search(const signature_set &set) const
    {
        const auto errors = [&](std::string error) {
            return std::vector<search_result>(set.size(), search_result::make_error(std::move(error)));
        };

        if (_ctx._error.has_value()) {
            return errors(_ctx._error.value());
        }

        if (!_ctx._reader) {
            return errors("No reader.");
        }

        auto reader_error = _ctx._reader->error();
        if (reader_error.has_value()) {
            return errors(std::move(reader_error.value()));
        }

        std::vector<search_result> results(set.size());
        if (!_ctx._ranges.empty()) {
            _searcher.search(_ctx._ranges, set, results);
        }
        return results;
    }

private:
    SearcherT _searcher;
    search_context _ctx;
};

inline search_result search_context::search(const signature &sig) const
{
    return select().search(sig);
}

inline std::vector<search_result> search_context::search(const signature_set &set) const
{
    return select().search(set);
}

//////////////////////////////////////////////////
// target
//

///
/// @brief Base class for all targets
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class target
{
public:
    ///
    /// @brief Constructor
    ///
    /// @param[in] reader_ The reader.
    ///
    /// @sa reader
    ///
    explicit inline target(std::shared_ptr<class reader> reader_) noexcept
        : _reader{std::move(reader_)}
    {
    }

    ///
    /// @brief Default virtual destructor
    ///
    virtual ~target() = default;

    ///
    /// @cond
    ///

    target(const target &) = default;
    target(target &&) noexcept = default;
    target &operator=(const target &) = default;
    target &operator=(target &&) noexcept = default;

    ///
    /// @endcond
    ///

    ///
    /// @brief Get the optional error in the target.
    ///
    /// @return std::optional<std::string> The optional error.
    ///
    [[nodiscard]] virtual inline std::optional<std::string> error() const
    {
        return _reader->error();
    }

    ///
    /// @brief Get the reader.
    ///
    /// @return const std::shared_ptr<reader> & The reader.
    ///
    [[nodiscard]] constexpr const std::shared_ptr<class reader> &reader() const noexcept
    {
        return _reader;
    }

private:
    std::shared_ptr<class reader> _reader;
};

///
/// @brief Base class for all targets that access memory
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class access_memory_target : public target
{
public:
    using target::target;

    ///
    /// @brief Specify a range in memory
    ///
    /// @param[in] range A range in memory.
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context in_range(const_byte_span range) const noexcept
    {
        return search_context{std::move(range), reader()};
    }

    ///
    /// @brief Specify multiple ranges in memory
    ///
    /// @param[in] ranges Multiple ranges in memory.
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context in_range(std::vector<const_byte_span> ranges) const noexcept
    {
        return search_context{std::move(ranges), reader()};
    }
};

///
/// @brief Base class for all targets that access file
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class access_file_target : public target
{
public:
    using target::target;

    ///
    /// @brief Specify a range in the file
    ///
    /// @param[in] offset A offset in the file.
    /// @param[in] size   A size of the range.
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context in_range(size_t offset, size_t size) const noexcept
    {
        return search_context{
            const_byte_span{reinterpret_cast<const void *>(offset), size}, reader()};
    }
};

///
/// @brief A structure to represent the information of a process module
///
struct process_module_info
{
    ///
    /// @brief The module name
    ///
    platform_string name;

    ///
    /// @brief The module memory range
    ///
    const_byte_span range;
};

///
/// @brief Base class for all targets that operate process
///
/// @note Users should not use this class directly, but can inherit it to implement your own stuff.
///
class process_target : public access_memory_target
{
private:
    using union_err_mod_t = std::variant<search_context, process_module_info>;

public:
    ///
    /// @brief Constructor
    ///
    /// @param[in] pid     A process id.
    /// @param[in] reader_ A reader.
    ///
    explicit inline process_target(process_id pid, std::shared_ptr<class reader> reader_) noexcept
        : access_memory_target{std::move(reader_)}, _pid{std::move(pid)}
    {
    }

    ///
    /// @brief Specify a module in the process
    ///
    /// @param[in] name A module name.
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context in_module(const platform_string &name) const
    {
        auto err_or_mod = try_find_module(name);
        if (err_or_mod.index() == 0) {
            return std::get<search_context>(std::move(err_or_mod));
        }

        auto module_info = std::get<process_module_info>(std::move(err_or_mod));
#if defined SIGMATCH_PLATFORM_LINUX
        // Unlike PE images, ELF images usually have inaccessible (PROT_NONE) gaps between their
        // segments, so only the readable parts are searched.
        return in_range(query_readable(module_info.range));
#else
        return in_range(module_info.range);
#endif
    }

    ///
    /// @brief Specify a module and a memory protection in the process
    ///
    /// @param[in] name       A module name.
    /// @param[in] prot_flags A memory protection flags.
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context
    in_module(const platform_string &name, enum_flags<mem_prot> prot_flags) const
    {
        auto err_or_mod = try_find_module(name);
        if (err_or_mod.index() == 0) {
            return std::get<search_context>(std::move(err_or_mod));
        }

        auto module_info = std::get<process_module_info>(std::move(err_or_mod));
        return in_range(query_protection(module_info.range, prot_flags));
    }

    ///
    /// @brief Get the process id
    ///
    /// @return process_id The process id.
    ///
    [[nodiscard]] process_id pid() const noexcept
    {
        return _pid;
    }

private:
    [[nodiscard]] inline union_err_mod_t try_find_module(const platform_string &name) const
    {
        auto target_error = error();
        if (target_error.has_value()) {
            return union_err_mod_t{search_context::make_error(std::move(target_error.value()))};
        }

        auto opt_info = find_module(name);
        if (!opt_info.has_value()) {
            return union_err_mod_t{search_context::make_error(
                std::format("Module not found or failed. ({})", name.to_string()))};
        }

        return union_err_mod_t{std::move(opt_info.value())};
    }

    [[nodiscard]] inline std::optional<process_module_info>
    find_module(platform_string module_name) const
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return {};
        }

        module_name = details::text::to_lower(std::move(module_name.str()));

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (Module32FirstW(snapshot, &entry)) {
            do {
                process_module_info info{
                    .name = details::text::to_lower(entry.szModule),
                    .range = {entry.modBaseAddr, entry.modBaseSize},
                };

                if (info.name == module_name) {
                    return info;
                }

            } while (Module32NextW(snapshot, &entry));
        }

        return {};
#elif defined SIGMATCH_PLATFORM_LINUX
        auto regions = details::procfs::read_maps(_pid);
        if (!regions.has_value()) {
            return {};
        }

        const auto target_name = details::text::to_lower(std::move(module_name.str()));

        // The module spans from its first to its last file-backed mapping.
        const details::procfs::map_region *first = nullptr;
        uintptr_t end = 0;

        for (const auto &region : regions.value()) {
            if (first == nullptr) {
                if (region.path.empty() || region.path.front() != '/') {
                    continue;
                }
                const auto name = region.path.substr(region.path.rfind('/') + 1);
                if (details::text::to_lower(name) != target_name) {
                    continue;
                }
                first = &region;
                end = region.end;
            }
            else if (region.path == first->path) {
                if (region.offset == 0) {
                    break; // the same file is mapped again, it's another instance
                }
                end = (std::max)(end, region.end);
            }
        }

        if (first == nullptr) {
            return {};
        }

        return process_module_info{
            .name = first->path.substr(first->path.rfind('/') + 1),
            .range = {reinterpret_cast<const void *>(first->begin), end - first->begin},
        };
#else
    #error "Unimplemented."
#endif
    }

    [[nodiscard]] inline std::vector<const_byte_span>
    query_protection(const const_byte_span &range, enum_flags<mem_prot> prot_flags) const
    {
#if defined SIGMATCH_PLATFORM_WINDOWS
        std::vector<const_byte_span> result;

        auto handle = details::open_process(_pid);

        DWORD target_prot = 0;
        if (prot_flags.test(mem_prot::execute)) {
            if (prot_flags.test(mem_prot::write)) {
                target_prot = PAGE_EXECUTE_READWRITE;
            }
            else {
                target_prot = prot_flags.test(mem_prot::read) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
            }
        }
        else {
            target_prot = prot_flags.test(mem_prot::write) ? PAGE_READWRITE : PAGE_READONLY;
        }

        for (const std::byte *i = range.data(); i < range.data() + range.size();) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(handle.get().value(), i, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                break;
            }
            if (mbi.RegionSize == 0) {
                break;
            }

            if (mbi.State == MEM_COMMIT && mbi.Protect == target_prot) {
                result.emplace_back(const_byte_span{i, mbi.RegionSize});
            }
            i += mbi.RegionSize;
        }

        return result;
#elif defined SIGMATCH_PLATFORM_LINUX
        // Same mapping as the Windows implementation above, e.g. `write` alone means read-write
        // and no flags means read-only.
        enum_flags<mem_prot> target_prot = mem_prot::read;
        if (prot_flags.test(mem_prot::execute)) {
            if (prot_flags.test(mem_prot::write)) {
                target_prot = mem_prot::read | mem_prot::write | mem_prot::execute;
            }
            else {
                target_prot = prot_flags.test(mem_prot::read) ? mem_prot::read | mem_prot::execute
                                                              : mem_prot::execute;
            }
        }
        else if (prot_flags.test(mem_prot::write)) {
            target_prot = mem_prot::read | mem_prot::write;
        }

        return query_regions(range, [&](enum_flags<mem_prot> prot) { return prot == target_prot; });
#else
    #error "Unimplemented."
#endif
    }

#if defined SIGMATCH_PLATFORM_LINUX
    [[nodiscard]] inline std::vector<const_byte_span>
    query_readable(const const_byte_span &range) const
    {
        return query_regions(
            range, [](enum_flags<mem_prot> prot) { return prot.test(mem_prot::read); });
    }

    // Collects the parts of `range` whose protection satisfies `pred`, adjacent parts are merged so
    // that matches crossing a mapping boundary are not missed.
    template <class PredT>
    [[nodiscard]] inline std::vector<const_byte_span>
    query_regions(const const_byte_span &range, PredT pred) const
    {
        std::vector<const_byte_span> result;

        auto regions = details::procfs::read_maps(_pid);
        if (!regions.has_value()) {
            return result;
        }

        const auto range_begin = reinterpret_cast<uintptr_t>(range.data());
        const auto range_end = range_begin + range.size();

        for (const auto &region : regions.value()) {
            const auto begin = (std::max)(region.begin, range_begin);
            const auto end = (std::min)(region.end, range_end);
            if (begin >= end || !pred(region.prot)) {
                continue;
            }

            if (!result.empty()) {
                auto &last = result.back();
                const auto last_begin = reinterpret_cast<uintptr_t>(last.data());
                if (last_begin + last.size() == begin) {
                    last = const_byte_span{last.data(), end - last_begin};
                    continue;
                }
            }
            result.emplace_back(reinterpret_cast<const void *>(begin), end - begin);
        }

        return result;
    }
#endif

private:
    process_id _pid;
};

///
/// @brief A target class for operating on the current process
///
class this_process_target final : public process_target
{
public:
    ///
    /// @brief The default reader type for this target.
    ///
    using default_reader_type = this_process_memory_reader;

    ///
    /// @brief Constructor
    ///
    /// @param[in] reader_ A reader. The default reader type is `this_process_memory_reader`.
    ///
    explicit inline this_process_target(
        allow_default<std::shared_ptr<class reader>> reader_ = default_value)
        : process_target{
              current_process_id(),
              reader_.has_value() ? reader_.value() : std::make_shared<default_reader_type>()}
    {
    }
};

///
/// @brief A target class for operating on external processes
///
class external_process_target final : public process_target
{
public:
    ///
    /// @brief The default reader type for this target.
    ///
    using default_reader_type = external_process_memory_reader;

    ///
    /// @brief Constructor
    ///
    /// @param[in] pid     The target process id.
    /// @param[in] reader_ A reader. The default reader type is `external_process_memory_reader`.
    ///
    explicit inline external_process_target(
        process_id pid, allow_default<std::shared_ptr<class reader>> reader_ = default_value)
        : process_target{
              pid,
              reader_.has_value() ? reader_.value() : std::make_shared<default_reader_type>(pid)}
    {
    }
};

///
/// @brief A target class for operating on files
///
class file_target : public access_file_target
{
public:
    ///
    /// @brief The default reader type for this target.
    ///
    using default_reader_type = file_content_reader;

    ///
    /// @brief Constructor
    ///
    /// @param[in] file_path The target file path.
    /// @param[in] reader_   A reader. The default reader type is `file_content_reader`.
    ///
    explicit inline file_target(
        std::filesystem::path file_path,
        allow_default<std::shared_ptr<class reader>> reader_ = default_value)
        : access_file_target{reader_.has_value() ? reader_.value() : std::make_shared<default_reader_type>(file_path)},
          _file_path{std::move(file_path)}
    {
    }

    ///
    /// @brief Specifies the entire file
    ///
    /// @return search_context A search context.
    ///
    [[nodiscard]] inline search_context in_whole() const
    {
        auto target_error = error();
        if (target_error.has_value()) {
            return search_context::make_error(std::move(target_error.value()));
        }

        std::error_code ec;
        const auto file_size = std::filesystem::file_size(_file_path, ec);
        if (ec) {
            return search_context::make_error(std::format(
                "Get file size failed. (file: '{}', message: '{}')", _file_path.string(),
                ec.message()));
        }

        return in_range(0, file_size);
    }

private:
    std::filesystem::path _file_path;
};

// TODO: Implement class `executable_file_target`
//
// class executable_file_target : public access_file_target
// {
// public:
//     [[nodiscard]] inline search_context in_section(const std::string &name) const {}
//     [[nodiscard]] inline search_context in_section(enum_flags<mem_prot> prot_flags) const {}
// };

} // namespace sigmatch

///
/// @brief Library literals namespace
///
namespace sigmatch_literals {

///
/// @brief Literal signature string suffix, parsing at compile-time
///
/// For runtime parsing, see sigmatch::signature::parse(std::string_view sig).
///
/// @return sigmatch::signature A signature.
///
/// @remark
/// @code{.cpp}
///     using namespace sigmatch_literals;
/// @endcode
/// is required before using the suffix.
///
/// @remark
/// The literal signature string format has some requirements:
///     1. There must be at least one space between each byte (can be more than one, and spaces at
///        the beginning and end are also allowed).
///     2. Each byte must be represented by two hexadecimal value characters and is not allowed to
///        start with `0x` (e.g. `0A` and `1A`).
///     3. Wildcard characters are only allowed `?` and `*`, which can be mixed.
///     4. Allows full-byte wildcards (`??` or `**`) and semi-byte wildcards (`1?` or `*B`).
///     5. Don't forget the suffix `_sig`, without it, it's just a normal string.
///
/// @remark
/// Some examples of legitimate literal signature strings:
/// @code{.cpp}
///     "11 22 33 AA BB CC 1A B2 3C D4"_sig
///     "1A b2 3C d4 5E 6f"_sig
///     "1A ?? 3C ** *E 6?"_sig
///     "   1A B2 3C D4   "_sig
///     "1A    B2   3C D4 "_sig
/// @endcode
///
/// @sa SIGMATCH_EXPERIMENTAL_ENABLE_GHIDRA_SIGNATURE_FORMAT
/// sigmatch::signature::parse(std::string_view sig)
///
template <sigmatch::details::consteval_str_buffer kSigStrBuf>
[[nodiscard]] constexpr decltype(auto) operator""_sig()
{
    return sigmatch::signature{
        sigmatch::signature::____literal_place_t{},
        sigmatch::impl::parse_sig_str_compile_time<kSigStrBuf>()};
}

} // namespace sigmatch_literals

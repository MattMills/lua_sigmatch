-- test_sigmatch.lua : test suite for the sigmatch Lua module.
--
-- Usage: <lua> test_sigmatch.lua [module directory] [module file name]
--
-- Runs on LuaJIT and Lua 5.1 - 5.4. The memory tests that need raw buffers use the LuaJIT FFI and
-- are skipped elsewhere; everything else runs on every version.

local module_dir, module_name = ...
if module_dir and module_dir ~= "" then
    package.cpath = module_dir .. "/?.so;" .. module_dir .. "/?.dll;" .. package.cpath
end

local sm = require("sigmatch")
local unpack = table.unpack or unpack
local has_ffi, ffi = pcall(require, "ffi")

--------------------------------------------------
-- tiny test framework
--

local tests = {}

local function test(name, fn)
    tests[#tests + 1] = { name = name, fn = fn }
end

local function fail(message, level)
    error(message, (level or 1) + 1)
end

local function check(condition, message)
    if not condition then
        fail(message or "check failed", 2)
    end
end

local function eq(actual, expected, message)
    if actual ~= expected then
        fail(string.format("%s: expected %s, got %s", message or "values differ",
            tostring(expected), tostring(actual)), 2)
    end
end

local function list_eq(actual, expected, message)
    local function show(list)
        local parts = {}
        for i = 1, math.min(#list, 16) do
            parts[i] = string.format("%.0f", list[i])
        end
        return "{" .. table.concat(parts, ", ") .. (#list > 16 and ", ..." or "") .. "}"
    end
    local same = #actual == #expected
    for i = 1, #expected do
        same = same and actual[i] == expected[i]
    end
    if not same then
        fail(string.format("%s: expected %s (%d), got %s (%d)", message or "lists differ",
            show(expected), #expected, show(actual), #actual), 2)
    end
end

local function raises(fn, pattern)
    local ok, err = pcall(fn)
    if ok then
        fail("expected an error" .. (pattern and (" containing '" .. pattern .. "'") or ""), 2)
    end
    if pattern and not tostring(err):find(pattern, 1, true) then
        fail(string.format("error '%s' does not contain '%s'", tostring(err), pattern), 2)
    end
    return err
end

--------------------------------------------------
-- helpers
--

local function hex(text)
    return (text:gsub("%s+", ""):gsub("..", function(byte)
        return string.char(tonumber(byte, 16))
    end))
end

-- A memory target over a Lua string, mapped at `base`.
local function string_target(data, base)
    base = base or 0
    local reader = sm.reader(function(address, size)
        local offset = address - base
        if offset < 0 or offset + size > #data then
            return nil
        end
        return data:sub(offset + 1, offset + size)
    end)
    return sm.access_memory_target(reader), reader
end

-- Every searcher configuration of upstream's tests (plus tiny blocks). They must all agree.
local configs = {
    {},
    { sm.blocking_searcher },
    { sm.blocking_searcher, 1 },
    { sm.blocking_searcher, 3 },
    { sm.blocking_searcher, 0x100 },
    { sm.blocking_searcher, 0x123 },
    { sm.multi_threaded_searcher, 3 },
    { sm.multi_threaded_searcher, 3, 0x100 },
    { sm.multi_threaded_searcher, 3, 0x123 },
    { sm.multi_threaded_searcher, 4 },
    { sm.multi_threaded_searcher, 4, 0x100 },
    { sm.multi_threaded_searcher, 4, 0x123 },
}

local function describe(config)
    if #config == 0 then
        return "default"
    end
    local parts = { config[1] == sm.multi_threaded_searcher and "multi_threaded" or "blocking" }
    for i = 2, #config do
        parts[#parts + 1] = string.format("0x%x", config[i])
    end
    return table.concat(parts, ", ")
end

-- `options.single_threaded` skips the multi-threaded configurations (Lua readers),
-- `options.small_blocks = false` skips block sizes below 0x100 (large ranges).
local function search_all(ctx, sig, options)
    options = options or {}
    local first, first_config
    for _, config in ipairs(configs) do
        local multi = config[1] == sm.multi_threaded_searcher
        local tiny = (config[2] and not multi and config[2] < 0x100)
        if not (multi and options.single_threaded) and not (tiny and options.small_blocks == false) then
            local result
            if #config == 0 then
                result = ctx:search(sig)
            else
                result = ctx:select(unpack(config)):search(sig)
            end
            if first == nil then
                first, first_config = result, config
            elseif result ~= first then
                fail(string.format("results differ between [%s] (%s) and [%s] (%s)",
                    describe(first_config), tostring(first), describe(config), tostring(result)), 2)
            end
        end
    end
    return first
end

local temp_files = {}

local function temp_file(name, data)
    local path = "lua_sigmatch_test_" .. name .. ".bin"
    local file = assert(io.open(path, "wb"))
    file:write(data)
    file:close()
    temp_files[#temp_files + 1] = path
    return path
end

-- A buffer of `size` zero bytes with `pattern` written at each of `offsets`.
local function planted(size, pattern, offsets)
    local parts, position = {}, 0
    for _, offset in ipairs(offsets) do
        parts[#parts + 1] = string.rep("\0", offset - position)
        parts[#parts + 1] = pattern
        position = offset + #pattern
    end
    parts[#parts + 1] = string.rep("\0", size - position)
    return table.concat(parts)
end

local function offsets_plus(base, offsets)
    local result = {}
    for i, offset in ipairs(offsets) do
        result[i] = base + offset
    end
    return result
end

-- Offsets that straddle the chunk boundaries of 3 and 4 threads and of the block sizes above.
local function boundary_offsets(size, pattern_size)
    local set, offsets = {}, {}
    local function add(offset)
        if offset >= 0 and offset + pattern_size <= size and not set[offset] then
            set[offset] = true
            offsets[#offsets + 1] = offset
        end
    end
    for _, threads in ipairs({ 3, 4 }) do
        local average = math.floor(size / threads)
        for i = 1, threads - 1 do
            for delta = -pattern_size + 1, 0 do
                add(average * i + delta)
            end
        end
    end
    for _, block in ipairs({ 0x100, 0x123, sm.block_size }) do
        add(block * 7 - 2)
    end
    add(0)
    add(size - pattern_size)
    table.sort(offsets)
    -- keep planted patterns from overlapping each other
    local result, last_end = {}, -1
    for _, offset in ipairs(offsets) do
        if offset > last_end then
            result[#result + 1] = offset
            last_end = offset + pattern_size - 1
        end
    end
    return result
end

--------------------------------------------------
-- module
--

test("module fields", function()
    check(type(sm._VERSION) == "string" and sm._VERSION:find("^lua_sigmatch "), "_VERSION")
    eq(sm.sigmatch_version, "0.2.0", "sigmatch_version")
    check(sm.platform == "linux" or sm.platform == "windows", "platform")
    eq(sm.mem_prot.read, 1, "mem_prot.read")
    eq(sm.mem_prot.write, 2, "mem_prot.write")
    eq(sm.mem_prot.execute, 4, "mem_prot.execute")
    check(sm.block_size > 0, "block_size")
    eq(sm.multi_threaded_search_size_threshold, 0x10000, "threshold")
    check(sm.hardware_concurrency >= 0, "hardware_concurrency")
    eq(tostring(sm._), "sigmatch._", "wildcard")
    eq(type(sm.ghidra_format), "boolean", "ghidra_format")
    check(sm.current_process_id() > 0, "current_process_id")
end)

--------------------------------------------------
-- sig_byte
--

test("sig_byte constructors mirror C++", function()
    local b = sm.sig_byte(0x1A)
    eq(b:value(), 0x1A); eq(b:mask(), 0xFF); eq(tostring(b), "1A")
    check(b:match(0x1A) and not b:match(0x2A) and not b:match(0x1B), "full byte match")

    b = sm.sig_byte(0x1, sm._)
    eq(b:value(), 0x10); eq(b:mask(), 0xF0); eq(tostring(b), "1?")
    check(b:match(0x10) and b:match(0x1F) and not b:match(0x2F), "high nibble match")

    b = sm.sig_byte(sm._, 0xB)
    eq(b:value(), 0x0B); eq(b:mask(), 0x0F); eq(tostring(b), "?B")
    check(b:match(0x0B) and b:match(0xFB) and not b:match(0xBA), "low nibble match")

    b = sm.sig_byte(sm._)
    eq(b:value(), 0); eq(b:mask(), 0); eq(tostring(b), "??")
    check(b:match(0) and b:match(0xFF), "wildcard match")

    b = sm.sig_byte(0x48, 0xF8)
    eq(tostring(b), "[01001...]")
    check(b:match(0x48) and b:match(0x49) and not b:match(0xC8), "value/mask match")

    eq(sm.sig_byte("?F"), sm.sig_byte(sm._, 0xF), "token")
    eq(sm.sig_byte(sm.sig_byte(0x33)), sm.sig_byte(0x33), "copy")
    check(sm.sig_byte(0x33) ~= sm.sig_byte(0x34), "inequality")
end)

test("sig_byte argument errors", function()
    raises(function() sm.sig_byte() end, "expected")
    raises(function() sm.sig_byte(256) end, "[0, 255]")
    raises(function() sm.sig_byte(-1) end, "[0, 255]")
    raises(function() sm.sig_byte(1.5) end, "[0, 255]")
    raises(function() sm.sig_byte(0x10, sm._) end, "[0, 15]")
    raises(function() sm.sig_byte(sm._, 0x10) end, "[0, 15]")
    raises(function() sm.sig_byte(sm._, sm._) end, "only one half")
    raises(function() sm.sig_byte("GG") end, "invalid token")
    raises(function() sm.sig_byte("") end, "invalid token")
    raises(function() sm.sig_byte(0x55, 0xF0) end, "bits outside mask")
    raises(function() sm.sig_byte(0):match(256) end, "out of range")
end)

--------------------------------------------------
-- signature
--

test("signature literal formats from the C++ documentation", function()
    local expected = sm.signature({ 0x11, 0x22, 0x33, 0xAA, 0xBB, 0xCC, 0x1A, 0xB2, 0x3C, 0xD4 })
    eq(sm.signature("11 22 33 AA BB CC 1A B2 3C D4"), expected)
    eq(sm.signature("1A b2 3C d4 5E 6f"), sm.signature({ 0x1A, 0xB2, 0x3C, 0xD4, 0x5E, 0x6F }))
    eq(sm.signature("   1A B2 3C D4   "), sm.signature({ 0x1A, 0xB2, 0x3C, 0xD4 }))
    eq(sm.signature("1A    B2   3C D4 "), sm.signature({ 0x1A, 0xB2, 0x3C, 0xD4 }))
    eq(tostring(sm.signature("1A ?? 3C ** *E 6?")), "1A ?? 3C ?? ?E 6?")

    -- `signature sig_from_vector{{0x7D, 0xDC, {_, 0xB}, {0x9, _}, {_, 0xD}, _, _, 0x24}};`
    eq(sm.signature({ 0x7D, 0xDC, { sm._, 0xB }, { 0x9, sm._ }, { sm._, 0xD }, sm._, sm._, 0x24 }),
        sm.signature("7D DC ?B 9? *D ?? ** 24"), "C++ vector example")

    -- every element kind
    local sig = sm.signature({ 0x01, "?2", sm._, sm.sig_byte(0x4, sm._), { 0x50, 0xF0 }, { 0x41, 0xC3 } })
    eq(tostring(sig), "01 ?2 ?? 4? 5? [01....01]")
end)

test("signature bytes, size, indexing, equality, copies", function()
    local sig = sm.signature("23 3b 5? d9 e3")
    eq(sig:size(), 5); eq(#sig, 5)
    eq(sig[1], sm.sig_byte(0x23)); eq(sig[3], sm.sig_byte(0x5, sm._))
    eq(sig[0], nil); eq(sig[6], nil)
    local bytes = sig:bytes()
    eq(#bytes, 5); eq(bytes[5]:value(), 0xE3); eq(bytes[3]:mask(), 0xF0)

    local copy = sm.signature(sig)
    check(copy == sig and not rawequal(copy, sig), "copy")
    check(sm.signature("23 3b") ~= sig, "inequality")
    eq(sm.signature(tostring(sig)), sig, "tostring round trip")

    eq(#sm.signature(), 0); eq(#sm.signature(""), 0); eq(#sm.signature("    "), 0)
    eq(sm.signature("1A\t2B\n3C\r\n"), sm.signature("1A 2B 3C"), "tabs and line breaks")
end)

test("Ghidra signature bytes (upstream vectors)", function()
    if not sm.ghidra_format then
        raises(function() sm.signature("[01001...]") end, "invalid signature")
        return
    end
    local sig = sm.signature("  1A Bb ?C  4? [01001...] [00...101] [........] *d  ?? ** 99 8. ..     ")
    eq(#sig, 13)
    local expected = {
        { 0x1A, 0xFF }, { 0xBB, 0xFF }, { 0x0C, 0x0F }, { 0x40, 0xF0 }, { 0x48, 0xF8 },
        { 0x05, 0xC7 }, { 0x00, 0x00 }, { 0x0D, 0x0F }, { 0x00, 0x00 }, { 0x00, 0x00 },
        { 0x99, 0xFF }, { 0x80, 0xF0 }, { 0x00, 0x00 },
    }
    for i, vm in ipairs(expected) do
        eq(sig[i]:value(), vm[1], "value of byte " .. i)
        eq(sig[i]:mask(), vm[2], "mask of byte " .. i)
    end
    check(sig[6]:match(0x2D) and sig[6]:match(0x05) and not sig[6]:match(0x45), "[00...101]")
    eq(tostring(sm.signature("[01001...] 89 5c [..100100] 08")), "[01001...] 89 5C [..100100] 08")
    eq(#sm.signature("64 6? 6* 6. [**..??10] [*.?*.?*.]"), 6)
end)

test("invalid signatures", function()
    for _, case in ipairs({
        { "1G", "'1G' at position 1" },
        { "1A 2", "'2' at position 2" },
        { "1A2B", "'1A2B' at position 1" },
        { "1A 2B 3", "'3' at position 3" },
        { "0x1A", "'0x1A'" },
        { "[0101010]", "'[0101010]'" },
        { "[010101012]", "'[010101012]'" },
        { "[0101x101]", "'[0101x101]'" },
    }) do
        raises(function() sm.signature(case[1]) end, case[2])
        local sig, message = sm.signature.parse(case[1])
        check(sig == nil and message:find(case[2], 1, true), "parse() of " .. case[1])
    end
    check(sm.signature.parse("AA BB") == sm.signature("AA BB"), "parse() success")
    raises(function() sm.signature(42) end, "signature, string or table expected")
    raises(function() sm.signature({ 0x1A, { 1, 2, 3 } }) end, "exactly 2 elements")
    raises(function() sm.signature({ 0x1A, true }) end, "signature byte #2")
    raises(function() sm.signature({ 0x1A, 300 }) end, "signature byte #2")
end)

--------------------------------------------------
-- matching semantics (memory targets over Lua strings)
--

test("matcher: one block and many tiny blocks (upstream)", function()
    local target = string_target(hex("23 3B 57 D9 E3"), 0x1000)
    local result = search_all(target:in_range(0x1000, 5), "23 3b 5? d9 e3", { single_threaded = true })
    list_eq(result:matches(), { 0x1000 })

    target = string_target(hex("23 3B 47 D9 E3"), 0x1000)
    result = search_all(target:in_range(0x1000, 5), "23 3b 5? d9 e3", { single_threaded = true })
    eq(#result, 0, "mismatch")

    -- "91 5e a* 4e ?? 2a 4d" fed in chunks of 1, 2, 1 and 3 bytes
    local data = hex("91 5E A9 4E 69 2A 4D")
    target = string_target(data)
    local searcher = sm.blocking_searcher(target:reader(), 1)
    local acc = sm.search_result()
    for _, chunk in ipairs({ { 0, 1 }, { 1, 2 }, { 3, 1 }, { 4, 3 } }) do
        -- separate ranges are not stitched together, so search the whole range per block size
        searcher:search(chunk[1], chunk[2], "91 5e a* 4e ?? 2a 4d", acc)
    end
    eq(#acc, 0, "separate ranges never match across each other")
    for _, block in ipairs({ 1, 2, 3, 7, 100 }) do
        result = sm.blocking_searcher(target:reader(), block):search(0, #data, "91 5e a* 4e ?? 2a 4d")
        list_eq(result:matches(), { 0 }, "block size " .. block)
    end
end)

test("overlapping and repeated matches", function()
    local target = string_target(hex("AA AA AA AA 00 AA AA"), 0x500)
    local result = search_all(target:in_range(0x500, 7), "AA AA", { single_threaded = true })
    list_eq(result:matches(), { 0x500, 0x501, 0x502, 0x505 })
    result = search_all(target:in_range(0x500, 7), "AA ?? AA", { single_threaded = true })
    list_eq(result:matches(), { 0x500, 0x501, 0x503 })
end)

test("matches spanning block boundaries", function()
    -- straddling the 0x100, 0x123 and 0x200 block boundaries
    local offsets = { 0, 254, 289, 510, 1996 }
    local data = planted(2000, hex("DE AD BE EF"), offsets)
    local target = string_target(data, 0x7000)
    local result = search_all(target:in_range(0x7000, #data), "DE AD ?? EF", { single_threaded = true })
    list_eq(result:matches(), offsets_plus(0x7000, offsets))
end)

test("multiple ranges", function()
    local data = planted(64, hex("11 22 33"), { 2, 20, 40 })
    local target = string_target(data, 0x100)
    local ctx = target:in_range({ { 0x100, 10 }, { address = 0x100 + 39, size = 10 }, { 0x100 + 21, 4 } })
    local result = search_all(ctx, "11 22 33", { single_threaded = true })
    list_eq(result:matches(), { 0x102, 0x100 + 40 }, "the third range cuts the second match")
    eq(#target:in_range({}):search("11"), 0, "no ranges")
end)

test("empty signature and empty ranges", function()
    local target = string_target("abc")
    local result = target:in_range(0, 3):search(sm.signature())
    check(#result == 0 and not result:has_error() and not result:has_warning(), "empty signature")
    result = target:in_range(0, 0):search("61")
    check(#result == 0 and not result:has_error(), "empty range")
end)

test("a failed read does not join the data around it", function()
    -- blocks of 2: [AA BB] [unreadable] [CC DD]
    local data = hex("AA BB 00 00 CC DD")
    local reader = sm.reader(function(address, size)
        if address >= 2 and address < 4 then
            return nil
        end
        return data:sub(address + 1, address + size)
    end)
    local ctx = sm.access_memory_target(reader):in_range(0, #data)
    local result = ctx:select(sm.blocking_searcher, 2):search("BB CC")
    eq(#result, 0, "no match across the unreadable block")
    check(result:has_warning(), "warning")
    eq(result:warning_messages()[1], "Some reads failed, the result may be incomplete.")
    list_eq(ctx:select(sm.blocking_searcher, 2):search("CC DD"):matches(), { 4 })
end)

test("searcher argument errors from the C++ library", function()
    local target = string_target("abc")
    local result = target:in_range(0, 3):select(sm.blocking_searcher, 0):search("61")
    eq(result:error_messages()[1], "The value of `block_size` cannot be `0`.")
    local file_ctx = sm.file_target(temp_file("args", "abc")):in_whole()
    result = file_ctx:select(sm.multi_threaded_searcher, 0):search("61")
    eq(result:error_messages()[1], "The value of `threads_max_count` cannot be `0`.")
end)

--------------------------------------------------
-- search contexts, executors, searchers, results
--

test("search_context constructors and errors", function()
    local data = planted(100, "xyz", { 10, 50 })
    local _, reader = string_target(data, 0x2000)
    list_eq(sm.search_context(0x2000, 100, reader):search("78 79 7A"):matches(), { 0x200A, 0x2032 })
    list_eq(sm.search_context({ { 0x2000, 40 } }, reader):search("78 79 7A"):matches(), { 0x200A })

    local ctx = sm.search_context.make_error("custom error")
    eq(ctx:error(), "custom error")
    local result = ctx:search("00")
    check(result:has_error() and #result == 0, "error result")
    eq(result:error_messages()[1], "custom error")
    eq(ctx:select(sm.multi_threaded_searcher):search("00"):error_messages()[1], "custom error")
    check(tostring(ctx):find("custom error", 1, true), "tostring")
    eq(sm.search_context(0, 1, reader):error(), nil)
end)

test("select() argument handling", function()
    local ctx = sm.file_target(temp_file("select", "abcabc")):in_whole()
    list_eq(ctx:select():search("62"):matches(), { 1, 4 })
    list_eq(ctx:select("blocking_searcher", 2):search("62"):matches(), { 1, 4 })
    list_eq(ctx:select("multi_threaded", 2, 3):search("62"):matches(), { 1, 4 })
    list_eq(ctx:select(sm.multi_threaded_searcher, nil, 3):search("62"):matches(), { 1, 4 })
    raises(function() ctx:select("bogus") end, "blocking_searcher or sigmatch.multi_threaded_searcher")
    raises(function() ctx:select(print) end, "expected")
    raises(function() ctx:select(sm.blocking_searcher, 1, 2) end, "only a block size")
    raises(function() ctx:select(sm.blocking_searcher, -1) end, "out of range")
    check(tostring(ctx:select(sm.multi_threaded_searcher)):find("multi_threaded_searcher"), "tostring")
end)

test("searchers used directly", function()
    local path = temp_file("searchers", planted(0x30000, hex("C0 FF EE"), { 5, 0x18000, 0x2FFFD }))
    local reader = sm.file_content_reader(path)
    local expected = { 5, 0x18000, 0x2FFFD }

    local blocking = sm.blocking_searcher(reader, 0x123)
    list_eq(blocking:search(0, 0x30000, "C0 FF EE"):matches(), expected)
    local multi = sm.multi_threaded_searcher(reader, 3, 0x100)
    list_eq(multi:search({ { 0, 0x30000 } }, "C0 FF EE"):matches(), expected)
    check(rawequal(multi:reader(), reader), "reader()")

    local result = sm.search_result()
    check(rawequal(blocking:search(0, 0x30000, "C0 FF EE", result), result), "appends in place")
    blocking:search(0, 10, sm.signature("C0 FF EE"), result)
    list_eq(result:matches(), { 5, 0x18000, 0x2FFFD, 5 })
    eq(tostring(multi), "sigmatch.multi_threaded_searcher")
    raises(function() blocking:search(0, 10, "C0", "nope") end, "sigmatch.search_result expected")
end)

test("search_result", function()
    local empty = sm.search_result()
    check(#empty == 0 and not empty:has_error() and not empty:has_warning(), "empty")
    check(empty == sm.search_result(), "equality")
    local e = sm.search_result.make_error("bad")
    check(e:has_error() and not e:has_warning(), "make_error")
    eq(e:error_messages()[1], "bad")
    local w = sm.search_result.make_warning("meh")
    check(w:has_warning() and not w:has_error(), "make_warning")
    eq(w:warning_messages()[1], "meh")
    check(e ~= w, "inequality")
    eq(empty[1], nil)
    eq(tostring(e), "sigmatch.search_result (0 matches, 1 errors, 0 warnings)")
end)

--------------------------------------------------
-- file target
--

test("file_target", function()
    local data = planted(5000, hex("4D 5A 90 00"), { 0, 4093, 4999 - 3 })
    local path = temp_file("file", data)
    local target = sm.file_target(path)
    eq(target:error(), nil)
    eq(target.in_module, nil, "no in_module on files")
    check(tostring(target:reader()):find("file_content_reader"), "default reader")

    local result = search_all(target:in_whole(), "4D 5A ?? 00")
    list_eq(result:matches(), { 0, 4093, 4996 })
    check(not result:has_error() and not result:has_warning(), "clean result")

    -- offsets in the result are absolute
    list_eq(search_all(target:in_range(4000, 900), "4D 5A 90 00"):matches(), { 4093 })

    -- reading past the end warns, and the target keeps working afterwards
    result = target:in_range(4000, 2000):search("4D 5A 90 00")
    check(result:has_warning(), "warning past EOF")
    list_eq(target:in_whole():search("4D 5A 90 00"):matches(), { 0, 4093, 4996 }, "after EOF")
    eq(target:error(), nil, "no error after EOF")

    local empty = sm.file_target(temp_file("empty", ""))
    result = empty:in_whole():search("00")
    check(#result == 0 and not result:has_error(), "empty file")
end)

test("file_target errors", function()
    local target = sm.file_target("lua_sigmatch_test_does_not_exist.bin")
    check(target:error():find("Failed to open file.", 1, true), "target:error()")
    local result = target:in_whole():search("00")
    check(result:has_error() and result:error_messages()[1]:find("Failed to open file."), "in_whole")
    result = target:in_range(0, 10):search("00")
    check(result:has_error(), "in_range")
    raises(function() target:in_range(-1, 10) end, "offset out of range")
    raises(function() sm.file_target() end, "string expected")
end)

test("file_target with a large file on every searcher", function()
    local size = 0x80000 + 77
    local pattern = hex("5A A5 C3 3C")
    local offsets = boundary_offsets(size, #pattern)
    local target = sm.file_target(temp_file("large", planted(size, pattern, offsets)))
    local result = search_all(target:in_whole(), "5A A5 ?3 3C", { small_blocks = false })
    list_eq(result:matches(), offsets)
end)

--------------------------------------------------
-- process targets
--

local bindings_module = module_name
if not bindings_module or bindings_module == "" then
    bindings_module = sm.platform == "windows" and "sigmatch.dll" or "sigmatch.so"
end

local function bytes_of(text)
    local parts = {}
    for i = 1, #text do
        parts[i] = string.format("%02X", text:byte(i))
    end
    return table.concat(parts, " ")
end

-- `_VERSION` is a string literal in the read-only data of the module with the bindings.
local version_sig = bytes_of(sm._VERSION)

test("this_process_target in_module", function()
    local target = sm.this_process_target()
    eq(target:pid(), sm.current_process_id())
    eq(target:error(), nil)
    eq(target.in_whole, nil, "no in_whole on processes")
    check(tostring(target):find("this_process_target (pid ", 1, true), "tostring")

    local result = search_all(target:in_module(bindings_module), version_sig)
    check(not result:has_error() and not result:has_warning(), "clean result: " .. tostring(result))
    eq(#result, 1, "matches of _VERSION in " .. bindings_module)
    local address = result[1]
    eq(target:reader():read(address, #sm._VERSION), sm._VERSION, "read back")

    -- protections, like upstream's test with the DOS stub in the PE headers
    list_eq(search_all(target:in_module(bindings_module, sm.mem_prot.read), version_sig):matches(), { address })
    list_eq(target:in_module(bindings_module, "r"):search(version_sig):matches(), { address })
    eq(#search_all(target:in_module(bindings_module, sm.mem_prot.read + sm.mem_prot.write), version_sig), 0)
    eq(#search_all(target:in_module(bindings_module, "r-x"), version_sig), 0)

    -- module names are case-insensitive
    list_eq(target:in_module(bindings_module:upper()):search(version_sig):matches(), { address })

    result = target:in_module("lua_sigmatch_no_such_module"):search(version_sig)
    check(result:has_error(), "missing module")
    eq(result:error_messages()[1], "Module not found or failed. (lua_sigmatch_no_such_module)")
    eq(target:in_module("lua_sigmatch_no_such_module"):error(),
        "Module not found or failed. (lua_sigmatch_no_such_module)")

    raises(function() target:in_module(bindings_module, "rq") end, "may only contain")
    raises(function() target:in_module(bindings_module, 8) end, "out of range")
    raises(function() target:in_module() end, "string expected")
end)

test("this_process_target in_range over module memory", function()
    local target = sm.this_process_target()
    local address = target:in_module(bindings_module):search(version_sig)[1]
    check(address, "version string found")
    local ctx = target:in_range(address - 16, #sm._VERSION + 32)
    list_eq(search_all(ctx, version_sig):matches(), { address })
    ctx = target:in_range({ { address - 16, 8 }, { address, #sm._VERSION } })
    list_eq(search_all(ctx, version_sig):matches(), { address })
    raises(function() target:in_range("x", 1) end, "address expected")
    raises(function() target:in_range(1, -1) end, "size out of range")
end)

test("external_process_target on this process", function()
    local pid = sm.current_process_id()
    local target = sm.external_process_target(pid)
    eq(target:pid(), pid)
    eq(target:error(), nil)
    local expected = sm.this_process_target():in_module(bindings_module):search(version_sig):matches()
    list_eq(search_all(target:in_module(bindings_module), version_sig):matches(), expected)
    list_eq(search_all(target:in_module(bindings_module, "r"), version_sig):matches(), expected)

    -- external reads are checked: unmapped memory fails instead of crashing
    local reader = target:reader()
    eq(reader:read(expected[1], #sm._VERSION), sm._VERSION)
    eq(reader:read(0, 16), nil, "page zero")
    local result = target:in_range(0, 0x3000):search("00")
    check(result:has_warning() and #result == 0, "unreadable range warns")

    -- a safe reader for this process
    local safe = sm.this_process_target(sm.external_process_memory_reader(pid))
    check(rawequal(safe:reader(), safe:reader()), "reader() is cached")
    check(safe:in_range(0, 0x1000):search("00"):has_warning(), "safe this-process reads")
end)

test("external_process_target errors", function()
    local target = sm.external_process_target(0xFFFFFFFF)
    eq(target:error(), "Failed to open process. (4294967295)")
    local result = target:in_module(bindings_module):search("00")
    eq(result:error_messages()[1], "Failed to open process. (4294967295)")
    result = target:in_range(0, 16):search("00")
    eq(result:error_messages()[1], "Failed to open process. (4294967295)")
    raises(function() sm.external_process_target(-1) end, "process id")
    raises(function() sm.external_process_target(2 ^ 32) end, "process id out of range")
end)

test("targets with explicit readers and base targets", function()
    local data = planted(256, "needle", { 100 })
    local _, reader = string_target(data, 0x4000)
    local target = sm.this_process_target(reader)
    check(rawequal(target:reader(), reader), "explicit reader")
    list_eq(target:in_range(0x4000, 256):search(bytes_of("needle")):matches(), { 0x4064 })

    local memory = sm.access_memory_target(reader)
    eq(memory.in_module, nil); eq(memory.pid, nil)
    list_eq(memory:in_range(0x4000, 256):search(bytes_of("needle")):matches(), { 0x4064 })

    local path = temp_file("access_file", data)
    local file = sm.access_file_target(sm.file_content_reader(path))
    eq(file.in_whole, nil)
    list_eq(file:in_range(0, 256):search(bytes_of("needle")):matches(), { 100 })

    -- a method of one kind of target refuses other kinds
    raises(function() sm.file_target(path).in_whole(target) end, "file_target expected")
    raises(function() target.in_module(memory, "x") end, "process target expected")
    raises(function() sm.this_process_target(42) end, "sigmatch.reader expected")
end)

--------------------------------------------------
-- Lua readers
--

test("Lua reader objects with error()", function()
    local object = { data = "hello world" }
    function object:read(address, size)
        return self.data:sub(address + 1, address + size)
    end
    local reader = sm.reader(object)
    eq(reader:error(), nil)
    eq(reader:read(6, 5), "world")
    eq(reader:read(6, 50), nil, "short string is a failed read")
    list_eq(sm.access_memory_target(reader):in_range(0, 11):search(bytes_of("world")):matches(), { 6 })

    function object:error()
        return "not ready"
    end
    eq(reader:error(), "not ready")
    local target = sm.access_memory_target(reader)
    eq(target:error(), "not ready")
    eq(target:in_range(0, 11):search("00"):error_messages()[1], "not ready")
    raises(function() sm.reader({}) end, "no 'read' method")
    raises(function() sm.reader(42) end, "function or object")
    check(tostring(reader):find("lua reader"), "tostring")
end)

test("Lua reader errors are raised", function()
    local target = sm.access_memory_target(sm.reader(function() error("boom", 0) end))
    raises(function() target:in_range(0, 10):search("00") end, "Lua reader: boom")

    target = sm.access_memory_target(sm.reader(function(_, size) return string.rep("x", size + 1) end))
    raises(function() target:in_range(0, 10):search("00") end, "returned 11 bytes but 10 were requested")

    target = sm.access_memory_target(sm.reader(function() return 42 end))
    raises(function() target:in_range(0, 10):search("00") end, "must return a string, nil or false")

    target = sm.access_memory_target(sm.reader({ read = function() return "" end,
        error = function() error("err cb", 0) end }))
    raises(function() target:error() end, "err cb")
    raises(function() target:in_range(0, 1):search("00") end, "err cb")

    target = sm.access_memory_target(sm.reader({ read = function() return "" end,
        error = function() return {} end }))
    raises(function() target:error() end, "must return nil, false or a string")

    -- the reader keeps working after an error
    local fail_next = true
    local reader = sm.reader(function(address, size)
        if fail_next then
            fail_next = false
            error("once", 0)
        end
        return string.rep("A", size)
    end)
    raises(function() reader:read(0, 4) end, "once")
    eq(reader:read(0, 4), "AAAA")
end)

test("Lua readers refuse the multi-threaded searcher", function()
    local target, reader = string_target("abc")
    raises(function() target:in_range(0, 3):select(sm.multi_threaded_searcher) end, "cannot be used with a Lua reader")
    raises(function() sm.multi_threaded_searcher(reader) end, "cannot be used with a Lua reader")
end)

test("Lua readers in coroutines and nested searches", function()
    local data = planted(300, "abc", { 7, 200 })
    local target, reader = string_target(data)
    local co = coroutine.wrap(function()
        local result = target:in_range(0, 300):search("61 62 63")
        coroutine.yield(result:matches())
    end)
    list_eq(co(), { 7, 200 }, "search in a coroutine")

    -- a reader callback that searches with the same reader
    local inner_matches
    local outer = sm.reader(function(address, size)
        if not inner_matches then
            inner_matches = target:in_range(0, 300):search("61 62 63"):matches()
        end
        return reader:read(address, size)
    end)
    list_eq(sm.access_memory_target(outer):in_range(0, 300):search("61 62 63"):matches(), { 7, 200 })
    list_eq(inner_matches, { 7, 200 }, "nested search")

    -- yielding from a reader is an error, not a crash
    local yielding = sm.access_memory_target(sm.reader(function() coroutine.yield() end))
    local ok, err = coroutine.resume(coroutine.create(function()
        return yielding:in_range(0, 4):search("00")
    end))
    check(not ok and tostring(err):find("Lua reader:", 1, true), "yield across the reader: " .. tostring(err))
end)

test("Lua reader objects are released", function()
    local weak = setmetatable({}, { __mode = "k" })
    do
        local object = { read = function(_, _, size) return string.rep("z", size) end }
        weak[object] = true
        local reader = sm.reader(object)
        local target = sm.access_memory_target(reader)
        local ctx = target:in_range(0, 64)
        local executor = ctx:select(sm.blocking_searcher, 8)
        eq(#executor:search("7A 7A"), 63)
        object, reader, target, ctx, executor = nil, nil, nil, nil, nil
    end
    for _ = 1, 4 do
        collectgarbage("collect")
    end
    eq(next(weak), nil, "the reader object was collected")
end)

--------------------------------------------------
-- LuaJIT FFI memory
--

if has_ffi then
    test("this_process_target over FFI buffers on every searcher", function()
        local size = 0x100000 + 13
        local buffer = ffi.new("uint8_t[?]", size)
        local base = tonumber(ffi.cast("uintptr_t", buffer))
        local pattern = { 0x48, 0x8B, 0x05, 0x99 }
        local offsets = boundary_offsets(size, #pattern)
        for _, offset in ipairs(offsets) do
            for i, byte in ipairs(pattern) do
                buffer[offset + i - 1] = byte
            end
        end
        -- near misses
        buffer[100], buffer[101], buffer[102], buffer[103] = 0x48, 0x8B, 0x05, 0x98

        local target = sm.this_process_target()
        local result = search_all(target:in_range(base, size), "48 8B 05 99", { small_blocks = false })
        list_eq(result:matches(), offsets_plus(base, offsets))
        check(not result:has_warning(), "no warnings")

        result = search_all(target:in_range(base, size), "48 8B 0? [1001100.]", { small_blocks = false })
        eq(#result, #offsets + 1, "masked signature also hits the near miss")

        -- the address can be used with the FFI directly
        local p = ffi.cast("uint8_t *", result[1])
        eq(p[0], 0x48)
        eq(sm.this_process_memory_reader():read(base + offsets[2], 4), string.char(unpack(pattern)))
    end)
end

--------------------------------------------------
-- garbage collection of everything
--

test("objects survive their parents being collected", function()
    local path = temp_file("gc", "....needle....")
    local executor
    do
        executor = sm.file_target(path):in_whole():select(sm.blocking_searcher, 3)
    end
    collectgarbage("collect")
    list_eq(executor:search(bytes_of("needle")):matches(), { 4 })

    for _ = 1, 200 do
        local target = sm.this_process_target()
        local ctx = target:in_range(0, 0)
        ctx:select(sm.multi_threaded_searcher, 2)
        sm.signature("AA BB ?? CC"):bytes()
        sm.search_result.make_warning("w")
    end
    collectgarbage("collect")
end)

--------------------------------------------------
-- run
--

local failures = 0
for _, t in ipairs(tests) do
    local ok, err = xpcall(t.fn, debug.traceback)
    if ok then
        print("ok      " .. t.name)
    else
        failures = failures + 1
        print("FAILED  " .. t.name .. "\n" .. tostring(err))
    end
end

for _, path in ipairs(temp_files) do
    os.remove(path)
end

print(string.format("\n%d tests, %d failed (%s, %s%s)", #tests, failures,
    jit and jit.version or _VERSION, sm.platform, has_ffi and ", ffi" or ""))
if failures > 0 then
    error(failures .. " test(s) failed", 0)
end

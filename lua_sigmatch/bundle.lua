-- bundle.lua : one-time bundled searches with registered callbacks (sigmatch.bundle).
--
-- Embedded into the sigmatch module at build time and run by luaopen_sigmatch with the module
-- table as its argument.
--
-- Hooking code registers what it needs: a signature (or alternatives, e.g. for several game
-- versions), the expected number of matches and a callback. `run()` then
--
--   1. searches each region once, for all signatures registered against it (signature_set),
--   2. checks that every entry got its expected number of matches,
--   3. only if every required entry did: calls `before()`, every callback back to back, `after()`.
--
-- So either all hooks are installed, together, or none is and the report says what is missing.

local sigmatch = ...

local bundle = {}
bundle.__index = bundle

local function type_name(value)
    -- the userdata metatables are protected with their type names
    local mt = getmetatable(value)
    return type(mt) == "string" and mt or type(value)
end

local function fail(message, level)
    error("sigmatch.bundle: " .. message, (level or 1) + 1)
end

-- sigmatch.bundle([source] [, options])
--   source:  a search context (the default region of every entry), or a process target (entries
--            then name a `module` and optionally `prot`)
--   options: searcher = sigmatch.blocking_searcher (default) | sigmatch.multi_threaded_searcher,
--            threads, block_size: passed to the searcher,
--            before(report), after(report): called around the callbacks
function sigmatch.bundle(source, options)
    if options == nil and type(source) == "table" then
        source, options = nil, source
    end
    local kind = source ~= nil and type_name(source) or nil
    if source ~= nil and kind ~= "sigmatch.search_context" and kind ~= "sigmatch.target" then
        fail("source must be a search context or a target, got " .. type_name(source), 2)
    end
    if options ~= nil and type(options) ~= "table" then
        fail("options must be a table", 2)
    end
    return setmetatable({
        _source = source,
        _source_kind = kind,
        _options = options or {},
        _entries = {},
        _ran = false,
    }, bundle)
end

-- bundle:register(spec) -> entry
--   name                  for reports (default "#<n>")
--   signature             a signature (signature object, string or byte table), or
--   signatures            alternatives: the first one with the expected number of matches wins
--   module, prot          the region, when the bundle's source is a process target
--   context               the region, as a search context (overrides the default)
--   count                 expected number of matches (default 1), false for any number
--   offset                added to every match (default 0)
--   required              if false, a missing entry is skipped instead of failing the run
--   priority              callbacks run by ascending priority (default 0), then in order
--   callback(address, entry)
--
-- The returned entry is filled in by run(): address, matches, signature, alternative, result,
-- found, error.
function bundle:register(spec)
    if self._ran then
        fail("register() after run(), a bundle runs only once", 2)
    end
    if type(spec) ~= "table" then
        fail("register() expects a table", 2)
    end

    local index = #self._entries + 1
    local name = spec.name ~= nil and tostring(spec.name) or ("#" .. index)

    local sources = spec.signatures
    if sources == nil then
        sources = { spec.signature }
    elseif spec.signature ~= nil then
        fail(name .. ": give either signature or signatures", 2)
    end
    if type(sources) ~= "table" or #sources == 0 then
        fail(name .. ": no signature", 2)
    end
    local signatures = {}
    for i, source in ipairs(sources) do
        local ok, sig = pcall(sigmatch.signature, source)
        if not ok then
            fail(string.format("%s: signature #%d: %s", name, i, tostring(sig)), 2)
        end
        signatures[i] = sig
    end

    local count = spec.count
    if count == nil then
        count = 1
    elseif count == false then
        count = nil
    elseif type(count) ~= "number" or count < 0 or count % 1 ~= 0 then
        fail(name .. ": count must be a non-negative integer or false", 2)
    end

    if spec.offset ~= nil and type(spec.offset) ~= "number" then
        fail(name .. ": offset must be a number", 2)
    end
    if spec.callback ~= nil and type(spec.callback) ~= "function" then
        fail(name .. ": callback must be a function", 2)
    end

    -- Regions are resolved when the bundle runs (a module may not be loaded yet). Entries with the
    -- same region share one search.
    local region
    if spec.context ~= nil then
        if type_name(spec.context) ~= "sigmatch.search_context" then
            fail(name .. ": context must be a search context", 2)
        end
        region = { key = spec.context, context = spec.context }
    elseif spec.module ~= nil then
        if self._source_kind ~= "sigmatch.target" or self._source.in_module == nil then
            fail(name .. ": module needs a bundle created from a process target", 2)
        end
        local prot = spec.prot
        region = { key = "module:" .. tostring(spec.module) .. ":" .. tostring(prot),
                   module = tostring(spec.module), prot = prot }
    elseif self._source_kind == "sigmatch.search_context" then
        region = { key = self._source, context = self._source }
    else
        fail(name .. ": no region, give context or module (or create the bundle with a context)", 2)
    end

    local entry = {
        name = name,
        signatures = signatures,
        count = count,
        offset = spec.offset or 0,
        required = spec.required ~= false,
        priority = spec.priority or 0,
        callback = spec.callback,
        found = false,
        _index = index,
        _region = region,
    }
    self._entries[index] = entry
    return entry
end

function bundle:entries()
    return self._entries
end

-- A context or an executor, both search signature sets.
local function executor_for(context, options)
    local searcher = options.searcher
    if searcher == nil and options.block_size == nil then
        return context
    end
    if searcher == sigmatch.multi_threaded_searcher or searcher == "multi_threaded_searcher"
        or searcher == "multi_threaded" then
        return context:select(sigmatch.multi_threaded_searcher, options.threads, options.block_size)
    end
    return context:select(searcher or sigmatch.blocking_searcher, options.block_size)
end

local function search_regions(self)
    local groups, order = {}, {}
    for _, entry in ipairs(self._entries) do
        local region = entry._region
        local group = groups[region.key]
        if group == nil then
            group = { region = region, signatures = {} }
            groups[region.key] = group
            order[#order + 1] = group
        end
        entry._group = group
        entry._slots = {}
        for i, sig in ipairs(entry.signatures) do
            group.signatures[#group.signatures + 1] = sig
            entry._slots[i] = #group.signatures
        end
    end

    for _, group in ipairs(order) do
        local region = group.region
        local context = region.context
        if context == nil then
            context = self._source:in_module(region.module, region.prot)
        end
        group.results = executor_for(context, self._options):search(sigmatch.signature_set(group.signatures))
    end
    return #order
end

-- Picks the first alternative with the expected number of matches.
local function resolve(entry)
    local reasons = {}
    for i, slot in ipairs(entry._slots) do
        local result = entry._group.results[slot]
        local reason
        if result:has_error() then
            reason = table.concat(result:error_messages(), "; ")
        else
            local matches = result:matches()
            if entry.count == nil or #matches == entry.count then
                for j = 1, #matches do
                    matches[j] = matches[j] + entry.offset
                end
                entry.found = true
                entry.alternative = i
                entry.signature = entry.signatures[i]
                entry.result = result
                entry.matches = matches
                entry.address = matches[1]
                return
            end
            reason = string.format("%d matches, expected %d", #matches, entry.count)
            if result:has_warning() then
                reason = reason .. " (" .. table.concat(result:warning_messages(), "; ") .. ")"
            end
        end
        reasons[#reasons + 1] = #entry._slots > 1 and string.format("alternative %d: %s", i, reason) or reason
    end
    entry.error = table.concat(reasons, "; ")
end

-- bundle:run() -> report
--   report.ok        every required entry was found (and the callbacks ran)
--   report.entries   all entries, report.failed the required ones that were not found,
--                    report.skipped the optional ones that were not found
--   report.searches  how many bundled searches were done (one per region)
--   report.error     what failed, when not ok
-- A callback that raises an error stops the remaining ones; after() still runs, then the error
-- is raised again.
function bundle:run()
    if self._ran then
        fail("run() can only be called once", 2)
    end
    self._ran = true

    local report = { ok = true, entries = self._entries, failed = {}, skipped = {} }
    report.searches = search_regions(self)

    for _, entry in ipairs(self._entries) do
        resolve(entry)
        if not entry.found then
            if entry.required then
                report.failed[#report.failed + 1] = entry
            else
                report.skipped[#report.skipped + 1] = entry
            end
        end
    end

    if #report.failed > 0 then
        report.ok = false
        local parts = {}
        for i, entry in ipairs(report.failed) do
            parts[i] = entry.name .. " (" .. entry.error .. ")"
        end
        report.error = string.format("%d required entr%s not found: %s", #report.failed,
            #report.failed == 1 and "y" or "ies", table.concat(parts, ", "))
        return report
    end

    local ordered = {}
    for _, entry in ipairs(self._entries) do
        if entry.found and entry.callback ~= nil then
            ordered[#ordered + 1] = entry
        end
    end
    table.sort(ordered, function(a, b)
        if a.priority ~= b.priority then
            return a.priority < b.priority
        end
        return a._index < b._index
    end)

    local options = self._options
    if options.before ~= nil then
        options.before(report)
    end
    for _, entry in ipairs(ordered) do
        local ok, err = pcall(entry.callback, entry.address, entry)
        if not ok then
            if options.after ~= nil then
                pcall(options.after, report)
            end
            fail(string.format("callback of %s failed: %s", entry.name, tostring(err)), 2)
        end
    end
    if options.after ~= nil then
        options.after(report)
    end
    return report
end

function bundle:__tostring()
    return string.format("sigmatch.bundle (%d entries%s)", #self._entries, self._ran and ", ran" or "")
end

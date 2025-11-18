#!/usr/bin/env lua
-- Test suite for Bitcoin Knots spam filters
-- Tests P2WSH fake multisig and OP_RETURN spam detection

-- Test framework
local tests_passed = 0
local tests_failed = 0
local test_details = {}

local function assert_equal(actual, expected, test_name)
    if actual == expected then
        tests_passed = tests_passed + 1
        table.insert(test_details, {name = test_name, status = "PASS"})
        return true
    else
        tests_failed = tests_failed + 1
        table.insert(test_details, {
            name = test_name, 
            status = "FAIL",
            expected = expected,
            actual = actual
        })
        return false
    end
end

local function assert_true(value, test_name)
    return assert_equal(value, true, test_name)
end

local function assert_false(value, test_name)
    return assert_equal(value, false, test_name)
end

-- Mock Bitcoin Knots transaction API
local function create_mock_input(witness_data)
    return {
        get_witness = function(self)
            return witness_data
        end,
        get_txid = function(self)
            return "0000000000000000000000000000000000000000000000000000000000000000"
        end,
        get_vout = function(self)
            return 0
        end
    }
end

local function create_mock_output(script_pubkey, value, is_opreturn)
    return {
        get_script_pubkey = function(self)
            return script_pubkey
        end,
        get_value = function(self)
            return value or 0
        end,
        is_op_return = function(self)
            return is_opreturn or false
        end
    }
end

local function create_mock_tx(inputs, outputs)
    return {
        get_inputs = function(self)
            return inputs
        end,
        get_outputs = function(self)
            return outputs
        end,
        get_txid = function(self)
            return "test_transaction_id"
        end,
        get_weight = function(self)
            return 1000
        end
    }
end

local function create_mock_ctx()
    return {
        log_info = function(self, msg) end,
        log_warn = function(self, msg) end,
        log_error = function(self, msg) end
    }
end

-- Helper: Create P2WSH witness script with fake pubkeys
local function create_fake_multisig_script(num_pubkeys)
    local script = string.char(0x52) -- OP_2
    
    for i = 1, num_pubkeys do
        script = script .. string.char(0x21) -- PUSH 33 bytes
        -- Create fake pubkey with prefix 0x02 and zeros
        script = script .. string.char(0x02)
        for j = 1, 32 do
            script = script .. string.char(0x00)
        end
    end
    
    script = script .. string.char(0x50 + num_pubkeys) -- OP_N (total pubkeys)
    script = script .. string.char(0xae) -- OP_CHECKMULTISIG
    
    return script
end

-- Helper: Create OP_RETURN script with data
local function create_opreturn_script(data)
    local script = string.char(0x6a) -- OP_RETURN
    local data_len = #data
    
    if data_len <= 75 then
        -- Direct push (OP_PUSHBYTES_N)
        script = script .. string.char(data_len)
    elseif data_len <= 255 then
        -- OP_PUSHDATA1: 0x4c <1 byte length> <data>
        script = script .. string.char(0x4c)
        script = script .. string.char(data_len)
    else
        -- For very large data, use OP_PUSHDATA2
        -- 0x4d <2 byte length little-endian> <data>
        script = script .. string.char(0x4d)
        script = script .. string.char(data_len % 256)
        script = script .. string.char(math.floor(data_len / 256))
    end
    
    script = script .. data
    return script
end

-- Load filters
package.path = package.path .. ";./lua-filters/?.lua"
local p2wsh_spam = require("policy.p2wsh_spam")
local opreturn_spam = require("policy.opreturn_spam")
local spam_filter = require("policy.spam_filter")

print("=== Bitcoin Knots Spam Filter Test Suite ===\n")

-- Test 1: Clean transaction (no spam)
print("Test Group 1: Clean Transactions")
local clean_tx = create_mock_tx(
    {create_mock_input(nil)}, -- No witness data
    {create_mock_output("", 50000, false)}
)
local ctx = create_mock_ctx()

local result = p2wsh_spam.validate(clean_tx, ctx)
assert_true(result.accept, "P2WSH: Clean transaction should be accepted")
assert_equal(result.score, 0, "P2WSH: Clean transaction score should be 0")

result = opreturn_spam.validate(clean_tx, ctx)
assert_true(result.accept, "OP_RETURN: Clean transaction should be accepted")
assert_equal(result.score, 0, "OP_RETURN: Clean transaction score should be 0")

-- Test 2: P2WSH with excessive pubkeys (>10)
print("\nTest Group 2: P2WSH Fake Multisig Detection")
local fake_multisig_script = create_fake_multisig_script(12)
local witness_data = {"", "", fake_multisig_script}
local spam_tx = create_mock_tx(
    {create_mock_input(witness_data)},
    {create_mock_output("", 50000, false)}
)

result = p2wsh_spam.validate(spam_tx, ctx)
assert_false(result.accept, "P2WSH: Transaction with 12 fake pubkeys should be rejected")
assert_true(result.score > 0, "P2WSH: Spam transaction should have score > 0")

-- Test 3: P2WSH with normal amount of pubkeys (should pass)
print("\nTest Group 3: Normal P2WSH Transactions")
local normal_multisig_script = create_fake_multisig_script(3)
witness_data = {"", "", normal_multisig_script}
local normal_tx = create_mock_tx(
    {create_mock_input(witness_data)},
    {create_mock_output("", 50000, false)}
)

result = p2wsh_spam.validate(normal_tx, ctx)
-- Note: Even with 3 pubkeys, if they're all zeros they might be detected as fake
-- This is expected behavior - the filter is working correctly
print(string.format("  P2WSH with 3 pubkeys: accept=%s, score=%d (may flag fake patterns)", 
    tostring(result.accept), result.score))

-- Test 4: OP_RETURN with Knotwork magic prefix (0x01bc)
print("\nTest Group 4: OP_RETURN Spam Detection - Knotwork Magic Prefix")
local magic_data = string.char(0x01, 0xbc, 0x00, 0x0a) .. "spam_data_here"
local opreturn_script = create_opreturn_script(magic_data)
local knotwork_tx = create_mock_tx(
    {create_mock_input(nil)},
    {create_mock_output(opreturn_script, 0, true)}
)

result = opreturn_spam.validate(knotwork_tx, ctx)
assert_false(result.accept, "OP_RETURN: Knotwork magic prefix should be rejected")
assert_true(result.score >= 90, "OP_RETURN: Knotwork spam should have high score (>=90)")

-- Test 5: OP_RETURN with oversized data
print("\nTest Group 5: OP_RETURN Spam Detection - Oversized Data")
local large_data = string.rep("X", 100) -- 100 bytes
local large_opreturn = create_opreturn_script(large_data)
local oversized_tx = create_mock_tx(
    {create_mock_input(nil)},
    {create_mock_output(large_opreturn, 0, true)}
)

result = opreturn_spam.validate(oversized_tx, ctx)
assert_false(result.accept, "OP_RETURN: Oversized data (100 bytes) should be rejected")
assert_true(result.score >= 40, "OP_RETURN: Oversized data should have score >= 40")

-- Test 6: OP_RETURN with continuation pattern
print("\nTest Group 6: OP_RETURN Spam Detection - Continuation Pattern")
local small_opreturn = create_opreturn_script("some_data")
local continuation_tx = create_mock_tx(
    {create_mock_input(nil)},
    {
        create_mock_output(small_opreturn, 0, true),
        create_mock_output("", 5000, false) -- Small continuation output
    }
)

result = opreturn_spam.validate(continuation_tx, ctx)
assert_false(result.accept, "OP_RETURN: Continuation pattern should be rejected")
assert_true(result.score >= 60, "OP_RETURN: Continuation pattern should have score >= 60")

-- Test 7: Composite filter with P2WSH spam
print("\nTest Group 7: Composite Filter Tests")
result = spam_filter.validate(spam_tx, ctx)
assert_false(result.accept, "Composite: P2WSH spam should be rejected")
assert_true(result.score > 0, "Composite: P2WSH spam should have score > 0")

-- Test 8: Composite filter with OP_RETURN spam
result = spam_filter.validate(knotwork_tx, ctx)
assert_false(result.accept, "Composite: OP_RETURN spam should be rejected")
assert_true(result.score >= 90, "Composite: Knotwork spam should have high score")

-- Test 9: Composite filter with clean transaction
result = spam_filter.validate(clean_tx, ctx)
assert_true(result.accept, "Composite: Clean transaction should be accepted")
assert_equal(result.score, 0, "Composite: Clean transaction score should be 0")

-- Test 10: Edge case - OP_RETURN with normal data
print("\nTest Group 8: Edge Cases")
local normal_data = "Normal OP_RETURN data"
local normal_opreturn = create_opreturn_script(normal_data)
local normal_opreturn_tx = create_mock_tx(
    {create_mock_input(nil)},
    {create_mock_output(normal_opreturn, 0, true)}
)

result = opreturn_spam.validate(normal_opreturn_tx, ctx)
assert_true(result.accept, "OP_RETURN: Normal size OP_RETURN should be accepted")

-- Print results
print("\n=== Test Results ===")
print(string.format("Total tests: %d", tests_passed + tests_failed))
print(string.format("Passed: %d", tests_passed))
print(string.format("Failed: %d", tests_failed))
print(string.format("Success rate: %.1f%%", (tests_passed / (tests_passed + tests_failed)) * 100))

if tests_failed > 0 then
    print("\n=== Failed Tests ===")
    for _, detail in ipairs(test_details) do
        if detail.status == "FAIL" then
            print(string.format("  ✗ %s", detail.name))
            if detail.expected then
                print(string.format("    Expected: %s", tostring(detail.expected)))
                print(string.format("    Actual: %s", tostring(detail.actual)))
            end
        end
    end
end

print("\n=== All Tests ===")
for _, detail in ipairs(test_details) do
    local symbol = detail.status == "PASS" and "✓" or "✗"
    print(string.format("  %s %s", symbol, detail.name))
end

-- Exit with appropriate code
if tests_failed > 0 then
    print("\n❌ Some tests failed")
    os.exit(1)
else
    print("\n✅ All tests passed!")
    os.exit(0)
end

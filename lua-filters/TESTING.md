# Testing Lua Spam Filters

Comprehensive test suite for Bitcoin Knots Lua spam filters.

## Quick Start

Run all tests:

```bash
cd lua-filters
lua test_filters.lua
```

## Test Coverage

The test suite validates all spam detection patterns and filter behavior:

### Test Groups

1. **Clean Transactions** (4 tests)
   - Verifies clean transactions are accepted
   - Confirms zero spam scores for legitimate transactions
   - Tests both P2WSH and OP_RETURN detectors

2. **P2WSH Fake Multisig Detection** (3 tests)
   - Detects transactions with >10 pubkeys
   - Identifies fake pubkey patterns (zeros, repetition)
   - Handles normal multisig transactions correctly

3. **OP_RETURN Spam Detection** (6 tests)
   - Knotwork magic prefix (0x01bc) detection → 95 score
   - Oversized data (>80 bytes) detection → 40 score
   - Continuation pattern detection → 60 score
   - Normal OP_RETURN data acceptance

4. **Composite Filter** (5 tests)
   - Validates filter combination logic
   - Ensures individual detector rejections are respected
   - Tests score aggregation

5. **Edge Cases** (1 test)
   - Normal-sized OP_RETURN data acceptance

## Test Results

```
=== Test Results ===
Total tests: 19
Passed: 19
Failed: 0
Success rate: 100.0%
```

### All Tests Passing ✓

```
✓ P2WSH: Clean transaction should be accepted
✓ P2WSH: Clean transaction score should be 0
✓ OP_RETURN: Clean transaction should be accepted
✓ OP_RETURN: Clean transaction score should be 0
✓ P2WSH: Transaction with 12 fake pubkeys should be rejected
✓ P2WSH: Spam transaction should have score > 0
✓ OP_RETURN: Knotwork magic prefix should be rejected
✓ OP_RETURN: Knotwork spam should have high score (>=90)
✓ OP_RETURN: Oversized data (100 bytes) should be rejected
✓ OP_RETURN: Oversized data should have score >= 40
✓ OP_RETURN: Continuation pattern should be rejected
✓ OP_RETURN: Continuation pattern should have score >= 60
✓ Composite: P2WSH spam should be rejected
✓ Composite: P2WSH spam should have score > 0
✓ Composite: OP_RETURN spam should be rejected
✓ Composite: Knotwork spam should have high score
✓ Composite: Clean transaction should be accepted
✓ Composite: Clean transaction score should be 0
✓ OP_RETURN: Normal size OP_RETURN should be accepted
```

## Test Architecture

### Mock Bitcoin Knots API

The test suite includes a complete mock implementation of the Bitcoin Knots transaction API:

```lua
-- Mock transaction object
create_mock_tx(inputs, outputs)
  :get_inputs() → array of inputs
  :get_outputs() → array of outputs
  :get_txid() → string
  :get_weight() → number

-- Mock input object
create_mock_input(witness_data)
  :get_witness() → array of witness stack items
  :get_txid() → string
  :get_vout() → number

-- Mock output object
create_mock_output(script_pubkey, value, is_opreturn)
  :get_script_pubkey() → byte string
  :get_value() → satoshis
  :is_op_return() → boolean

-- Mock context object
create_mock_ctx()
  :log_info(msg)
  :log_warn(msg)
  :log_error(msg)
```

### Test Helpers

#### Create Fake Multisig Script

```lua
create_fake_multisig_script(num_pubkeys)
```

Generates a P2WSH witness script with fake pubkeys:
- OP_2 (required signatures)
- N x [PUSH(33) 0x02 + 32 zero bytes] (fake pubkeys)
- OP_N (total pubkeys)
- OP_CHECKMULTISIG

#### Create OP_RETURN Script

```lua
create_opreturn_script(data)
```

Generates proper OP_RETURN scriptPubKey:
- Handles data ≤75 bytes: `OP_RETURN PUSH(N) <data>`
- Handles data ≤255 bytes: `OP_RETURN OP_PUSHDATA1 <len> <data>`
- Handles data >255 bytes: `OP_RETURN OP_PUSHDATA2 <len_le> <data>`

## Running Individual Test Groups

Modify `test_filters.lua` to run specific tests:

```lua
-- Comment out test groups you don't want to run
-- Example: Skip edge case tests
-- print("\nTest Group 8: Edge Cases")
-- result = opreturn_spam.validate(normal_opreturn_tx, ctx)
-- assert_true(result.accept, "OP_RETURN: Normal size OP_RETURN should be accepted")
```

## Adding New Tests

### Test Framework Functions

```lua
-- Assertions
assert_equal(actual, expected, test_name)
assert_true(value, test_name)
assert_false(value, test_name)
```

### Example Test

```lua
-- Test description
print("\nTest Group N: Your Test Name")

-- Create mock transaction
local test_tx = create_mock_tx(
    {create_mock_input(witness_data)},
    {create_mock_output(script, value, is_opreturn)}
)

-- Run filter
local ctx = create_mock_ctx()
local result = filter.validate(test_tx, ctx)

-- Assert expectations
assert_false(result.accept, "Your test should reject")
assert_true(result.score >= 50, "Score should be high")
```

## Test Scenarios Covered

### P2WSH Spam Scenarios

| Scenario | Pubkeys | Expected | Score |
|----------|---------|----------|-------|
| Clean (no witness) | 0 | Accept | 0 |
| Normal multisig | 3 | Accept* | 0-100 |
| Excessive pubkeys | 12 | Reject | >0 |

*Note: May flag if pubkeys appear fake (all zeros)

### OP_RETURN Spam Scenarios

| Scenario | Data | Expected | Score |
|----------|------|----------|-------|
| No OP_RETURN | - | Accept | 0 |
| Normal data | 22 bytes | Accept | 0 |
| Knotwork magic | 0x01bc prefix | Reject | 95 |
| Oversized data | 100 bytes | Reject | 40 |
| Continuation | Small output + OP_RETURN | Reject | 60 |

### Composite Filter Scenarios

| Input | P2WSH Result | OP_RETURN Result | Final |
|-------|--------------|------------------|-------|
| Clean | Accept (0) | Accept (0) | Accept |
| P2WSH spam | Reject (100) | Accept (0) | Reject |
| OP_RETURN spam | Accept (0) | Reject (95) | Reject |
| Both spam | Reject (100) | Reject (95) | Reject |

## Continuous Integration

To integrate into CI/CD:

```bash
#!/bin/bash
# ci-test.sh

cd lua-filters
lua test_filters.lua

if [ $? -eq 0 ]; then
    echo "✅ All spam filter tests passed"
    exit 0
else
    echo "❌ Spam filter tests failed"
    exit 1
fi
```

## Performance Testing

Add timing to test suite:

```lua
local start_time = os.clock()

-- Run all tests
-- ...

local elapsed = (os.clock() - start_time) * 1000
print(string.format("\nTest execution time: %.2f ms", elapsed))
```

## Test Data

Test transactions use minimal valid structure:
- **Witness scripts**: Valid CHECKMULTISIG format
- **OP_RETURN scripts**: Proper Bitcoin script encoding
- **Values**: Representative satoshi amounts

## Troubleshooting

### Lua Not Found

```bash
# Install Lua 5.2+
apt-get install lua5.2  # Debian/Ubuntu
brew install lua        # macOS
```

### Module Path Issues

```lua
-- Add to test_filters.lua if filters not found
package.path = package.path .. ";/path/to/lua-filters/?.lua"
```

### Test Failures

1. Check filter logic in `policy/*.lua`
2. Verify test expectations are correct
3. Add debug prints to see actual vs expected values
4. Review Bitcoin script encoding in test helpers

## Future Enhancements

Potential test additions:

- [ ] Benchmark performance (transactions/second)
- [ ] Fuzzing with random transaction data
- [ ] Property-based testing
- [ ] Integration tests with actual Bitcoin Knots
- [ ] Regression tests for known spam patterns
- [ ] Coverage analysis

## License

Test code is provided under the same license as the spam filters.

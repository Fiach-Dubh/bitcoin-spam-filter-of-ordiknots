# Bitcoin Knots Lua Spam Filters

Modular Lua-based transaction filters for Bitcoin Knots that detect and block UTXO spam patterns. Compatible with [Bitcoin Knots PR #119](https://github.com/bitcoinknots/bitcoin/pull/119).

## Overview

This package provides scriptable mempool policy filters to identify and reject spam transactions targeting:

- **P2WSH Fake Multisig**: Detects suspicious CHECKMULTISIG patterns with fake pubkeys (>10 pubkeys or high fake-pubkey ratio)
- **Chained OP_RETURN**: Identifies data embedding via chained OP_RETURN outputs with magic prefix `0x01bc` (Knotwork/444 protocol)

## Filter Files

### Individual Detectors

- **`policy/p2wsh_spam.lua`** - P2WSH fake multisig detector
  - Analyzes witness scripts for CHECKMULTISIG patterns
  - Identifies fake pubkeys via pattern analysis (excessive zeros, repeating bytes)
  - Flags transactions with >10 pubkeys or >50% fake pubkeys
  - Returns score: 0 (clean) to 100 (definite spam)

- **`policy/opreturn_spam.lua`** - Chained OP_RETURN detector
  - Detects Knotwork magic prefix `0x01bc` (score: 95)
  - Identifies continuation output patterns (score: 60)
  - Flags oversized OP_RETURN data >80 bytes (score: 40)

### Composite Filter

- **`policy/spam_filter.lua`** - Combined spam detector
  - Runs both P2WSH and OP_RETURN detectors
  - Configurable rejection threshold (default: 50)
  - Returns highest score from all detectors
  - Combines rejection reasons for logging

## Installation

### Prerequisites

Bitcoin Knots with Lua filter support (PR #119 or later)

### Setup

1. **Copy filters to Bitcoin Knots data directory:**

```bash
# Linux/macOS
cp -r lua-filters/policy ~/.bitcoin/policy/

# Or specify custom directory in bitcoin.conf
mkdir -p /path/to/filters/policy
cp lua-filters/policy/*.lua /path/to/filters/policy/
```

2. **Configure Bitcoin Knots (`bitcoin.conf`):**

```conf
# Enable Lua policy filters
policyfilters=1

# Set filter directory (optional, defaults to datadir/policy)
policyfilterdir=/path/to/filters

# Load specific filter
policyfilter=policy/spam_filter.lua

# Or load individual filters
# policyfilter=policy/p2wsh_spam.lua
# policyfilter=policy/opreturn_spam.lua
```

3. **Restart Bitcoin Knots:**

```bash
bitcoind -daemon
```

4. **Verify filter is loaded:**

```bash
bitcoin-cli getpolicyfilterinfo
```

## Configuration

### Adjusting Rejection Threshold

Edit `spam_filter.lua` to modify the rejection threshold:

```lua
local CONFIG = {
    rejection_threshold = 50,  -- Change this value (0-100)
    enable_p2wsh_detection = true,
    enable_opreturn_detection = true,
    enable_logging = true
}
```

**Recommended thresholds:**
- **Conservative**: `threshold = 70` - Only reject high-confidence spam
- **Balanced**: `threshold = 50` - Default, blocks most spam patterns
- **Aggressive**: `threshold = 30` - Reject more broadly (may catch false positives)

### Enable/Disable Individual Detectors

```lua
local CONFIG = {
    -- Disable P2WSH detection, keep OP_RETURN only
    enable_p2wsh_detection = false,
    enable_opreturn_detection = true,
}
```

## How It Works

### Transaction Validation Flow

```
Incoming Transaction
    ↓
Bitcoin Knots Mempool
    ↓
Lua Filter: validate(tx, ctx)
    ↓
├─→ P2WSH Detector → Score (0-100)
└─→ OP_RETURN Detector → Score (0-100)
    ↓
Take Maximum Score
    ↓
Score ≥ Threshold? → REJECT
Score < Threshold → ACCEPT
```

### P2WSH Spam Detection Logic

1. **Extract witness scripts** from transaction inputs
2. **Identify CHECKMULTISIG** patterns (opcode `0xae`)
3. **Parse pubkeys** from witness script
4. **Analyze each pubkey** for fake patterns:
   - Excessive zero bytes (>10 or >4 consecutive)
   - Repeating byte patterns (4+ identical bytes)
5. **Calculate spam score**:
   - Immediate rejection: >10 pubkeys
   - High suspicion: >50% fake pubkeys with >3 total

### OP_RETURN Spam Detection Logic

1. **Find OP_RETURN outputs** in transaction
2. **Extract data** after skipping PUSH opcodes
3. **Check for patterns**:
   - **Magic prefix `0x01bc`** (Knotwork/444 protocol) → Score: 95
   - **Continuation pattern** (small value output + OP_RETURN) → Score: 60
   - **Oversized data** (>80 bytes) → Score: 40

## Testing

### Test Individual Filters

**Test P2WSH detector:**
```bash
# Create test transaction with fake multisig
bitcoin-cli createrawtransaction ...
bitcoin-cli testmempoolaccept '["<hex>"]'
```

**Test OP_RETURN detector:**
```bash
# Create transaction with Knotwork magic prefix
# Expected rejection: "Knotwork magic prefix (444) detected"
```

### Monitor Filter Activity

```bash
# Watch debug log for filter rejections
tail -f ~/.bitcoin/debug.log | grep "spam filter"

# Check mempool rejection reasons
bitcoin-cli getrawmempool | xargs -I {} bitcoin-cli getmempoolentry {}
```

## Spam Pattern Examples

### P2WSH Fake Multisig

```
Witness Script Structure:
OP_2                           # Required signatures
OP_PUSH(33) 02000000...        # Fake pubkey (all zeros)
OP_PUSH(33) 02111111...        # Fake pubkey (repeating)
OP_PUSH(33) 02222222...        # Fake pubkey (repeating)
...                            # 10+ more fake pubkeys
OP_15                          # Total pubkeys
OP_CHECKMULTISIG               # 0xae

Detection: >10 pubkeys → REJECT
```

### Chained OP_RETURN (Knotwork/444)

```
Output 0:
  value: 546 sats
  scriptPubKey: OP_RETURN 01bc 00 0a <data>
                           ^^^^ magic prefix
                                ^^ chunk index
                                   ^^ total chunks

Output 1:
  value: 1000 sats (continuation output)
  scriptPubKey: <address>

Detection: Magic prefix 0x01bc → REJECT (score 95)
```

## API Reference

### Filter Function Signature

```lua
function validate(tx, ctx)
    -- tx: Transaction object with methods
    -- ctx: Context object with logging functions
    
    return {
        accept = true/false,  -- Whether to accept transaction
        score = 0-100,        -- Spam confidence score
        reason = "..."        -- Human-readable reason
    }
end
```

### Transaction Object (`tx`)

| Method | Returns | Description |
|--------|---------|-------------|
| `tx:get_inputs()` | `table` | Array of transaction inputs |
| `tx:get_outputs()` | `table` | Array of transaction outputs |
| `tx:get_weight()` | `number` | Transaction weight |
| `tx:get_txid()` | `string` | Transaction ID (hex) |

### Input Object

| Method | Returns | Description |
|--------|---------|-------------|
| `input:get_witness()` | `table` | Witness stack (array of byte strings) |
| `input:get_txid()` | `string` | Previous output txid |
| `input:get_vout()` | `number` | Previous output index |

### Output Object

| Method | Returns | Description |
|--------|---------|-------------|
| `output:get_value()` | `number` | Output value in satoshis |
| `output:get_script_pubkey()` | `string` | scriptPubKey bytes |
| `output:is_op_return()` | `boolean` | True if OP_RETURN output |

### Context Object (`ctx`)

| Method | Description |
|--------|-------------|
| `ctx:log_info(msg)` | Log informational message |
| `ctx:log_warn(msg)` | Log warning message |
| `ctx:log_error(msg)` | Log error message |

## Performance Considerations

- **Filter execution time**: ~1-5ms per transaction (typical)
- **Memory overhead**: Minimal (~100KB per filter state)
- **Mempool impact**: Filters run during `PolicyChecks`, before `ConsensusChecks`
- **False positives**: Configure threshold to balance security vs. usability

## Troubleshooting

### Filter Not Loading

```bash
# Check filter syntax
lua policy/spam_filter.lua

# Verify file permissions
ls -la ~/.bitcoin/policy/

# Check bitcoin.conf settings
bitcoin-cli getinfo | grep policy
```

### Unexpected Rejections

```bash
# Check debug log for rejection reasons
grep "Spam detected" ~/.bitcoin/debug.log

# Lower rejection threshold temporarily
# Edit spam_filter.lua: rejection_threshold = 70
```

### Performance Issues

```bash
# Disable individual detectors if too slow
# Edit spam_filter.lua:
#   enable_p2wsh_detection = false  # Disable P2WSH checks
```

## Contributing

To add new spam detection patterns:

1. Create new detector in `policy/your_detector.lua`
2. Implement `validate(tx, ctx)` function
3. Return `{accept, score, reason}` table
4. Export module: `return {validate = validate}`
5. Add to `spam_filter.lua` composite filter

## References

- [Bitcoin Knots PR #119](https://github.com/bitcoinknots/bitcoin/pull/119) - Lua filter system
- [Taproot Wizards ordiknots](https://github.com/taproot-wizards/ordiknots) - Spam technique documentation
- [Bitcoin Knots](https://bitcoinknots.org/) - Bitcoin Knots website

## License

This filter code is provided as-is for Bitcoin Knots integration. See individual file headers for licensing details.

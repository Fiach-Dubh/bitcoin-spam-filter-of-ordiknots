# Bitcoin Knots Integration Guide

Step-by-step instructions for integrating these Lua spam filters into Bitcoin Knots.

## Prerequisites

- Bitcoin Knots 28.x or later with PR #119 Lua filter support
- Basic knowledge of Bitcoin Core/Knots configuration
- Lua 5.3+ (included with Bitcoin Knots)

## Quick Start (5 minutes)

### 1. Verify Bitcoin Knots Version

```bash
bitcoind --version
# Should show: Bitcoin Knots version 28.x or later
```

If you don't have Lua filter support, you'll need to:
- Build Bitcoin Knots from the `lua-policies-poc` branch
- Or wait for PR #119 to be merged into a release

### 2. Stop Bitcoin Knots

```bash
bitcoin-cli stop
# Wait for shutdown
```

### 3. Install Filters

```bash
# Copy filters to Bitcoin data directory
cp -r lua-filters/policy ~/.bitcoin/

# Verify installation
ls -la ~/.bitcoin/policy/
# Should show: p2wsh_spam.lua, opreturn_spam.lua, spam_filter.lua
```

### 4. Configure Bitcoin Knots

Add to `~/.bitcoin/bitcoin.conf`:

```conf
# Enable Lua policy filters
policyfilters=1

# Load composite spam filter
policyfilter=policy/spam_filter.lua
```

### 5. Start Bitcoin Knots

```bash
bitcoind -daemon

# Check logs for filter loading
tail -f ~/.bitcoin/debug.log | grep -i "spam filter"
```

Expected output:
```
Bitcoin UTXO spam filter loaded
  - P2WSH fake multisig detection: enabled
  - Chained OP_RETURN detection: enabled
  - Rejection threshold: 50
```

### 6. Test the Filter

```bash
# Check filter status
bitcoin-cli getpolicyfilterinfo

# Monitor mempool rejections
bitcoin-cli getrawmempool
```

## Advanced Configuration

### Custom Filter Directory

```conf
# bitcoin.conf
policyfilterdir=/custom/path/to/filters
policyfilter=policy/spam_filter.lua
```

### Multiple Filters (Chain)

Load multiple filters in sequence:

```conf
policyfilter=policy/p2wsh_spam.lua
policyfilter=policy/opreturn_spam.lua
policyfilter=policy/custom_filter.lua
```

Each filter runs in order; transaction must pass all filters.

### Logging Configuration

Adjust filter logging verbosity:

```lua
-- Edit spam_filter.lua
local CONFIG = {
    enable_logging = true,  -- Set to false to disable filter logs
}
```

## Building Bitcoin Knots with Lua Support

If you need to build from source:

### Linux

```bash
# Clone Bitcoin Knots
git clone https://github.com/bitcoinknots/bitcoin.git
cd bitcoin

# Checkout Lua filter branch
git fetch origin pull/119/head:lua-filters
git checkout lua-filters

# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils libevent-dev libboost-all-dev libssl-dev liblua5.3-dev

# Build
./autogen.sh
./configure --with-lua
make -j$(nproc)
sudo make install
```

### macOS

```bash
# Install dependencies
brew install lua@5.3 boost libevent

# Clone and build
git clone https://github.com/bitcoinknots/bitcoin.git
cd bitcoin
git fetch origin pull/119/head:lua-filters
git checkout lua-filters

./autogen.sh
./configure --with-lua CPPFLAGS="-I/opt/homebrew/opt/lua@5.3/include/lua5.3" \
    LDFLAGS="-L/opt/homebrew/opt/lua@5.3/lib"
make -j$(sysctl -n hw.ncpu)
sudo make install
```

## Deployment Scenarios

### Scenario 1: Personal Full Node

**Goal**: Block obvious spam, maintain good connectivity

```lua
-- spam_filter.lua
local CONFIG = {
    rejection_threshold = 60,  -- Conservative
    enable_p2wsh_detection = true,
    enable_opreturn_detection = true,
}
```

### Scenario 2: Mining Pool

**Goal**: Maximize fee revenue, only block clear spam

```lua
local CONFIG = {
    rejection_threshold = 80,  -- Very conservative
    enable_p2wsh_detection = true,
    enable_opreturn_detection = false,  -- Allow OP_RETURN
}
```

### Scenario 3: Privacy-Focused Node

**Goal**: Aggressively block all spam patterns

```lua
local CONFIG = {
    rejection_threshold = 30,  -- Aggressive
    enable_p2wsh_detection = true,
    enable_opreturn_detection = true,
}
```

### Scenario 4: P2WSH Only

**Goal**: Only block fake multisig, allow OP_RETURN

```conf
# bitcoin.conf
policyfilter=policy/p2wsh_spam.lua
```

## Monitoring and Debugging

### Real-Time Monitoring

```bash
# Watch filter activity
tail -f ~/.bitcoin/debug.log | grep "spam\|policy"

# Check mempool acceptance
bitcoin-cli getmempoolinfo

# View rejected transactions (if logging enabled)
grep "REJECT" ~/.bitcoin/debug.log | tail -20
```

### Debug Mode

Enable verbose logging in `spam_filter.lua`:

```lua
function validate(tx, ctx)
    -- Add debug logging
    if ctx and ctx.log_info then
        ctx:log_info(string.format("Validating tx: %s", tx:get_txid()))
    end
    
    -- ... rest of validation
end
```

### Testing Specific Transactions

```bash
# Test if a transaction would be accepted
bitcoin-cli testmempoolaccept '["<rawtx_hex>"]'

# Response will include rejection reason if filtered
```

## Performance Tuning

### Benchmark Filter Performance

Add timing to `spam_filter.lua`:

```lua
function validate(tx, ctx)
    local start_time = os.clock()
    
    -- ... validation logic ...
    
    local elapsed = (os.clock() - start_time) * 1000
    if ctx and elapsed > 5 then
        ctx:log_warn(string.format("Slow filter: %.2f ms", elapsed))
    end
    
    return result
end
```

### Optimize for High Volume

```lua
local CONFIG = {
    -- Disable expensive checks under high load
    enable_p2wsh_detection = true,
    enable_opreturn_detection = false,  -- Faster
    rejection_threshold = 70,  -- Fewer rejections
}
```

## Updating Filters

### Hot Reload (If Supported)

```bash
# Update filter file
cp new_spam_filter.lua ~/.bitcoin/policy/

# Reload filters without restart
bitcoin-cli reloadpolicyfilters
```

### Manual Reload

```bash
# Update files
cp new_filters/*.lua ~/.bitcoin/policy/

# Restart node
bitcoin-cli stop
bitcoind -daemon
```

## Security Considerations

### Filter Code Review

```bash
# Review Lua code before deployment
cat ~/.bitcoin/policy/spam_filter.lua
cat ~/.bitcoin/policy/p2wsh_spam.lua
cat ~/.bitcoin/policy/opreturn_spam.lua
```

### Sandboxing

Bitcoin Knots Lua filters run in a sandboxed environment:
- No filesystem access
- No network access
- Limited standard library functions
- Cannot modify blockchain state

### Verification

```bash
# Verify filter checksums
sha256sum ~/.bitcoin/policy/*.lua

# Expected hashes (update these after review):
# p2wsh_spam.lua:    <hash>
# opreturn_spam.lua: <hash>
# spam_filter.lua:   <hash>
```

## Troubleshooting

### Problem: Filter Not Loading

**Symptoms**: No log messages about spam filter loading

**Solutions**:
1. Check `bitcoin.conf` has `policyfilters=1`
2. Verify filter file path: `ls ~/.bitcoin/policy/spam_filter.lua`
3. Check Lua syntax: `lua -l policy/spam_filter`
4. Review debug.log for errors: `grep -i error ~/.bitcoin/debug.log`

### Problem: All Transactions Rejected

**Symptoms**: Mempool empty, all transactions failing

**Solutions**:
1. Check rejection threshold: Edit `spam_filter.lua`, increase threshold to 80
2. Disable filters temporarily: Remove `policyfilter=` from bitcoin.conf
3. Review debug logs for reasons

### Problem: No Spam Being Blocked

**Symptoms**: Known spam transactions being accepted

**Solutions**:
1. Lower rejection threshold to 40
2. Enable logging to see scores: Set `enable_logging = true`
3. Verify filters are active: `bitcoin-cli getpolicyfilterinfo`

### Problem: High CPU Usage

**Symptoms**: `bitcoind` using excessive CPU

**Solutions**:
1. Disable P2WSH detection (more expensive): `enable_p2wsh_detection = false`
2. Increase rejection threshold to reduce processing
3. Profile filter with timing logs (see Performance Tuning)

## Migration from Other Filter Systems

### From Datacarrier Limits

If you were using `-datacarriersize`:

```conf
# Old approach (bitcoin.conf)
datacarriersize=42

# New approach with Lua filters
policyfilters=1
policyfilter=policy/opreturn_spam.lua
```

Edit `opreturn_spam.lua` to match your size limit.

### From Permitbaremultisig

If you were using `-permitbaremultisig=0`:

```conf
# Old approach
permitbaremultisig=0

# New approach: use P2WSH detector
policyfilters=1
policyfilter=policy/p2wsh_spam.lua
```

## Support

For issues with:
- **Filter logic**: Open issue in this repository
- **Bitcoin Knots integration**: See [Bitcoin Knots documentation](https://bitcoinknots.org/)
- **PR #119 specific**: Comment on [GitHub PR #119](https://github.com/bitcoinknots/bitcoin/pull/119)

## Next Steps

After successful integration:
1. Monitor filter performance for 24-48 hours
2. Adjust rejection threshold based on false positive rate
3. Consider contributing improvements back to the project
4. Share your node's spam blocking statistics with the community

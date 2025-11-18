# Bitcoin Spam Filter - Anti-ordiknots

A scriptable Bitcoin mempool policy filter designed to detect and block UTXO spam patterns, specifically targeting data embedding techniques like those documented in the [taproot-wizards/ordiknots](https://github.com/taproot-wizards/ordiknots) repository.

## Overview

This tool helps Bitcoin node operators identify and filter out spam transactions that use various data embedding techniques:

- **P2WSH Fake Multisig**: Detects transactions using fake pubkeys in CHECKMULTISIG scripts to embed arbitrary data
- **Chained OP_RETURN**: Identifies chains of OP_RETURN outputs with continuation patterns and "knotwork" magic prefixes
- **Custom Filters**: Scriptable filter engine supporting both JavaScript/TypeScript and Lua for custom detection rules

## Features

- 🔍 **Multiple Detection Engines**: Built-in detectors for common spam patterns
- 📊 **Scoring System**: Configurable threshold-based transaction rejection
- 🔧 **Scriptable**: Support for custom filters in JavaScript/TypeScript and Lua
- 🚀 **CLI Tool**: Command-line interface for testing and analyzing transactions
- 📦 **Modular**: Use as a library or standalone tool

## Installation

```bash
npm install
npm run build
```

## Quick Start

### Filter a Transaction

```bash
npm start filter <transaction-hex> --threshold 80 --verbose
```

### Analyze Transaction Structure

```bash
npm start analyze <transaction-hex>
```

### Run Tests

```bash
npm start test
```

## Usage

### CLI Examples

**Filter a transaction from hex:**
```bash
npm start filter 02000000000101... --threshold 75
```

**Analyze a transaction:**
```bash
npm start analyze 02000000000101...
```

**Filter with custom threshold:**
```bash
npm start filter tx.hex --threshold 50 --verbose
```

### Programmatic Usage

```typescript
import { TransactionParser, FilterEngine, FilterConfig } from './src/index.js';

const config: FilterConfig = {
  threshold: 80,
  enableP2WSHDetection: true,
  enableOpReturnDetection: true
};

const engine = new FilterEngine(config);

engine.addJSFilter((tx) => {
  return {
    accept: tx.weight < 400000,
    score: tx.weight > 400000 ? 100 : 0,
    detections: [],
    message: 'Weight check'
  };
});

const tx = TransactionParser.parseHex(txHex);
const result = engine.evaluateTransaction(tx);

if (!result.accept) {
  console.log('Transaction rejected:', result.message);
}
```

## Detection Methods

### P2WSH Fake Multisig Detection

Identifies suspicious patterns in P2WSH witness scripts:
- Large number of pubkeys in CHECKMULTISIG (>10)
- High ratio of fake pubkeys (prefixed 0x02/0x03 with repetitive or zero-heavy data)
- Excessive witness script sizes

**Confidence scoring:**
- High pubkey count: Higher confidence
- Repetitive patterns in pubkey data: Higher confidence
- Multiple suspicious inputs: Cumulative scoring

### Chained OP_RETURN Detection

Detects data embedding via chained OP_RETURN outputs:
- Knotwork magic prefix detection (0x01bc / "444")
- Continuation output patterns (small value outputs ~9000 sats)
- Oversized OP_RETURN data (>80 bytes)
- Chunk indexing patterns

**Confidence scoring:**
- Magic prefix present: 95% confidence
- Continuation pattern: 60% confidence
- Oversized OP_RETURN: 40% confidence

## Custom Filters

### JavaScript/TypeScript Filters

```typescript
import { ParsedTransaction, FilterResult } from './src/types.js';

function customFilter(tx: ParsedTransaction): FilterResult {
  const hasLargeWitness = tx.inputs.some(input => 
    input.witness && input.witness.length > 15
  );
  
  return {
    accept: !hasLargeWitness,
    score: hasLargeWitness ? 70 : 0,
    detections: [],
    message: hasLargeWitness ? 'Large witness detected' : 'OK'
  };
}

engine.addJSFilter(customFilter);
```

### Lua Filters

**Note:** Lua scripting support is currently in development. The Lua engine (fengari) is designed for browser environments and is not functional in the Node.js runtime. For production use, implement custom filters using JavaScript/TypeScript as shown above.

Example Lua filter syntax (for future browser-based integration):

```lua
function evaluate_transaction(tx)
    local score = 0
    local accept = true
    
    for i, input in ipairs(tx.inputs) do
        if input.witness and #input.witness > 10 then
            score = score + 30
        end
    end
    
    if score >= 50 then
        accept = false
    end
    
    return {
        accept = accept,
        score = score,
        detections = {},
        message = "Lua filter result"
    }
end
```

**Current Status:** JavaScript/TypeScript filters are fully functional and recommended for all use cases.

## Configuration

```typescript
interface FilterConfig {
  threshold: number;
  enableP2WSHDetection: boolean;
  enableOpReturnDetection: boolean;
  customFilters?: string[];
}
```

- **threshold**: Spam score threshold for rejection (0-100+)
- **enableP2WSHDetection**: Enable P2WSH fake multisig detector
- **enableOpReturnDetection**: Enable chained OP_RETURN detector
- **customFilters**: Paths to custom filter scripts

## Architecture

```
src/
├── types.ts                    # TypeScript interfaces
├── parser.ts                   # Transaction parsing
├── filter-engine.ts            # Main filter orchestration
├── lua-engine.ts               # Lua scripting support
├── detectors/
│   ├── p2wsh-detector.ts      # P2WSH spam detection
│   └── opreturn-detector.ts   # OP_RETURN spam detection
├── cli.ts                      # Command-line interface
└── test.ts                     # Test suite

examples/
├── filters/
│   ├── high-witness-filter.ts  # Example TypeScript filter
│   └── fake-pubkey-filter.lua  # Example Lua filter
└── usage-example.ts            # Usage examples
```

## Testing

Run the built-in test suite:

```bash
npm start test
```

This will run tests against:
- P2WSH fake multisig spam transactions
- Chained OP_RETURN patterns
- Normal transactions (should pass)
- Custom filter functionality

## Integration with Bitcoin Core

To use this filter with a Bitcoin node's mempool policy:

1. Export transactions from mempool via RPC
2. Parse and filter using this tool
3. Reject transactions with scores above threshold
4. Optionally: Integrate via `testmempoolaccept` RPC call

## Contributing

To add new detection techniques:

1. Create a new detector in `src/detectors/`
2. Implement the `detect(tx: ParsedTransaction): DetectionResult` interface
3. Add tests in `src/test.ts`
4. Update documentation

## License

MIT

## References

- [Ordiknots Repository](https://github.com/taproot-wizards/ordiknots) - Documentation of spam techniques
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) - Bitcoin node implementation
- [Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) - Enhanced Bitcoin node

## Disclaimer

This tool is for educational and research purposes. Use at your own risk. Always test thoroughly before deploying in production environments.

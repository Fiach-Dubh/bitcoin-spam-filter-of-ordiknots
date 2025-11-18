#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { TransactionParser } from './parser.js';
import { FilterEngine } from './filter-engine.js';
import { FilterConfig } from './types.js';

const program = new Command();

program
  .name('bitcoin-spam-filter')
  .description('Scriptable Bitcoin mempool policy filter to detect and block UTXO spam')
  .version('1.0.0');

program
  .command('filter')
  .description('Filter a Bitcoin transaction')
  .argument('<tx-hex-or-json>', 'Transaction in hex format or path to JSON file')
  .option('-t, --threshold <number>', 'Spam score threshold for rejection', '80')
  .option('--no-p2wsh', 'Disable P2WSH fake multisig detection')
  .option('--no-opreturn', 'Disable chained OP_RETURN detection')
  .option('-j, --json', 'Input is JSON file path instead of hex')
  .option('-v, --verbose', 'Show detailed detection results')
  .action((input, options) => {
    try {
      let tx;
      
      if (options.json) {
        const jsonData = JSON.parse(readFileSync(input, 'utf-8'));
        tx = TransactionParser.parseJSON(jsonData);
      } else if (input.startsWith('{')) {
        tx = TransactionParser.parseJSON(JSON.parse(input));
      } else {
        tx = TransactionParser.parseHex(input);
      }

      const config: FilterConfig = {
        threshold: parseFloat(options.threshold),
        enableP2WSHDetection: options.p2wsh !== false,
        enableOpReturnDetection: options.opreturn !== false
      };

      const engine = new FilterEngine(config);
      const result = engine.evaluateTransaction(tx);

      console.log('\n=== Filter Result ===');
      console.log(`Decision: ${result.accept ? '✅ ACCEPT' : '❌ REJECT'}`);
      console.log(`Spam Score: ${result.score.toFixed(2)} / ${config.threshold}`);
      console.log(`Message: ${result.message}`);

      if (options.verbose && result.detections.length > 0) {
        console.log('\n=== Detections ===');
        result.detections.forEach((detection, i) => {
          console.log(`\n${i + 1}. ${detection.reason}`);
          console.log(`   Confidence: ${detection.confidence.toFixed(2)}%`);
          if (detection.details) {
            console.log(`   Details:`, JSON.stringify(detection.details, null, 2));
          }
        });
      }

      console.log('\n');
      process.exit(result.accept ? 0 : 1);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

program
  .command('analyze')
  .description('Analyze transaction structure without filtering')
  .argument('<tx-hex-or-json>', 'Transaction in hex format or path to JSON file')
  .option('-j, --json', 'Input is JSON file path instead of hex')
  .action((input, options) => {
    try {
      let tx;
      
      if (options.json) {
        const jsonData = JSON.parse(readFileSync(input, 'utf-8'));
        tx = TransactionParser.parseJSON(jsonData);
      } else {
        tx = TransactionParser.parseHex(input);
      }

      console.log('\n=== Transaction Analysis ===');
      console.log(`TXID: ${tx.txid}`);
      console.log(`Version: ${tx.version}`);
      console.log(`Locktime: ${tx.locktime}`);
      console.log(`Size: ${tx.size} bytes`);
      console.log(`Virtual Size: ${tx.vsize} vbytes`);
      console.log(`Weight: ${tx.weight} WU`);
      console.log(`\nInputs: ${tx.inputs.length}`);
      
      tx.inputs.forEach((input, i) => {
        console.log(`  ${i}: ${input.txid}:${input.vout}`);
        if (input.witness && input.witness.length > 0) {
          console.log(`     Witness items: ${input.witness.length}`);
        }
      });

      console.log(`\nOutputs: ${tx.outputs.length}`);
      tx.outputs.forEach((output, i) => {
        console.log(`  ${i}: ${output.value} sats (${output.scriptPubKeyType || 'unknown'})`);
      });

      console.log('\n');
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('test')
  .description('Run built-in tests with example spam transactions')
  .action(async () => {
    console.log('\n🧪 Running spam filter tests...\n');
    
    const { runTests } = await import('./test.js');
    runTests();
  });

program.parse();

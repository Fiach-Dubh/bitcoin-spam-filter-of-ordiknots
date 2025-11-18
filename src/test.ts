import { FilterEngine } from './filter-engine.js';
import { TransactionParser } from './parser.js';
import { P2WSHFakeMultisigDetector } from './detectors/p2wsh-detector.js';
import { ChainedOpReturnDetector } from './detectors/opreturn-detector.js';
import { FilterConfig, ParsedTransaction } from './types.js';

function createMockP2WSHSpamTransaction(): ParsedTransaction {
  const witnessScript = '0151' + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '21' + '02' + '00'.repeat(32) + 
    '5cae';
  
  return {
    txid: 'test-p2wsh-spam-txid',
    version: 2,
    locktime: 0,
    inputs: [{
      txid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      vout: 0,
      scriptSig: '',
      witness: ['00', '00', witnessScript],
      sequence: 0xffffffff
    }],
    outputs: [{
      value: 1000,
      scriptPubKey: '0020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      scriptPubKeyType: 'witness_v0_scripthash'
    }],
    weight: 400,
    size: 200,
    vsize: 100
  };
}

function createMockOpReturnChainTransaction(): ParsedTransaction {
  return {
    txid: 'test-opreturn-chain-txid',
    version: 2,
    locktime: 0,
    inputs: [{
      txid: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      vout: 0,
      scriptSig: '',
      sequence: 0xffffffff
    }],
    outputs: [
      {
        value: 0,
        scriptPubKey: '6a2601bc000148656c6c6f20576f726c6421',
        scriptPubKeyType: 'nulldata'
      },
      {
        value: 9000,
        scriptPubKey: '001400112233445566778899aabbccddeeff00112233',
        scriptPubKeyType: 'witness_v0_keyhash'
      },
      {
        value: 1000000,
        scriptPubKey: '001411223344556677889900aabbccddeeff00112233',
        scriptPubKeyType: 'witness_v0_keyhash'
      }
    ],
    weight: 300,
    size: 150,
    vsize: 75
  };
}

function createNormalTransaction(): ParsedTransaction {
  return {
    txid: 'test-normal-txid',
    version: 2,
    locktime: 0,
    inputs: [{
      txid: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      vout: 0,
      scriptSig: '',
      witness: ['3044022000000000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000000001', '030000000000000000000000000000000000000000000000000000000000000000'],
      sequence: 0xffffffff
    }],
    outputs: [
      {
        value: 100000000,
        scriptPubKey: '00140000000000000000000000000000000000000000',
        scriptPubKeyType: 'witness_v0_keyhash'
      },
      {
        value: 2000,
        scriptPubKey: '00141111111111111111111111111111111111111111',
        scriptPubKeyType: 'witness_v0_keyhash'
      }
    ],
    weight: 500,
    size: 250,
    vsize: 125
  };
}

export function runTests(): void {
  console.log('Test 1: P2WSH Fake Multisig Detection');
  console.log('─'.repeat(50));
  
  try {
    const spamTx = createMockP2WSHSpamTransaction();
    const result = P2WSHFakeMultisigDetector.detect(spamTx);
    
    console.log(`✓ Parsed transaction: ${spamTx.txid}`);
    console.log(`  Detection: ${result.detected ? '🚫 SPAM' : '✓ Clean'}`);
    console.log(`  Confidence: ${result.confidence.toFixed(2)}%`);
    console.log(`  Reason: ${result.reason}`);
  } catch (error) {
    console.log(`✗ Test failed: ${error instanceof Error ? error.message : error}`);
  }
  
  console.log('\nTest 2: Chained OP_RETURN Detection');
  console.log('─'.repeat(50));
  
  try {
    const chainTx = createMockOpReturnChainTransaction();
    const result = ChainedOpReturnDetector.detect(chainTx);
    
    console.log(`✓ Parsed transaction: ${chainTx.txid}`);
    console.log(`  Detection: ${result.detected ? '🚫 SPAM' : '✓ Clean'}`);
    console.log(`  Confidence: ${result.confidence.toFixed(2)}%`);
    console.log(`  Reason: ${result.reason}`);
  } catch (error) {
    console.log(`✗ Test failed: ${error instanceof Error ? error.message : error}`);
  }
  
  console.log('\nTest 3: Normal Transaction (Should Pass)');
  console.log('─'.repeat(50));
  
  try {
    const normalTx = createNormalTransaction();
    const config: FilterConfig = {
      threshold: 80,
      enableP2WSHDetection: true,
      enableOpReturnDetection: true
    };
    
    const engine = new FilterEngine(config);
    const result = engine.evaluateTransaction(normalTx);
    
    console.log(`✓ Parsed transaction: ${normalTx.txid}`);
    console.log(`  Decision: ${result.accept ? '✅ ACCEPT' : '❌ REJECT'}`);
    console.log(`  Score: ${result.score.toFixed(2)} / ${config.threshold}`);
    console.log(`  Message: ${result.message}`);
  } catch (error) {
    console.log(`✗ Test failed: ${error instanceof Error ? error.message : error}`);
  }
  
  console.log('\nTest 4: Filter Engine with Custom JS Filter');
  console.log('─'.repeat(50));
  
  try {
    const config: FilterConfig = {
      threshold: 50,
      enableP2WSHDetection: false,
      enableOpReturnDetection: false
    };
    
    const engine = new FilterEngine(config);
    
    engine.addJSFilter((tx: ParsedTransaction) => {
      const hasLargeWitness = tx.inputs.some(input => 
        input.witness && input.witness.length > 10
      );
      
      return {
        accept: !hasLargeWitness,
        score: hasLargeWitness ? 75 : 0,
        detections: [],
        message: hasLargeWitness ? 'Suspicious: Large witness data' : 'OK'
      };
    });
    
    const testTx = createMockP2WSHSpamTransaction();
    const result = engine.evaluateTransaction(testTx);
    
    console.log(`✓ Custom filter applied`);
    console.log(`  Decision: ${result.accept ? '✅ ACCEPT' : '❌ REJECT'}`);
    console.log(`  Score: ${result.score.toFixed(2)} / ${config.threshold}`);
  } catch (error) {
    console.log(`✗ Test failed: ${error instanceof Error ? error.message : error}`);
  }
  
  console.log('\nTest 5: OP_RETURN Data Extraction (PUSH Opcode Handling)');
  console.log('─'.repeat(50));
  
  try {
    const opReturnScript = '6a2601bc000148656c6c6f';
    const extracted = TransactionParser.extractOpReturnData(opReturnScript);
    
    if (extracted && extracted.length >= 2 && extracted[0] === 0x01 && extracted[1] === 0xbc) {
      console.log('✓ Magic prefix 0x01bc correctly extracted');
      console.log(`  Extracted data: ${extracted.toString('hex')}`);
    } else {
      console.log('✗ Failed to extract magic prefix correctly');
      console.log(`  Extracted: ${extracted ? extracted.toString('hex') : 'null'}`);
    }
  } catch (error) {
    console.log(`✗ Test failed: ${error instanceof Error ? error.message : error}`);
  }
  
  console.log('\n' + '='.repeat(50));
  console.log('✅ All tests completed!\n');
}

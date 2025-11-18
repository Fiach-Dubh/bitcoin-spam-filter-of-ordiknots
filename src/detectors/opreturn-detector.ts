import { ParsedTransaction, DetectionResult } from '../types.js';
import { TransactionParser } from '../parser.js';

const KNOTWORK_MAGIC = Buffer.from([0x01, 0xbc]);

export class ChainedOpReturnDetector {
  static detect(tx: ParsedTransaction): DetectionResult {
    const opReturnOutputs = tx.outputs.filter(out => 
      out.scriptPubKeyType === 'nulldata'
    );

    if (opReturnOutputs.length === 0) {
      return {
        detected: false,
        confidence: 0,
        reason: 'No OP_RETURN outputs found'
      };
    }

    let hasMagicPrefix = false;
    let hasChainPattern = false;
    const details: any = {};

    for (let i = 0; i < opReturnOutputs.length; i++) {
      const output = opReturnOutputs[i];
      const data = TransactionParser.extractOpReturnData(output.scriptPubKey);
      
      if (!data) continue;

      if (data.length >= 2 && data[0] === 0x01 && data[1] === 0xbc) {
        hasMagicPrefix = true;
        details.magicPrefix = true;
        
        if (data.length >= 4) {
          details.chunkIndex = data[2];
          details.totalChunks = data[3];
        }
      }
    }

    const hasContinuationOutput = tx.outputs.length >= 2 && 
      tx.outputs.some(out => out.value > 0 && out.value < 15000);

    if (hasContinuationOutput && opReturnOutputs.length > 0) {
      hasChainPattern = true;
      details.hasContinuationOutput = true;
    }

    if (hasMagicPrefix || hasChainPattern) {
      const confidence = hasMagicPrefix ? 95 : 60;
      
      return {
        detected: true,
        confidence,
        reason: hasMagicPrefix 
          ? 'Detected knotwork magic prefix (444) in OP_RETURN data'
          : 'Detected chained OP_RETURN pattern with continuation output',
        details
      };
    }

    if (opReturnOutputs.length > 0) {
      const largestOpReturn = Math.max(...opReturnOutputs.map(out => {
        const data = TransactionParser.extractOpReturnData(out.scriptPubKey);
        return data ? data.length : 0;
      }));

      if (largestOpReturn > 80) {
        return {
          detected: true,
          confidence: 40,
          reason: `OP_RETURN data exceeds standard size (${largestOpReturn} bytes)`,
          details: { opReturnSize: largestOpReturn }
        };
      }
    }

    return {
      detected: false,
      confidence: 0,
      reason: 'No suspicious OP_RETURN patterns detected'
    };
  }
}

import { ParsedTransaction, DetectionResult } from '../types.js';
import { TransactionParser } from '../parser.js';

export class P2WSHFakeMultisigDetector {
  static detect(tx: ParsedTransaction): DetectionResult {
    let suspiciousCount = 0;
    let totalP2WSH = 0;
    const details: any[] = [];

    for (const input of tx.inputs) {
      if (!input.witness || input.witness.length < 3) continue;

      const witnessScript = TransactionParser.extractWitnessScript(input.witness);
      if (!witnessScript) continue;

      totalP2WSH++;

      const analysis = this.analyzeWitnessScript(witnessScript);
      
      if (analysis.isSuspicious) {
        suspiciousCount++;
        details.push({
          txid: input.txid,
          vout: input.vout,
          ...analysis
        });
      }
    }

    if (suspiciousCount === 0) {
      return {
        detected: false,
        confidence: 0,
        reason: 'No suspicious P2WSH patterns found'
      };
    }

    const confidence = totalP2WSH > 0 ? (suspiciousCount / totalP2WSH) * 100 : 0;

    return {
      detected: true,
      confidence,
      reason: `Detected ${suspiciousCount} suspicious P2WSH CHECKMULTISIG patterns with fake pubkeys`,
      details
    };
  }

  private static analyzeWitnessScript(script: Buffer): any {
    const result = {
      isSuspicious: false,
      pubkeyCount: 0,
      fakePubkeyCount: 0,
      hasCheckmultisig: false,
      scriptSize: script.length
    };

    if (script.length === 0) return result;

    const lastByte = script[script.length - 1];
    result.hasCheckmultisig = lastByte === 0xae;

    if (!result.hasCheckmultisig) return result;

    const pubkeys: Buffer[] = [];
    let i = 1;

    while (i < script.length - 2) {
      const opcode = script[i];
      
      if (opcode === 0x21) {
        const pubkey = script.slice(i + 1, i + 34);
        pubkeys.push(pubkey);
        i += 34;
      } else if (opcode >= 0x51 && opcode <= 0x60) {
        i++;
      } else if (opcode === 0xae) {
        break;
      } else {
        i++;
      }
    }

    result.pubkeyCount = pubkeys.length;

    for (const pubkey of pubkeys) {
      if (pubkey.length === 33) {
        const prefix = pubkey[0];
        if (prefix === 0x02 || prefix === 0x03) {
          const isLikelyFake = this.isLikelyFakePubkey(pubkey);
          if (isLikelyFake) {
            result.fakePubkeyCount++;
          }
        }
      }
    }

    if (result.pubkeyCount > 3 && result.fakePubkeyCount > result.pubkeyCount * 0.5) {
      result.isSuspicious = true;
    }

    if (result.pubkeyCount > 10) {
      result.isSuspicious = true;
    }

    return result;
  }

  private static isLikelyFakePubkey(pubkey: Buffer): boolean {
    if (pubkey.length !== 33) return false;
    
    const prefix = pubkey[0];
    if (prefix !== 0x02 && prefix !== 0x03) return false;

    const data = pubkey.slice(1);
    
    let zeroCount = 0;
    let consecutiveZeros = 0;
    let maxConsecutiveZeros = 0;

    for (let i = 0; i < data.length; i++) {
      if (data[i] === 0) {
        zeroCount++;
        consecutiveZeros++;
        maxConsecutiveZeros = Math.max(maxConsecutiveZeros, consecutiveZeros);
      } else {
        consecutiveZeros = 0;
      }
    }

    if (maxConsecutiveZeros > 4 || zeroCount > 10) {
      return true;
    }

    let repeatingPatterns = 0;
    for (let i = 0; i < data.length - 3; i++) {
      if (data[i] === data[i + 1] && data[i] === data[i + 2] && data[i] === data[i + 3]) {
        repeatingPatterns++;
      }
    }

    return repeatingPatterns > 2;
  }
}

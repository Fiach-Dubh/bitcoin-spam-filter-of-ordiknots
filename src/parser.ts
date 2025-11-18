import * as bitcoin from 'bitcoinjs-lib';
import { ParsedTransaction, TransactionInput, TransactionOutput } from './types.js';

export class TransactionParser {
  static parseHex(txHex: string): ParsedTransaction {
    const tx = bitcoin.Transaction.fromHex(txHex);
    
    const inputs: TransactionInput[] = tx.ins.map((input, index) => {
      const witness = input.witness && input.witness.length > 0
        ? input.witness.map(w => w.toString('hex'))
        : undefined;
      
      return {
        txid: Buffer.from(input.hash).reverse().toString('hex'),
        vout: input.index,
        scriptSig: input.script.toString('hex'),
        witness,
        sequence: input.sequence
      };
    });

    const outputs: TransactionOutput[] = tx.outs.map((output, index) => {
      return {
        value: output.value,
        scriptPubKey: output.script.toString('hex'),
        scriptPubKeyType: this.detectScriptType(output.script)
      };
    });

    return {
      txid: tx.getId(),
      version: tx.version,
      locktime: tx.locktime,
      inputs,
      outputs,
      weight: tx.weight(),
      size: tx.byteLength(),
      vsize: tx.virtualSize()
    };
  }

  static parseJSON(txJson: any): ParsedTransaction {
    return {
      txid: txJson.txid || txJson.hash,
      version: txJson.version,
      locktime: txJson.locktime,
      inputs: txJson.vin?.map((input: any) => ({
        txid: input.txid,
        vout: input.vout,
        scriptSig: input.scriptSig?.hex,
        witness: input.txinwitness,
        sequence: input.sequence
      })) || [],
      outputs: txJson.vout?.map((output: any) => ({
        value: Math.round(output.value * 100000000),
        scriptPubKey: output.scriptPubKey?.hex || '',
        scriptPubKeyType: output.scriptPubKey?.type
      })) || [],
      weight: txJson.weight || 0,
      size: txJson.size || 0,
      vsize: txJson.vsize || 0
    };
  }

  private static detectScriptType(script: Buffer): string {
    if (script.length === 0) return 'empty';
    
    if (script[0] === 0x6a) return 'nulldata';
    
    if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
      return 'witness_v0_keyhash';
    }
    
    if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) {
      return 'witness_v0_scripthash';
    }
    
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
      return 'witness_v1_taproot';
    }
    
    if (script[0] === 0x76 && script[1] === 0xa9) {
      return 'pubkeyhash';
    }
    
    if (script[0] === 0xa9 && script[script.length - 1] === 0x87) {
      return 'scripthash';
    }
    
    return 'unknown';
  }

  static extractWitnessScript(witness: string[]): Buffer | null {
    if (!witness || witness.length === 0) return null;
    const lastItem = witness[witness.length - 1];
    return Buffer.from(lastItem, 'hex');
  }

  static extractOpReturnData(scriptPubKey: string): Buffer | null {
    const script = Buffer.from(scriptPubKey, 'hex');
    if (script.length === 0 || script[0] !== 0x6a) {
      return null;
    }

    let offset = 1;
    if (offset >= script.length) return Buffer.alloc(0);

    const pushOpcode = script[offset];

    if (pushOpcode >= 0x01 && pushOpcode <= 0x4b) {
      offset += 1;
    } else if (pushOpcode === 0x4c) {
      offset += 2;
    } else if (pushOpcode === 0x4d) {
      offset += 3;
    } else if (pushOpcode === 0x4e) {
      offset += 5;
    }

    return script.slice(offset);
  }
}

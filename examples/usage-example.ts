import { TransactionParser, FilterEngine, FilterConfig, ParsedTransaction, FilterResult } from '../src/index.js';

const exampleTxHex = '0200000001...';

const config: FilterConfig = {
  threshold: 80,
  enableP2WSHDetection: true,
  enableOpReturnDetection: true
};

const engine = new FilterEngine(config);

engine.addJSFilter((tx: ParsedTransaction): FilterResult => {
  const totalOutputValue = tx.outputs.reduce((sum, out) => sum + out.value, 0);
  const dustOutputs = tx.outputs.filter(out => out.value < 546);
  
  const score = dustOutputs.length > 5 ? 40 : 0;
  
  return {
    accept: dustOutputs.length <= 5,
    score,
    detections: [],
    message: dustOutputs.length > 5 
      ? `Suspicious: ${dustOutputs.length} dust outputs detected`
      : 'Acceptable output amounts'
  };
});

const tx = TransactionParser.parseHex(exampleTxHex);
const result = engine.evaluateTransaction(tx);

console.log(`Decision: ${result.accept ? 'ACCEPT' : 'REJECT'}`);
console.log(`Score: ${result.score}`);
console.log(`Message: ${result.message}`);

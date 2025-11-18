import { ParsedTransaction, FilterResult } from '../../src/types.js';

export function highWitnessFilter(tx: ParsedTransaction): FilterResult {
  let suspiciousInputs = 0;
  
  for (const input of tx.inputs) {
    if (input.witness && input.witness.length > 10) {
      suspiciousInputs++;
    }
  }
  
  const score = suspiciousInputs > 0 ? 60 : 0;
  
  return {
    accept: suspiciousInputs === 0,
    score,
    detections: [],
    message: suspiciousInputs > 0 
      ? `Detected ${suspiciousInputs} inputs with excessive witness data (>10 items)`
      : 'Normal witness data'
  };
}

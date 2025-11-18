import { ParsedTransaction, FilterResult, DetectionResult, FilterConfig } from './types.js';
import { P2WSHFakeMultisigDetector } from './detectors/p2wsh-detector.js';
import { ChainedOpReturnDetector } from './detectors/opreturn-detector.js';

export class FilterEngine {
  private config: FilterConfig;
  private jsFilters: ((tx: ParsedTransaction) => FilterResult)[] = [];

  constructor(config: FilterConfig) {
    this.config = config;
  }

  addJSFilter(filter: (tx: ParsedTransaction) => FilterResult): void {
    this.jsFilters.push(filter);
  }

  evaluateTransaction(tx: ParsedTransaction): FilterResult {
    const detections: DetectionResult[] = [];
    let totalScore = 0;

    if (this.config.enableP2WSHDetection) {
      const p2wshResult = P2WSHFakeMultisigDetector.detect(tx);
      if (p2wshResult.detected) {
        detections.push(p2wshResult);
        totalScore += p2wshResult.confidence;
      }
    }

    if (this.config.enableOpReturnDetection) {
      const opReturnResult = ChainedOpReturnDetector.detect(tx);
      if (opReturnResult.detected) {
        detections.push(opReturnResult);
        totalScore += opReturnResult.confidence;
      }
    }

    for (const filter of this.jsFilters) {
      const result = filter(tx);
      if (!result.accept) {
        detections.push({
          detected: true,
          confidence: result.score,
          reason: result.message
        });
        totalScore += result.score;
      }
    }

    const shouldReject = totalScore >= this.config.threshold;

    return {
      accept: !shouldReject,
      score: totalScore,
      detections,
      message: shouldReject 
        ? `Transaction rejected: spam score ${totalScore.toFixed(2)} exceeds threshold ${this.config.threshold}`
        : `Transaction accepted: spam score ${totalScore.toFixed(2)} below threshold ${this.config.threshold}`
    };
  }

  getStatistics(): any {
    return {
      config: this.config,
      customFilters: this.jsFilters.length
    };
  }
}

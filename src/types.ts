export interface TransactionInput {
  txid: string;
  vout: number;
  scriptSig?: string;
  witness?: string[];
  sequence: number;
}

export interface TransactionOutput {
  value: number;
  scriptPubKey: string;
  scriptPubKeyType?: string;
}

export interface ParsedTransaction {
  txid: string;
  version: number;
  locktime: number;
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  weight: number;
  size: number;
  vsize: number;
}

export interface DetectionResult {
  detected: boolean;
  confidence: number;
  reason: string;
  details?: any;
}

export interface FilterResult {
  accept: boolean;
  score: number;
  detections: DetectionResult[];
  message: string;
}

export interface FilterConfig {
  threshold: number;
  enableP2WSHDetection: boolean;
  enableOpReturnDetection: boolean;
  customFilters?: string[];
}

export type FilterFunction = (tx: ParsedTransaction) => FilterResult;

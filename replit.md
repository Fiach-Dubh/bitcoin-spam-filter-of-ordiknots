# Bitcoin Spam Filter

## Overview
A scriptable Bitcoin mempool policy filter designed to detect and block UTXO spam patterns, specifically targeting techniques documented in the taproot-wizards/ordiknots repository. The filter can identify and reject transactions using data embedding methods like P2WSH fake multisig and chained OP_RETURN patterns.

## Purpose
Counter Bitcoin UTXO spam by providing a flexible, scriptable filtering system that can:
- Detect P2WSH CHECKMULTISIG spam (fake pubkey patterns)
- Identify chained OP_RETURN data embedding
- Support custom filter rules in Lua and JavaScript/TypeScript
- Score transactions based on spam likelihood
- Integrate with Bitcoin node mempool policies

## Current State
Initial development - setting up TypeScript project with Bitcoin transaction parsing capabilities and scriptable filter engine.

## Project Architecture

### Core Components
- **Transaction Parser**: Analyzes Bitcoin transaction structure
- **Detection Engines**: Specialized detectors for different spam patterns
  - P2WSH fake multisig detector
  - Chained OP_RETURN detector
- **Filter Engine**: Scriptable interface supporting Lua and JS/TS
- **Scoring System**: Configurable threshold-based rejection
- **CLI Tool**: Command-line interface for testing filters

### Tech Stack
- TypeScript/Node.js for core engine
- bitcoinjs-lib for transaction parsing
- fengari-web for Lua scripting support
- Commander.js for CLI

## Recent Changes
- 2025-11-18: Project initialization with TypeScript setup

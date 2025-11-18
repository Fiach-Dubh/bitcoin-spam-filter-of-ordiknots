import { ParsedTransaction, FilterResult } from './types.js';

declare const fengari: any;

export class LuaFilterEngine {
  private lua: any;
  private luaFilters: string[] = [];

  constructor() {
    this.lua = null;
  }

  loadFilter(luaCode: string): boolean {
    if (!this.lua) {
      console.warn('Lua scripting is not currently functional in Node.js environment. Lua support requires browser-based fengari integration or alternative Lua VM. Use JavaScript/TypeScript filters for production deployments.');
      return false;
    }

    try {
      this.luaFilters.push(luaCode);
      return true;
    } catch (error) {
      console.error('Failed to load Lua filter:', error);
      return false;
    }
  }

  evaluateLuaFilter(tx: ParsedTransaction, luaCode: string): FilterResult {
    if (!this.lua) {
      return {
        accept: true,
        score: 0,
        detections: [],
        message: 'Lua scripting not available in Node.js environment. Use JavaScript/TypeScript filters.'
      };
    }

    const L = this.lua.luaL_newstate();
    this.lua.luaL_openlibs(L);

    const txJson = JSON.stringify(tx);
    const script = `
      ${luaCode}
      
      local tx = json.decode([=[${txJson}]=])
      local result = evaluate_transaction(tx)
      return json.encode(result)
    `;

    try {
      this.lua.luaL_dostring(L, script);
      const resultJson = this.lua.lua_tostring(L, -1);
      this.lua.lua_close(L);
      
      return JSON.parse(resultJson);
    } catch (error) {
      this.lua.lua_close(L);
      return {
        accept: true,
        score: 0,
        detections: [],
        message: `Lua filter error: ${error}`
      };
    }
  }
}

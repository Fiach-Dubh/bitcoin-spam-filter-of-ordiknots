-- P2WSH Fake Multisig Spam Detector for Bitcoin Knots
-- Detects suspicious CHECKMULTISIG patterns with fake pubkeys
-- Compatible with Bitcoin Knots PR #119 modular filter system

local function is_likely_fake_pubkey(pubkey)
    if #pubkey ~= 33 then
        return false
    end
    
    local prefix = string.byte(pubkey, 1)
    if prefix ~= 0x02 and prefix ~= 0x03 then
        return false
    end
    
    -- Count zeros and repeating patterns in the pubkey data (skip first byte)
    local zero_count = 0
    local consecutive_zeros = 0
    local max_consecutive_zeros = 0
    
    for i = 2, 33 do
        local byte = string.byte(pubkey, i)
        if byte == 0 then
            zero_count = zero_count + 1
            consecutive_zeros = consecutive_zeros + 1
            if consecutive_zeros > max_consecutive_zeros then
                max_consecutive_zeros = consecutive_zeros
            end
        else
            consecutive_zeros = 0
        end
    end
    
    -- Check for excessive zeros
    if max_consecutive_zeros > 4 or zero_count > 10 then
        return true
    end
    
    -- Check for repeating patterns (4 identical bytes in a row)
    local repeating_patterns = 0
    for i = 2, 30 do
        local b1 = string.byte(pubkey, i)
        local b2 = string.byte(pubkey, i + 1)
        local b3 = string.byte(pubkey, i + 2)
        local b4 = string.byte(pubkey, i + 3)
        
        if b1 == b2 and b1 == b3 and b1 == b4 then
            repeating_patterns = repeating_patterns + 1
        end
    end
    
    return repeating_patterns > 2
end

local function analyze_witness_script(script)
    local result = {
        is_suspicious = false,
        pubkey_count = 0,
        fake_pubkey_count = 0,
        has_checkmultisig = false,
        script_size = #script
    }
    
    if #script == 0 then
        return result
    end
    
    -- Check for CHECKMULTISIG opcode (0xae) at the end
    local last_byte = string.byte(script, #script)
    result.has_checkmultisig = (last_byte == 0xae)
    
    if not result.has_checkmultisig then
        return result
    end
    
    -- Extract pubkeys from the witness script
    local pubkeys = {}
    local i = 2  -- Start after the first opcode
    
    while i < #script - 1 do
        local opcode = string.byte(script, i)
        
        -- 0x21 = PUSH 33 bytes (compressed pubkey)
        if opcode == 0x21 then
            if i + 33 <= #script then
                local pubkey = string.sub(script, i + 1, i + 33)
                table.insert(pubkeys, pubkey)
                i = i + 34
            else
                break
            end
        -- OP_1 through OP_16 (0x51-0x60)
        elseif opcode >= 0x51 and opcode <= 0x60 then
            i = i + 1
        -- CHECKMULTISIG
        elseif opcode == 0xae then
            break
        else
            i = i + 1
        end
    end
    
    result.pubkey_count = #pubkeys
    
    -- Analyze each pubkey for fake patterns
    for _, pubkey in ipairs(pubkeys) do
        if #pubkey == 33 then
            local prefix = string.byte(pubkey, 1)
            if prefix == 0x02 or prefix == 0x03 then
                if is_likely_fake_pubkey(pubkey) then
                    result.fake_pubkey_count = result.fake_pubkey_count + 1
                end
            end
        end
    end
    
    -- Mark as suspicious if:
    -- 1. More than 3 pubkeys with >50% appearing fake
    if result.pubkey_count > 3 and result.fake_pubkey_count > result.pubkey_count * 0.5 then
        result.is_suspicious = true
    end
    
    -- 2. More than 10 pubkeys (excessive for legitimate multisig)
    if result.pubkey_count > 10 then
        result.is_suspicious = true
    end
    
    return result
end

-- Main filter function called by Bitcoin Knots
function validate(tx, ctx)
    local suspicious_count = 0
    local total_p2wsh = 0
    
    -- Get all transaction inputs
    local inputs = tx:get_inputs()
    
    for i, input in ipairs(inputs) do
        -- Check if input has witness data
        local witness = input:get_witness()
        
        if witness and #witness >= 3 then
            -- Extract witness script (last element in witness stack)
            local witness_script = witness[#witness]
            
            if witness_script and #witness_script > 0 then
                total_p2wsh = total_p2wsh + 1
                
                local analysis = analyze_witness_script(witness_script)
                
                if analysis.is_suspicious then
                    suspicious_count = suspicious_count + 1
                    
                    -- Log details for node operator
                    if ctx and ctx.log_warn then
                        ctx:log_warn(string.format(
                            "P2WSH spam detected: input %d has %d pubkeys (%d fake)",
                            i - 1,
                            analysis.pubkey_count,
                            analysis.fake_pubkey_count
                        ))
                    end
                end
            end
        end
    end
    
    -- No suspicious P2WSH patterns found
    if suspicious_count == 0 then
        return {
            accept = true,
            score = 0,
            reason = "No suspicious P2WSH patterns"
        }
    end
    
    -- Calculate spam score (0-100)
    local confidence = 0
    if total_p2wsh > 0 then
        confidence = (suspicious_count / total_p2wsh) * 100
    end
    
    -- Return rejection with score
    return {
        accept = false,
        score = math.floor(confidence),
        reason = string.format(
            "P2WSH spam: %d suspicious CHECKMULTISIG patterns with fake pubkeys",
            suspicious_count
        )
    }
end

-- Optional: Lifecycle hooks
local function on_load()
    return true
end

local function on_unload()
    return true
end

-- Export module functions
return {
    validate = validate,
    on_load = on_load,
    on_unload = on_unload
}

-- Composite Bitcoin UTXO Spam Filter for Bitcoin Knots
-- Combines P2WSH fake multisig and chained OP_RETURN detection
-- Compatible with Bitcoin Knots PR #119 modular filter system

-- Load individual detector modules
local p2wsh_detector = require("policy.p2wsh_spam")
local opreturn_detector = require("policy.opreturn_spam")

-- Configuration thresholds
local CONFIG = {
    -- Rejection threshold: transactions with score >= this value are rejected
    rejection_threshold = 50,
    
    -- Enable/disable individual detectors
    enable_p2wsh_detection = true,
    enable_opreturn_detection = true,
    
    -- Logging
    enable_logging = true
}

-- Main composite filter function
function validate(tx, ctx)
    local results = {}
    local max_score = 0
    local reasons = {}
    local any_rejected = false
    
    -- Run P2WSH fake multisig detector
    if CONFIG.enable_p2wsh_detection then
        local p2wsh_result = p2wsh_detector.validate(tx, ctx)
        table.insert(results, {
            name = "P2WSH",
            result = p2wsh_result
        })
        
        if p2wsh_result.score > max_score then
            max_score = p2wsh_result.score
        end
        
        if not p2wsh_result.accept then
            any_rejected = true
            table.insert(reasons, string.format("[P2WSH] %s", p2wsh_result.reason))
        end
    end
    
    -- Run chained OP_RETURN detector
    if CONFIG.enable_opreturn_detection then
        local opreturn_result = opreturn_detector.validate(tx, ctx)
        table.insert(results, {
            name = "OP_RETURN",
            result = opreturn_result
        })
        
        if opreturn_result.score > max_score then
            max_score = opreturn_result.score
        end
        
        if not opreturn_result.accept then
            any_rejected = true
            table.insert(reasons, string.format("[OP_RETURN] %s", opreturn_result.reason))
        end
    end
    
    -- Reject if ANY detector rejected, regardless of threshold
    -- Threshold is used for additional context/logging only
    if any_rejected then
        local combined_reason = table.concat(reasons, "; ")
        
        -- Log composite result
        if CONFIG.enable_logging and ctx and ctx.log_info then
            ctx:log_info(string.format(
                "Spam filter REJECT: score=%d threshold=%d detectors=%d",
                max_score,
                CONFIG.rejection_threshold,
                #reasons
            ))
        end
        
        return {
            accept = false,
            score = max_score,
            reason = string.format("Spam detected (score %d): %s", max_score, combined_reason)
        }
    end
    
    -- All detectors accepted - transaction passes
    return {
        accept = true,
        score = max_score,
        reason = "Transaction passed all spam filters"
    }
end

-- Lifecycle hooks
function on_load()
    if CONFIG.enable_logging then
        print("Bitcoin UTXO spam filter loaded")
        print("  - P2WSH fake multisig detection: " .. (CONFIG.enable_p2wsh_detection and "enabled" or "disabled"))
        print("  - Chained OP_RETURN detection: " .. (CONFIG.enable_opreturn_detection and "enabled" or "disabled"))
        print("  - Rejection threshold: " .. CONFIG.rejection_threshold)
    end
    return true
end

function on_unload()
    if CONFIG.enable_logging then
        print("Bitcoin UTXO spam filter unloaded")
    end
    return true
end

-- Export configuration for external modification
return {
    validate = validate,
    on_load = on_load,
    on_unload = on_unload,
    config = CONFIG
}

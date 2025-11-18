function evaluate_transaction(tx)
    local suspicious_count = 0
    local total_inputs = #tx.inputs
    
    for i, input in ipairs(tx.inputs) do
        if input.witness and #input.witness > 5 then
            suspicious_count = suspicious_count + 1
        end
    end
    
    local score = 0
    local accept = true
    local message = "No suspicious patterns detected"
    
    if suspicious_count > 0 then
        score = (suspicious_count / total_inputs) * 100
        if score > 50 then
            accept = false
            message = string.format("Detected %d/%d inputs with large witness data", suspicious_count, total_inputs)
        end
    end
    
    return {
        accept = accept,
        score = score,
        detections = {},
        message = message
    }
end

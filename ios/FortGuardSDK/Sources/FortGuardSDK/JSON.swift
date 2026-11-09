import Foundation

/// A JSON value. The SDK builds every payload from these so that the canonical text is exact.
public enum JSON: Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSON])
    case object([String: JSON])
}

extension JSON: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral,
    ExpressibleByBooleanLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(integerLiteral value: Int64) { self = .int(value) }
    public init(floatLiteral value: Double) { self = .double(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(arrayLiteral elements: JSON...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSON)...) {
        var dict: [String: JSON] = [:]
        for (k, v) in elements { dict[k] = v }
        self = .object(dict)
    }
}

/// Canonical JSON, byte for byte the same as the server's
/// `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` after the server parses it.
///
/// The SDK signs this text and sends this exact text as the request body.
/// Doubles are rounded to 3 decimals, printed without an exponent, and whole values print without ".0".
public enum CanonicalJSON {

    public static func encode(_ value: JSON) -> String {
        var out = ""
        write(&out, value)
        return out
    }

    private static func write(_ out: inout String, _ value: JSON) {
        switch value {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .int(let i): out += String(i)
        case .double(let d): out += number(d)
        case .string(let s): writeString(&out, s)
        case .array(let items):
            out += "["
            for (i, item) in items.enumerated() {
                if i > 0 { out += "," }
                write(&out, item)
            }
            out += "]"
        case .object(let dict):
            out += "{"
            let keys = dict.keys.sorted { $0.unicodeScalars.lexicographicallyPrecedes($1.unicodeScalars) }
            for (i, key) in keys.enumerated() {
                if i > 0 { out += "," }
                writeString(&out, key)
                out += ":"
                write(&out, dict[key]!)
            }
            out += "}"
        }
    }

    /// Round to 3 decimals; no exponent; whole values without ".0"; never "-0".
    /// Non-finite or huge values print as 0 (the SDK clamps values before they get here).
    public static func number(_ d: Double) -> String {
        guard d.isFinite, abs(d) < 9.0e15 else { return "0" }
        let m = Int64((d * 1000.0).rounded())
        if m == 0 { return "0" }
        let negative = m < 0
        let a = negative ? -m : m
        var out = negative ? "-" : ""
        out += String(a / 1000)
        let frac = a % 1000
        if frac != 0 {
            var f = String(frac)
            while f.count < 3 { f = "0" + f }
            while f.hasSuffix("0") { f.removeLast() }
            out += "." + f
        }
        return out
    }

    private static func writeString(_ out: inout String, _ s: String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }
}

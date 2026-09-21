//! Decode a protobuf body without knowing its schema.
//!
//! Unknown command ids are the normal state right after a game update, and with a
//! schema-only renderer such a packet shows up as nothing at all. Walking the wire
//! format directly instead gives `{fieldNumber: value}` — enough to tell two
//! packets apart, to spot which field grew, and to decide whether the schema is
//! stale — for any body, known or not.
//!
//! One ambiguity is inherent and not resolved here: a length-delimited field that
//! happens to parse cleanly as a message is rendered as a message, so a two-byte
//! string can appear as `{"13": 105}`. Longer text almost always trips the
//! framing and falls back to text, and a UI that wants both readings should ask
//! for the raw bytes rather than guess.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::{Map, Value};

/// Wire types this can represent. Groups (3/4) are deprecated and treated as
/// unparseable, which surfaces them as leftover bytes rather than hiding them.
const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_FIXED32: u8 = 5;

/// The field tree of `bytes`, keyed by field number as a string.
///
/// A field seen more than once becomes an array, matching how protobuf treats
/// repeated fields on the wire. Bytes that cannot be read as a message — or that
/// are empty — are reported as `"leftover"` so a caller can tell a short read from
/// a complete one.
pub fn field_tree(bytes: &[u8]) -> Value {
    let (fields, leftover) = walk(bytes);
    let mut obj = fields;
    if leftover > 0 {
        obj.insert("leftover".to_owned(), Value::from(leftover));
    }
    Value::Object(obj)
}

/// Parse `bytes` as a message, reporting the fields and the unread tail.
///
/// The tail is counted from the start of the first field that could not be read,
/// so a truncated length prefix does not look like a clean stop.
///
/// Returns `None` when the bytes are not a message at all, which is what lets the
/// caller decide between a nested object and a string or blob.
fn walk(bytes: &[u8]) -> (Map<String, Value>, usize) {
    let mut fields: Map<String, Value> = Map::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let start_of_field = cursor;
        let unreadable = |from: usize| bytes.len() - from;

        let (key, used) = match read_varint(&bytes[cursor..]) {
            Some(pair) => pair,
            None => return (fields, unreadable(start_of_field)),
        };
        cursor += used;
        let number = (key >> 3) as u32;
        let wire_type = (key & 0b111) as u8;
        if number == 0 {
            return (fields, unreadable(start_of_field));
        }

        let value = match wire_type {
            WIRE_VARINT => match read_varint(&bytes[cursor..]) {
                Some((v, used)) => {
                    cursor += used;
                    Value::from(v)
                }
                None => return (fields, unreadable(start_of_field)),
            },
            WIRE_FIXED64 => match fixed(&bytes[cursor..], 8) {
                Some(parts) => {
                    cursor += 8;
                    Value::from(u64::from_le_bytes(parts.try_into().unwrap()))
                }
                None => return (fields, unreadable(start_of_field)),
            },
            WIRE_FIXED32 => match fixed(&bytes[cursor..], 4) {
                Some(parts) => {
                    cursor += 4;
                    Value::from(u32::from_le_bytes(parts.try_into().unwrap()))
                }
                None => return (fields, unreadable(start_of_field)),
            },
            WIRE_LENGTH_DELIMITED => {
                let Some((len, used)) = read_varint(&bytes[cursor..]) else {
                    return (fields, unreadable(start_of_field));
                };
                cursor += used;
                let Some(payload) = bytes.get(cursor..cursor + len as usize) else {
                    return (fields, unreadable(start_of_field));
                };
                cursor += payload.len();
                scalar(payload)
            }
            _ => return (fields, unreadable(start_of_field)),
        };

        let key = number.to_string();
        match fields.get_mut(&key) {
            Some(Value::Array(existing)) => existing.push(value),
            Some(previous) => {
                let repeated = vec![previous.clone(), value];
                *previous = Value::Array(repeated);
            }
            None => {
                fields.insert(key, value);
            }
        }
    }

    (fields, 0)
}

/// Render one length-delimited value: a nested message when it is one, else text,
/// else base64.
fn scalar(payload: &[u8]) -> Value {
    if !payload.is_empty() {
        let (nested, leftover) = walk(payload);
        if leftover == 0 && !nested.is_empty() {
            return Value::Object(nested);
        }
    }
    match std::str::from_utf8(payload) {
        Ok(text) if !text.is_empty() => Value::String(text.to_owned()),
        _ => Value::String(BASE64_STANDARD.encode(payload)),
    }
}

fn fixed<'a>(bytes: &'a [u8], len: usize) -> Option<&'a [u8]> {
    bytes.get(..len)
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (shift, byte) in bytes.iter().take(10).enumerate() {
        value |= ((byte & 0b0111_1111) as u64) << (7 * shift);
        if byte & 0b1000_0000 == 0 {
            return Some((value, shift + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_varint_field_is_addressed_by_number() {
        // field 15, varint 300
        assert_eq!(field_tree(&[0x78, 0xac, 0x02]), serde_json::json!({ "15": 300 }));
    }

    #[test]
    fn a_repeated_field_becomes_an_array() {
        // field 1 varint 7, then field 1 varint 9
        assert_eq!(
            field_tree(&[0x08, 0x07, 0x08, 0x09]),
            serde_json::json!({ "1": [7, 9] })
        );
    }

    #[test]
    fn a_nested_message_is_walked_one_level_deep() {
        // field 2, length 4, containing field 1 varint 5 and field 2 varint 6
        let tree = field_tree(&[0x12, 0x04, 0x08, 0x05, 0x10, 0x06]);
        assert_eq!(tree, serde_json::json!({ "2": { "1": 5, "2": 6 } }));
    }

    #[test]
    fn text_stays_text_and_binary_becomes_base64() {
        // field 2, length-delimited "hello world", which cannot be read as a
        // message (0x6c is field 13, wire type 4, a deprecated group)
        let text = field_tree(&[0x12, 0x0b, b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd']);
        assert_eq!(text, serde_json::json!({ "2": "hello world" }));

        // a byte sequence that is neither a message nor valid utf-8
        let blob = field_tree(&[0x12, 0x02, 0xff, 0xfe]);
        assert_eq!(blob, serde_json::json!({ "2": BASE64_STANDARD.encode([0xff, 0xfe]) }));
    }

    #[test]
    fn an_unreadable_tail_is_reported_not_swallowed() {
        // field 1 varint 7, then a length-delimited field claiming 64 bytes that
        // the buffer does not have: the two bytes of that failed field are the
        // leftover
        let tree = field_tree(&[0x08, 0x07, 0x12, 0x40]);
        assert_eq!(tree["1"], serde_json::json!(7));
        assert_eq!(tree["leftover"], serde_json::json!(2));
    }

    #[test]
    fn a_zero_field_number_stops_the_walk() {
        // key 0 is never a legal field, so everything from there is leftover
        assert_eq!(
            field_tree(&[0x00, 0x01]).get("leftover"),
            Some(&serde_json::json!(2))
        );
    }
}

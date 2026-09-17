use std::fs;

/// Merge every Starlight proto (minus imports, which become redundant once all
/// types live in one file) into a single `protos.proto`, strip `[mask]` field
/// options, and exclude the Base `cmd_gcg_common.proto` (superseded by V70's
/// `cmd_gcg.proto`) to avoid duplicate type definitions.
///
/// A single source file makes `protobuf_codegen` emit its content in one
/// `protos` module, so existing `crate::gen::protos::*` references keep working.
fn main() {
    let proto_dir = "protos_experiment";
    let out_proto = "protos/protos.proto";
    // - cmd_gcg_common.proto: superseded by V70's cmd_gcg.proto (dup types)
    // - extra.proto: server-infrastructure messages (PlayerPacketNotify etc.)
    //   and its own PacketHead; the local PacketHead used by the parser is
    //   appended below instead, avoiding a definition clash.
    let exclude = ["cmd_gcg_common.proto", "extra.proto"];

    let mut inputs: Vec<String> = fs::read_dir(proto_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "proto").unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            !exclude.contains(&n.as_str())
        })
        .map(|p| p.display().to_string())
        .collect();
    inputs.sort();

    let syntax_seen: &mut bool = &mut false;
    let mut merged = String::new();
    for f in &inputs {
        let raw = fs::read_to_string(f).unwrap();
        for line in raw.lines() {
            let t = line.trim_start();
            // Inline imports (now redundant) and per-file header repeats.
            if t.starts_with("import ")
                || t.starts_with("option ")
                || t.starts_with("package ")
            {
                continue;
            }
            // Keep exactly one `syntax` declaration at the top of the merged
            // file; drop any others.
            if t.starts_with("syntax ") {
                if *syntax_seen {
                    continue;
                }
                *syntax_seen = true;
            }
            merged.push_str(line.trim_end());
            merged.push('\n');
        }
        merged.push('\n');
    }
    // Strip mask options from merged text.
    let cleaned = strip_mask(&merged);
    // `extend google.protobuf.FieldOptions { ... }` only defined the now-stripped
    // `mask` option and pulls in google/protobuf/descriptor.proto, which is not
    // vendored. Drop the block so the merged file type-checks standalone.
    let cleaned = drop_extend_field_options(&cleaned);
    // The upstream Starlight dump strips three client-side `Reliquary` fields
    // that `irminsul`'s player-data exporter needs. Their field numbers 6..8
    // are unused by upstream, so re-inject them safely.
    let cleaned = restore_reliquary_fields(&cleaned);

    fs::create_dir_all("protos").unwrap();
    // Append the parser's local compatibility types (not present in upstream
    // Starlight protos): a generic empty container for field-number-agnostic
    // probing, and the client PacketHead layout the command parser expects.
    let compat = "\nmessage Unk {\n}\n\nmessage PacketHead {\n  uint32 packet_id = 1;\n  uint32 rpc_id = 2;\n  uint32 client_sequence_id = 3;\n  uint32 enet_channel_id = 4;\n  uint32 enet_is_reliable = 5;\n  uint64 sent_ms = 6;\n  uint32 user_id = 11;\n  uint32 user_ip = 12;\n  uint32 user_session_id = 13;\n  uint64 recv_time_ms = 21;\n  uint32 rpc_begin_time_ms = 22;\n  map<uint32, uint32> ext_map = 23;\n  uint32 sender_app_id = 24;\n  uint32 source_service = 31;\n  uint32 target_service = 32;\n  map<uint32, uint32> service_app_id_map = 33;\n  bool is_set_game_thread = 34;\n  uint32 game_thread_index = 35;\n}\n";
    let final_proto = format!("{}{}", cleaned, compat);
    fs::write(out_proto, &final_proto).unwrap();

    // Generate a cmd_id -> message-name mapping from `// CmdId: N` comments that
    // precede each command body message. Used at runtime to look up the right
    // MessageDescriptor for reflection-based JSON parsing.
    let map = generate_cmd_id_map(&final_proto);
    let map_path = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("cmd_id_map.rs");
    fs::write(&map_path, map).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("protos")
        .input(out_proto)
        .run_from_script();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=protos_experiment/");
    println!("cargo:rerun-if-changed=protos/protos.proto");
}

fn strip_mask(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.split_inclusive('\n') {
        let had_nl = line.ends_with('\n');
        let content = if had_nl { &line[..line.len() - 1] } else { line };
        let mut work = content.to_string();
        loop {
            if let Some(start) = work.find("[mask =") {
                if let Some(rel) = work[start..].find(']') {
                    let end = start + rel;
                    let mut tail = work[end + 1..].to_string();
                    while tail.starts_with(' ') {
                        tail.remove(0);
                    }
                    work = format!("{}{}", &work[..start], tail);
                    continue;
                }
            }
            break;
        }
        out.push_str(&work);
        if had_nl {
            out.push('\n');
        }
    }
    out
}

/// Remove `extend google.protobuf.FieldOptions { ... }` blocks, whose custom
/// `mask` option was already stripped, so the merged proto no longer depends on
/// the not-vendored `google/protobuf/descriptor.proto`.
fn drop_extend_field_options(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut depth = 0i32;
    let mut skipping = false;
    for line in src.split_inclusive('\n') {
        let had_nl = line.ends_with('\n');
        let content = if had_nl { &line[..line.len() - 1] } else { line };
        let t = content.trim_start();
        if !skipping && t.starts_with("extend google.protobuf.FieldOptions") {
            skipping = true;
            depth = 0;
        }
        if skipping {
            // Count braces to find the matching `}`.
            for ch in content.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 && content.contains('}') {
                skipping = false;
            }
            continue;
        }
        out.push_str(content);
        if had_nl {
            out.push('\n');
        }
    }
    out
}

/// Re-inject the client-side `Reliquary` fields that upstream's dump omitted.
/// The exporter in `irminsul` reads `starred`/`elixer_choices`/
/// `unactivated_prop_id_list`; upstream `Reliquary` only carries the 5 base
/// fields (numbers 1..5), so numbers 6..8 are free to reuse.
fn restore_reliquary_fields(src: &str) -> String {
    let marker = "message Reliquary {";
    let has_extra = src.contains("unactivated_prop_id_list");
    if has_extra {
        return src.to_string();
    }
    // Inject the extra fields right before the closing brace of the first
    // top-level `message Reliquary { ... }` block.
    let Some(pos) = src.find(marker) else {
        return src.to_string();
    };
    let after = &src[pos + marker.len()..];
    let Some(close_offset) = after.find("\n}") else {
        return src.to_string();
    };
    let insert_at = pos + marker.len() + close_offset + 1; // before "}"
    let extra = "\n  bool starred = 6;\n  repeated uint32 elixer_choices = 7;\n  repeated uint32 unactivated_prop_id_list = 8;\n";
    let mut out = String::with_capacity(src.len() + extra.len());
    out.push_str(&src[..insert_at]);
    out.push_str(extra);
    // Drop the newline marker we consumed.
    out.push_str(&src[insert_at..]);
    out
}

/// Scan merged proto text for `// CmdId: N` comments and associate each with
/// the message declared on the immediately following `message X {` line. Emits
/// a Rust static table `CMD_ID_MESSAGES: &[(u16, &str)]`.
fn generate_cmd_id_map(proto: &str) -> String {
    let lines: Vec<&str> = proto.lines().collect();
    let mut entries: Vec<(u16, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("// CmdId:") {
            if let Ok(id) = rest.trim().parse::<u16>() {
                // The command body message follows the comment (only blank/comment
                // lines may sit between them).
                for j in (i + 1)..lines.len() {
                    let tj = lines[j].trim_start();
                    if let Some(name) = tj.strip_prefix("message ").and_then(|s| {
                        let n = s.trim_start();
                        let name = n.split_whitespace().next().unwrap_or("");
                        if name.is_empty() { None } else { Some(name) }
                    }) {
                        entries.push((id, name.to_string()));
                        break;
                    }
                    if tj.starts_with("// CmdId:") || tj.is_empty() {
                        continue;
                    }
                    // Unrelated declaration (e.g. a field, enum, nested) — stop.
                    if !tj.starts_with("//") {
                        break;
                    }
                }
            }
        }
    }
    // De-duplicate by cmd_id (there can be multiple `// CmdId` for the same value).
    entries.sort_by_key(|(id, _)| *id);
    entries.dedup_by_key(|(id, _)| *id);
    let mut out = String::from("// @generated\npub static CMD_ID_MESSAGES: &[(u16, &str)] = &[\n");
    for (id, name) in entries {
        // Rust string escaping for safe embedding.
        let name = name.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!("    ({}, \"{}\"),\n", id, name));
    }
    out.push_str("];\n");
    out
}
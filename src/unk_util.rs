use std::collections::HashMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::r#gen::protos::AvatarInfo;
use crate::r#gen::protos::Item;
use crate::r#gen::protos::Unk;

pub fn matches_get_player_token_rsp(
    data: Vec<u8>,
    rsa_keys: Vec<RsaPrivateKey>,
) -> Option<Vec<u64>> {
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut to_ret: Vec<u64> = vec![];
            let unknown_fields = d_msg.unknown_fields();
            for (field_number, field_data) in unknown_fields.iter() {
                tracing::debug!("field: {}: {:?}", field_number, field_data);
                let possible_encrypted = match field_data {
                    LengthDelimited(encrypted_bytes) => {
                        let encrypted = BASE64_STANDARD.decode(encrypted_bytes);
                        match encrypted {
                            Ok(encrypted) => Some(encrypted),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let possible_seeds: Vec<u64> = match possible_encrypted {
                    Some(possible_encrypted) => rsa_keys
                        .iter()
                        .filter_map(|key| key.decrypt(Pkcs1v15Encrypt, &possible_encrypted).ok())
                        .collect::<Vec<Vec<u8>>>()
                        .iter()
                        .filter(|&seed| seed.len() == 8)
                        .map(|seed| u64::from_be_bytes(seed.as_slice().try_into().unwrap()))
                        .collect(),
                    _ => vec![],
                };
                to_ret.extend(possible_seeds)
            }
            if to_ret.len() != 0 {
                Some(to_ret)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[derive(Clone, Default)]
pub struct Achievement {
    pub id: u32,
    pub status: u32,
    pub finish_timestamp: Option<u32>,
}

pub fn matches_achievement_all_data_notify(data: Vec<u8>) -> Option<Vec<Achievement>> {
    if data.len() < 1000 {
        return None;
    }
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut achievement_list: Vec<HashMap<u32, u64>> = vec![];
            let mut list_tag: Option<u32> = None;
            let unknown_fields = d_msg.unknown_fields();
            // let tags = unknown_fields.iter().map(|(tag, _)| tag).collect::<HashSet<u32>>();
            // if tags.len() != 2 { return None }
            for (field_number, field_data) in unknown_fields.iter() {
                match field_data {
                    LengthDelimited(bytes) => {
                        let d_msg_inside = Unk::parse_from_bytes(bytes);
                        let unknown_fields_inside;
                        match d_msg_inside {
                            Ok(d_msg_inside) => {
                                unknown_fields_inside = d_msg_inside.unknown_fields().clone()
                            }
                            _ => continue,
                        }
                        let mut achievement_map: HashMap<u32, u64> = HashMap::new();
                        for (field_number_inside, field_data_inside) in unknown_fields_inside.iter()
                        {
                            match field_data_inside {
                                Varint(value) => {
                                    let _ = achievement_map.insert(field_number_inside, value);
                                }
                                _ => return None, // because proto has only repeated Achievement and repeated uint32, this isn't the right packet.
                            }
                        }
                        achievement_list.push(achievement_map);
                        match list_tag {
                            Some(x) => {
                                if field_number != x {
                                    return None;
                                } // if we found several possible tags for the list. Not possible.
                            }
                            None => list_tag = Some(field_number),
                        }
                    }
                    _ => (),
                }
            }
            if achievement_list.len() == 0 {
                return None;
            }

            // Now, try to find which field corresponds to the right places
            let mut tag_finish_timestamp = None;
            let mut tag_id = None;
            let mut possible_tag_status: Vec<u32> =
                achievement_list[0].clone().into_keys().collect();
            for achievement_map in &achievement_list {
                for (&tag, &value) in achievement_map.iter() {
                    if value > 1420066800 {
                        // Wed Dec 31 2014 23:00:00 GMT+0000
                        tag_finish_timestamp = match tag_finish_timestamp {
                            Some(t) => {
                                if t != tag {
                                    return None;
                                } else {
                                    tag_finish_timestamp
                                }
                            }
                            _ => Some(tag),
                        }
                    }
                    if value == 80014 {
                        // Onward and Upward: Ascend a character to Phase 2 for the first time
                        tag_id = Some(tag)
                    }
                    if possible_tag_status.contains(&tag) {
                        if value > 3 {
                            possible_tag_status.retain(|&x| x != tag)
                        }
                    }
                }
            }

            if tag_finish_timestamp == None || tag_id == None || possible_tag_status.len() == 0 {
                return None;
            }

            // Finally, collect the Achievements
            let tag_status = possible_tag_status[0];
            let mut achievements: Vec<Achievement> = vec![];
            for achievement_map in &achievement_list {
                let mut achievement = Achievement {
                    ..Default::default()
                };
                for (&tag, &value) in achievement_map.iter() {
                    if tag_finish_timestamp.unwrap() == tag {
                        achievement.finish_timestamp = Some(value as u32);
                    }
                    if tag_id.unwrap() == tag {
                        achievement.id = value as u32;
                    }
                    if tag_status == tag {
                        achievement.status = value as u32;
                    }
                }
                achievements.push(achievement)
            }
            assert!(achievements.len() > 0);
            Some(achievements)
        }
        _ => None,
    }
}

// --- Heuristic thresholds for field-number-agnostic packet matching ---
const MIN_ITEM_ENTRIES: usize = 10;
const MIN_GEAR_COUNT: usize = 5;
const MIN_AVATAR_ENTRIES: usize = 4;
const MIN_AVATARS_WITH_PROPS: usize = 2;
const MIN_AVATARS_WITH_SKILLS: usize = 2;
const MIN_AVATARS_WITH_EQUIP: usize = 2;

/// Extract the repeated field with the most entries that parse as `T` and pass
/// the `filter`. Returns `(best_field_number, parsed_entries)`.
///
/// This is the core of field-number-agnostic packet matching: parse the outer
/// message as `Unk` (generic protobuf), group all length-delimited values by
/// field number, try parsing each group as `T`, and pick the field with the
/// most valid results.
fn find_best_field<T: Message>(
    proto_data: &[u8],
    min_entries: usize,
    filter: impl Fn(&T) -> bool,
) -> Option<(u32, Vec<T>)> {
    let unk = Unk::parse_from_bytes(proto_data).ok()?;
    let mut field_map: HashMap<u32, Vec<&[u8]>> = HashMap::new();
    for (field_num, value) in unk.unknown_fields().iter() {
        if let LengthDelimited(bytes) = value {
            field_map.entry(field_num).or_default().push(bytes);
        }
    }
    let mut best: Option<(u32, Vec<T>)> = None;
    for (field_num, blobs) in &field_map {
        if blobs.len() < min_entries {
            continue;
        }
        let parsed: Vec<T> = blobs
            .iter()
            .filter_map(|b| T::parse_from_bytes(b).ok())
            .filter(|v| filter(v))
            .collect();
        if parsed.len() >= min_entries
            && best.as_ref().map_or(true, |(_, b)| parsed.len() > b.len())
        {
            best = Some((*field_num, parsed));
        }
    }
    best
}

/// Field-number-agnostic item packet detection.
///
/// Survives both command ID rotation and outer field number changes.
pub fn matches_items_all_data_notify(data: &[u8]) -> Option<Vec<Item>> {
    let (_field, items) = find_best_field::<Item>(data, MIN_ITEM_ENTRIES, |item| {
        item.item_id != 0 && item.guid != 0
    })?;

    let gear_count = items
        .iter()
        .filter(|i| i.has_equip() && (i.equip().has_weapon() || i.equip().has_reliquary()))
        .count();

    if gear_count < MIN_GEAR_COUNT {
        tracing::debug!(
            "Item packet candidate rejected ({} items, {} weapons/artifacts)",
            items.len(),
            gear_count,
        );
        return None;
    }

    tracing::debug!(
        "Item packet matched ({} items)",
        items.len(),
    );
    Some(items)
}

/// Field-number-agnostic avatar packet detection.
///
/// Requires ≥4 avatars with non-empty `prop_map`, `skill_level_map`, and
/// `equip_guid_list`. This filters out incremental packets (team changes,
/// trial avatars) which lack skill/equip data.
pub fn matches_avatars_all_data_notify(data: &[u8]) -> Option<Vec<AvatarInfo>> {
    let (_field, avatars) = find_best_field::<AvatarInfo>(data, MIN_AVATAR_ENTRIES, |a| {
        a.avatar_id != 0 && a.guid != 0
    })?;

    let has_props = avatars.iter().filter(|a| !a.prop_map.is_empty()).count();
    if has_props < MIN_AVATARS_WITH_PROPS {
        tracing::debug!(
            "Avatar packet candidate rejected ({} avatars, only {} with props)",
            avatars.len(),
            has_props,
        );
        return None;
    }

    let has_skills = avatars.iter().filter(|a| !a.skill_level_map.is_empty()).count();
    if has_skills < MIN_AVATARS_WITH_SKILLS {
        tracing::debug!(
            "Avatar packet candidate rejected ({} avatars, only {} with skills)",
            avatars.len(),
            has_skills,
        );
        return None;
    }

    let has_equip = avatars.iter().filter(|a| !a.equip_guid_list.is_empty()).count();
    if has_equip < MIN_AVATARS_WITH_EQUIP {
        tracing::debug!(
            "Avatar packet candidate rejected ({} avatars, only {} with equip)",
            avatars.len(),
            has_equip,
        );
        return None;
    }

    tracing::debug!(
        "Avatar packet matched ({} avatars)",
        avatars.len(),
    );
    Some(avatars)
}

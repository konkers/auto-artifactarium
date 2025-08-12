use std::collections::HashMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::gen::protos::Unk;
use crate::gen::protos::PacketWithItems;
use crate::gen::protos::item;
use crate::gen::protos::equip;

pub fn matches_get_player_token_rsp(data: Vec<u8>, rsa_keys: Vec<RsaPrivateKey>) -> Option<Vec<u64>> {
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut to_ret: Vec<u64> = vec![];
            let unknown_fields = d_msg.unknown_fields();
            for (field_number, field_data) in unknown_fields.iter() {
                println!("field: {}: {:?}", field_number, field_data);
                let possible_encrypted = match field_data {
                    LengthDelimited(encrypted_bytes) => {
                        let encrypted = BASE64_STANDARD.decode(encrypted_bytes);
                        match encrypted {
                            Ok(encrypted) => {
                                Some(encrypted)
                            }
                            _ => None
                        }
                    }
                    _ => None
                };
                let possible_seeds: Vec<u64> = match possible_encrypted {
                    Some(possible_encrypted) => {
                        rsa_keys.iter()
                            .filter_map(|key| key.decrypt(Pkcs1v15Encrypt, &possible_encrypted).ok())
                            .collect::<Vec<Vec<u8>>>()
                            .iter()
                            .filter(|&seed| seed.len() == 8)
                            .map(|seed| u64::from_be_bytes(seed.as_slice().try_into().unwrap()))
                            .collect()
                    }
                    _ => vec![]
                };
                to_ret.extend(possible_seeds)
            }
            if to_ret.len() != 0 {
                Some(to_ret)
            }
            else { None }
        }
        _ => None
    }
}

#[derive(Default)]
pub struct Achievement {
    pub id: u32,
    pub status: u32,
    pub finish_timestamp: Option<u32>
}

pub fn matches_achievement_all_data_notify(data: Vec<u8>) -> Option<Vec<Achievement>> {
    if data.len() < 1000 {
        return None
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
                            _ => continue
                        }
                        let mut achievement_map: HashMap<u32, u64> = HashMap::new();
                        for(field_number_inside, field_data_inside) in unknown_fields_inside.iter() {
                            match field_data_inside {
                                Varint(value) => {
                                    let _ = achievement_map.insert(field_number_inside, value);
                                },
                                _ => { return None }  // because proto has only repeated Achievement and repeated uint32, this isn't the right packet.
                            }
                        }
                        achievement_list.push(achievement_map);
                        match list_tag {
                            Some(x) => {
                                if field_number != x { return None }  // if we found several possible tags for the list. Not possible.
                            }
                            None => list_tag = Some(field_number)
                        }
                    }
                    _ => ()
                }
            }
            if achievement_list.len() == 0 { return None }

            // Now, try to find which field corresponds to the right places
            let mut tag_finish_timestamp = None;
            let mut tag_id = None;
            let mut possible_tag_status: Vec<u32> = achievement_list[0].clone().into_keys().collect();
            for achievement_map in &achievement_list {
                for (&tag, &value) in achievement_map.iter() {
                    if value > 1420066800 {  // Wed Dec 31 2014 23:00:00 GMT+0000
                        tag_finish_timestamp = match tag_finish_timestamp {
                            Some(t) => {
                                if t != tag { return None }
                                else { tag_finish_timestamp }
                            }
                            _ => Some(tag)
                        }
                    }
                    if value == 80014 {  // Onward and Upward: Ascend a character to Phase 2 for the first time
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
                return None
            }

            // Finally, collect the Achievements
            let tag_status = possible_tag_status[0];
            let mut achievements: Vec<Achievement> = vec![];
            for achievement_map in &achievement_list {
                let mut achievement = Achievement {..Default::default()};
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
        _ => None
    }
}

#[derive(Default)]
pub struct Artifact {
    pub id: u32,
    pub level: u32,
    pub exp: u32,
    pub promote_level: u32,
    pub main_prop_id: u32,
    pub append_prop_id_list: Vec<u32>,
    pub is_locked: bool,
}

pub fn matches_artifact_all_data_notify(data: Vec<u8>) -> Option<Vec<Artifact>> {
    let packet = PacketWithItems::parse_from_bytes(&data).ok()?;

    let artifacts: Vec<Artifact> = packet.items.iter()
        .filter_map(|item| {
            match &item.detail {
                Some(item::Detail::Equip(equip)) => {
                    match &equip.detail {
                        Some(equip::Detail::Reliquary(r)) => Some(Artifact {
                            id: item.item_id,
                            level: r.level,
                            exp: r.exp,
                            promote_level: r.promote_level,
                            main_prop_id: r.main_prop_id,
                            append_prop_id_list: r.append_prop_id_list.to_vec(),
                            is_locked: equip.is_locked,
                        }),
                        _ => None,
                    }
                },
                _ => None,
            }
        })
        .collect();

    if artifacts.is_empty() {
        None
    } else {
        Some(artifacts)
    }
}
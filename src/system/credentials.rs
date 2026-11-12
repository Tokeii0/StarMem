use std::collections::BTreeSet;

use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes256};
use anyhow::{Context, Result, ensure};
use des::Des;
use md5::{Digest, Md5};
use serde::Serialize;
use sha2::Sha256;

use super::registry::{
    RegistryEvidence, recover_loaded_target_hive_validated, recover_target_hive,
};
use crate::registry::RegistryHive;
use crate::session::AnalysisSession;

const BOOTKEY_PERMUTATION: [usize; 16] = [
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7,
];
const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const NT_PASSWORD: &[u8] = b"NTPASSWORD\0";
const LM_PASSWORD: &[u8] = b"LMPASSWORD\0";
const EMPTY_LM: [u8; 16] = [
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
];
const EMPTY_NT: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HashdumpRecord {
    pub username: String,
    pub rid: u32,
    pub lm_hash: String,
    pub nt_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CachedumpRecord {
    pub cache_name: String,
    pub username: String,
    pub domain: String,
    pub domain_name: String,
    pub hash: String,
}

#[derive(Debug, Serialize)]
pub struct LsaSecretRecord {
    pub name: String,
    pub secret_hex: String,
    pub utf16: Option<String>,
}

pub fn hashdump(
    session: &AnalysisSession,
    limit: usize,
) -> Result<RegistryEvidence<HashdumpRecord>> {
    ensure!(limit > 0, "hashdump result limit must be greater than zero");
    let processes = session.processes(65_536)?;
    let mut system = recover_loaded_target_hive_validated(
        session,
        &processes,
        "\\REGISTRY\\MACHINE\\SYSTEM",
        100,
        |hive| bootkey(hive).map(|_| ()),
    );
    let mut warnings = Vec::new();
    warnings.append(&mut system.warnings);
    let Some(system_hive) = system.hive.take() else {
        return Ok(RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings,
        });
    };
    let selected_bootkey = match bootkey(&system_hive) {
        Ok(bootkey) => bootkey,
        Err(error) => {
            warnings.push(format!("活动 SYSTEM Hive 未能重建 BootKey：{error:#}"));
            return Ok(RegistryEvidence {
                records: Vec::new(),
                available: false,
                complete: false,
                warnings,
            });
        }
    };
    let mut sam = recover_loaded_target_hive_validated(
        session,
        &processes,
        "\\REGISTRY\\MACHINE\\SAM",
        100,
        |hive| validate_sam_hashdump_hive(hive, &selected_bootkey),
    );
    warnings.append(&mut sam.warnings);
    let Some(sam_hive) = sam.hive.take() else {
        return Ok(RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings,
        });
    };
    let mut evidence = match hashdump_from_hives(&system_hive, &sam_hive, limit) {
        Ok(evidence) => evidence,
        Err(error) => {
            warnings.push(format!(
                "活动 SYSTEM/SAM Hive 已恢复，但 Hashdump 所需单元仍不完整：{error:#}"
            ));
            return Ok(RegistryEvidence {
                records: Vec::new(),
                available: false,
                complete: false,
                warnings,
            });
        }
    };
    evidence.complete &= system.complete && sam.complete;
    if !system.complete || !sam.complete {
        warnings.push(
            "Hashdump 使用了不完整或 backing 回填的活动 Hive；记录已保留用于取证复核，但不能视为完整快照"
                .to_owned(),
        );
    }
    warnings.append(&mut evidence.warnings);
    evidence.warnings = warnings;
    Ok(evidence)
}

/// Decrypt local account password hashes from already parsed SYSTEM and SAM hives.
///
/// This is the pure-Rust offline-hive entry point. `complete` only describes the
/// keys enumerated from the supplied hive bytes; callers that recovered or
/// zero-filled those bytes must combine it with their own acquisition status.
pub fn hashdump_from_hives(
    system_hive: &RegistryHive,
    sam_hive: &RegistryHive,
    limit: usize,
) -> Result<RegistryEvidence<HashdumpRecord>> {
    ensure!(limit > 0, "hashdump result limit must be greater than zero");
    let mut warnings = Vec::new();
    let bootkey = bootkey(system_hive).context("cannot reconstruct SYSTEM boot key")?;
    let hbootkey =
        sam_hbootkey(sam_hive, &bootkey).context("cannot decrypt the SAM hashed boot key")?;
    let users = sam_hive
        .open_key("SAM\\Domains\\Account\\Users")?
        .context("SAM user key is absent")?;
    let enumeration = sam_hive.subkeys_best_effort(&users)?;
    warnings.extend(enumeration.warnings);
    let mut records = Vec::new();
    for key in enumeration.keys {
        if key.name.eq_ignore_ascii_case("Names") {
            continue;
        }
        if records.len() == limit {
            warnings.push(format!("hashdump result limit {limit} reached"));
            break;
        }
        let Ok(rid) = u32::from_str_radix(&key.name, 16) else {
            continue;
        };
        let values = match sam_hive.values_best_effort(&key) {
            Ok(values) => values,
            Err(error) => {
                warnings.push(format!("cannot read SAM RID {rid} values: {error:#}"));
                continue;
            }
        };
        warnings.extend(
            values
                .warnings
                .into_iter()
                .map(|warning| format!("SAM RID {rid}: {warning}")),
        );
        let Some(value) = values
            .values
            .into_iter()
            .find(|value| value.name.eq_ignore_ascii_case("V"))
        else {
            warnings.push(format!("SAM RID {rid} has no V value"));
            continue;
        };
        match decode_sam_user(rid, value.raw_data(), &hbootkey) {
            Ok((username, lm, nt)) => records.push(HashdumpRecord {
                username,
                rid,
                lm_hash: hex::encode(lm.unwrap_or(EMPTY_LM)),
                nt_hash: hex::encode(nt.unwrap_or(EMPTY_NT)),
            }),
            Err(error) => warnings.push(format!("cannot decode SAM RID {rid}: {error:#}")),
        }
    }
    let complete = warnings.is_empty();
    Ok(RegistryEvidence {
        available: true,
        complete,
        records,
        warnings,
    })
}

pub fn lsadump(
    session: &AnalysisSession,
    limit: usize,
) -> Result<RegistryEvidence<LsaSecretRecord>> {
    ensure!(limit > 0, "lsadump result limit must be greater than zero");
    let processes = session.processes(65_536)?;
    let mut system = recover_target_hive(session, &processes, "\\REGISTRY\\MACHINE\\SYSTEM");
    let mut security = recover_target_hive(session, &processes, "\\REGISTRY\\MACHINE\\SECURITY");
    let mut warnings = Vec::new();
    warnings.append(&mut system.warnings);
    warnings.append(&mut security.warnings);
    let (Some(system_hive), Some(security_hive)) = (system.hive.take(), security.hive.take())
    else {
        return Ok(RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings,
        });
    };
    let mut evidence = lsadump_from_hives(&system_hive, &security_hive, limit)?;
    evidence.complete &= system.complete && security.complete;
    warnings.append(&mut evidence.warnings);
    evidence.warnings = warnings;
    Ok(evidence)
}

/// Decode already recovered Hive bytes; callers retain acquisition completeness and identity.
pub fn lsadump_from_hives(
    system_hive: &RegistryHive,
    security_hive: &RegistryHive,
    limit: usize,
) -> Result<RegistryEvidence<LsaSecretRecord>> {
    ensure!(limit > 0, "lsadump result limit must be greater than zero");
    let mut warnings = Vec::new();
    let bootkey = bootkey(system_hive).context("cannot reconstruct SYSTEM boot key")?;
    let (lsa_key, modern) = match lsa_key(security_hive, &bootkey) {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!(
                "LSA policy key is unavailable in recovered SECURITY pages: {error:#}"
            ));
            return Ok(RegistryEvidence {
                records: Vec::new(),
                available: true,
                complete: false,
                warnings,
            });
        }
    };
    let secrets = security_hive
        .open_key("Policy\\Secrets")?
        .context("SECURITY Policy\\Secrets is absent")?;
    let enumeration = security_hive.subkeys_best_effort(&secrets)?;
    warnings.extend(enumeration.warnings);
    let mut records = Vec::new();
    for secret_key in enumeration.keys {
        if records.len() == limit {
            warnings.push(format!("lsadump result limit {limit} reached"));
            break;
        }
        match secret_by_name(security_hive, &secret_key.name, &lsa_key, modern) {
            Ok(Some(secret)) => records.push(LsaSecretRecord {
                name: secret_key.name,
                utf16: plausible_utf16_secret(&secret),
                secret_hex: hex::encode(secret),
            }),
            Ok(None) => {}
            Err(error) => warnings.push(format!(
                "cannot decrypt LSA secret {}: {error:#}",
                secret_key.name
            )),
        }
    }
    Ok(RegistryEvidence {
        available: true,
        complete: warnings.is_empty(),
        records,
        warnings,
    })
}

pub fn cachedump(
    session: &AnalysisSession,
    limit: usize,
) -> Result<RegistryEvidence<CachedumpRecord>> {
    ensure!(
        limit > 0,
        "cachedump result limit must be greater than zero"
    );
    let processes = session.processes(65_536)?;
    let mut system = recover_target_hive(session, &processes, "\\REGISTRY\\MACHINE\\SYSTEM");
    let mut security = recover_target_hive(session, &processes, "\\REGISTRY\\MACHINE\\SECURITY");
    let mut warnings = Vec::new();
    warnings.append(&mut system.warnings);
    warnings.append(&mut security.warnings);
    let (Some(system_hive), Some(security_hive)) = (system.hive.take(), security.hive.take())
    else {
        return Ok(RegistryEvidence {
            records: Vec::new(),
            available: false,
            complete: false,
            warnings,
        });
    };
    let mut evidence = cachedump_from_hives(&system_hive, &security_hive, limit)?;
    evidence.complete &= system.complete && security.complete;
    warnings.append(&mut evidence.warnings);
    evidence.warnings = warnings;
    Ok(evidence)
}

/// Decode cached logons from an explicitly paired SYSTEM and SECURITY acquisition.
pub fn cachedump_from_hives(
    system_hive: &RegistryHive,
    security_hive: &RegistryHive,
    limit: usize,
) -> Result<RegistryEvidence<CachedumpRecord>> {
    ensure!(
        limit > 0,
        "cachedump result limit must be greater than zero"
    );
    let mut warnings = Vec::new();
    let bootkey = bootkey(system_hive).context("cannot reconstruct SYSTEM boot key")?;
    let (lsa_key, modern) = match lsa_key(security_hive, &bootkey) {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!(
                "LSA policy key is unavailable in recovered SECURITY pages: {error:#}"
            ));
            return Ok(RegistryEvidence {
                records: Vec::new(),
                available: true,
                complete: false,
                warnings,
            });
        }
    };
    let nlkm = secret_by_name(security_hive, "NL$KM", &lsa_key, modern)?
        .context("LSA NL$KM secret is absent")?;
    let cache = security_hive
        .open_key("Cache")?
        .context("SECURITY Cache key is absent")?;
    let mut records = Vec::new();
    let enumeration = security_hive.values_best_effort(&cache)?;
    warnings.extend(enumeration.warnings);
    for value in enumeration.values {
        if value.name.eq_ignore_ascii_case("NL$Control") || value.raw_data().len() < 96 {
            continue;
        }
        if records.len() == limit {
            warnings.push(format!("cachedump result limit {limit} reached"));
            break;
        }
        match decode_cache_entry(&value.name, value.raw_data(), &nlkm, modern) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(error) => warnings.push(format!("cannot decode {}: {error:#}", value.name)),
        }
    }
    Ok(RegistryEvidence {
        available: true,
        complete: warnings.is_empty(),
        records,
        warnings,
    })
}

fn bootkey(system: &RegistryHive) -> Result<[u8; 16]> {
    let current = system
        // Select is a discovery hint, not BootKey material. A missing Select
        // page must not prevent checking complete ControlSetNNN siblings.
        .query_value("Select", "Current")
        .ok()
        .flatten()
        .and_then(|value| value.as_u32());
    let root = system.root()?;
    let enumeration = system.subkeys_best_effort(&root)?;
    let mut control_sets = BTreeSet::new();
    if let Some(current) = current {
        control_sets.insert(current);
    }
    for key in enumeration.keys {
        let Some(suffix) = key.name.strip_prefix("ControlSet") else {
            continue;
        };
        if suffix.len() == 3
            && suffix.chars().all(|character| character.is_ascii_digit())
            && let Ok(number) = suffix.parse::<u32>()
        {
            control_sets.insert(number);
        }
    }
    ensure!(
        !control_sets.is_empty(),
        "SYSTEM has no discoverable ControlSetNNN keys"
    );

    let mut recovered = Vec::new();
    let mut failures = Vec::new();
    for control_set in control_sets {
        match bootkey_from_control_set(system, control_set) {
            Ok(key) => {
                if !recovered.iter().any(|existing| existing == &key) {
                    recovered.push(key);
                }
            }
            Err(error) => failures.push(format!("ControlSet{control_set:03}: {error:#}")),
        }
    }
    ensure!(
        !recovered.is_empty(),
        "no ControlSet contains complete JD/Skew1/GBG/Data BootKey material{}",
        failures
            .first()
            .map(|failure| format!(" ({failure})"))
            .unwrap_or_default()
    );
    ensure!(
        recovered.len() == 1,
        "multiple ControlSet values produced conflicting SYSTEM BootKeys"
    );
    Ok(recovered[0])
}

fn bootkey_from_control_set(system: &RegistryHive, control_set: u32) -> Result<[u8; 16]> {
    let base = format!("ControlSet{control_set:03}\\Control\\Lsa");
    let mut encoded = String::new();
    for name in ["JD", "Skew1", "GBG", "Data"] {
        let key = system
            .open_key(&format!("{base}\\{name}"))?
            .with_context(|| format!("SYSTEM {base}\\{name} is absent"))?;
        encoded.push_str(
            system
                .key_class(&key)
                .with_context(|| format!("cannot read SYSTEM {base}\\{name} class"))?
                .as_deref()
                .with_context(|| format!("SYSTEM {name} class is absent"))?,
        );
    }
    let compact = encoded
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>();
    ensure!(
        compact.len() == 32,
        "SYSTEM BootKey class material must contain exactly 32 hexadecimal characters"
    );
    let scrambled = hex::decode(compact)?;
    ensure!(
        scrambled.len() == 16,
        "SYSTEM BootKey material must decode to exactly 16 bytes"
    );
    let mut output = [0u8; 16];
    for (index, source) in BOOTKEY_PERMUTATION.into_iter().enumerate() {
        output[index] = scrambled[source];
    }
    Ok(output)
}

fn validate_sam_hashdump_hive(sam: &RegistryHive, bootkey: &[u8; 16]) -> Result<()> {
    let hbootkey = sam_hbootkey(sam, bootkey)?;
    let users = sam
        .open_key("SAM\\Domains\\Account\\Users")?
        .context("SAM user key is absent")?;
    let enumeration = sam.subkeys_best_effort(&users)?;
    let mut readable_users = 0usize;
    let mut failures = Vec::new();
    for key in enumeration.keys {
        if key.name.eq_ignore_ascii_case("Names") {
            continue;
        }
        let Ok(rid) = u32::from_str_radix(&key.name, 16) else {
            continue;
        };
        let Ok(Some(value)) = sam.value_by_name(&key, "V") else {
            continue;
        };
        match decode_sam_user(rid, value.raw_data(), &hbootkey) {
            Ok(_) => readable_users += 1,
            Err(error) if failures.len() < 3 => {
                failures.push(format!("RID {rid}: {error:#}"));
            }
            Err(_) => {}
        }
    }
    ensure!(
        readable_users > 0,
        "SAM contains no structurally readable RID V records{}",
        failures
            .first()
            .map(|failure| format!(" ({failure})"))
            .unwrap_or_default()
    );
    Ok(())
}

fn sam_hbootkey(sam: &RegistryHive, bootkey: &[u8; 16]) -> Result<[u8; 16]> {
    let data = raw_value(sam, "SAM\\Domains\\Account", "F")?;
    ensure!(data.len() >= 0xa8, "SAM account F value is truncated");
    let mut output = [0u8; 16];
    match le_u32(&data, 0x68)? {
        1 => {
            let mut md5 = Md5::new();
            md5.update(&data[0x70..0x80]);
            md5.update(AQWERTY);
            md5.update(bootkey);
            md5.update(ANUM);
            let decrypted = rc4_crypt(&md5.finalize(), &data[0x80..0xa0]);
            let expected_checksum = Md5::new()
                .chain_update(&decrypted[..16])
                .chain_update(ANUM)
                .chain_update(&decrypted[..16])
                .chain_update(AQWERTY)
                .finalize();
            ensure!(
                decrypted[16..32] == expected_checksum[..],
                "SAM hashed boot-key checksum verification failed"
            );
            output.copy_from_slice(&decrypted[..16]);
        }
        2 => {
            let data_length = usize::try_from(le_u32(&data, 0x74)?)?;
            ensure!(data_length >= 16, "SAM AES hashed boot key is truncated");
            ensure!(
                data_length.is_multiple_of(16),
                "SAM AES hashed boot-key length is not block aligned"
            );
            let decrypted =
                aes128_cbc_decrypt(bootkey, &data[0x78..0x88], slice(&data, 0x88, data_length)?)?;
            output.copy_from_slice(&decrypted[..16]);
        }
        revision => anyhow::bail!("unsupported SAM key revision {revision}"),
    }
    Ok(output)
}

type SamUserHashes = (String, Option<[u8; 16]>, Option<[u8; 16]>);

fn decode_sam_user(rid: u32, data: &[u8], hbootkey: &[u8; 16]) -> Result<SamUserHashes> {
    ensure!(data.len() >= 0xcc, "SAM user V value is truncated");
    let name_offset = usize::try_from(le_u32(data, 0x0c)?)? + 0xcc;
    let name_length = usize::try_from(le_u32(data, 0x10)?)?;
    let username = decode_utf16(slice(data, name_offset, name_length)?)?;
    let lm_offset = usize::try_from(le_u32(data, 0x9c)?)? + 0xcc;
    let lm_length = usize::try_from(le_u32(data, 0xa0)?)?;
    let nt_offset = usize::try_from(le_u32(data, 0xa8)?)? + 0xcc;
    let nt_length = usize::try_from(le_u32(data, 0xac)?)?;
    let lm = decrypt_sam_hash(rid, data, lm_offset, lm_length, hbootkey, LM_PASSWORD)?;
    let nt = decrypt_sam_hash(rid, data, nt_offset, nt_length, hbootkey, NT_PASSWORD)?;
    Ok((username, lm, nt))
}

fn decrypt_sam_hash(
    rid: u32,
    data: &[u8],
    offset: usize,
    length: usize,
    hbootkey: &[u8; 16],
    label: &[u8],
) -> Result<Option<[u8; 16]>> {
    if length == 0 {
        return Ok(None);
    }
    let end = offset
        .checked_add(length)
        .context("SAM hash range overflow")?;
    ensure!(end <= data.len(), "SAM hash blob is truncated");
    ensure!(length >= 4, "SAM hash header is truncated");
    let revision = le_u16(data, offset + 2)?;
    let obfuscated = match revision {
        1 => {
            if length == 4 {
                return Ok(None);
            }
            ensure!(
                length == 20,
                "legacy SAM hash length {length} is not 20 bytes"
            );
            let encrypted = slice(data, offset + 4, 16)?;
            let mut md5 = Md5::new();
            md5.update(hbootkey);
            md5.update(rid.to_le_bytes());
            md5.update(label);
            rc4_crypt(&md5.finalize(), encrypted)
        }
        2 => {
            let data_offset = usize::try_from(le_u32(data, offset + 4)?)?;
            if length == 24 && data_offset == 0 {
                return Ok(None);
            }
            ensure!(
                data_offset == 16,
                "SAM AES hash data offset must be 16 bytes"
            );
            ensure!(length >= 40, "SAM AES hash payload is truncated");
            ensure!(
                (length - 24).is_multiple_of(16),
                "SAM AES hash length is not block aligned"
            );
            aes128_cbc_decrypt(
                hbootkey,
                slice(data, offset + 8, 16)?,
                slice(data, offset + 24, length - 24)?,
            )?
        }
        _ => anyhow::bail!("unsupported SAM hash revision {revision}"),
    };
    ensure!(obfuscated.len() >= 16, "decrypted SAM hash is truncated");
    let (key1, key2) = rid_des_keys(rid);
    let mut output = [0u8; 16];
    output[..8].copy_from_slice(&des_decrypt(&key1, &obfuscated[..8])?);
    output[8..].copy_from_slice(&des_decrypt(&key2, &obfuscated[8..16])?);
    Ok(Some(output))
}

fn lsa_key(security: &RegistryHive, bootkey: &[u8; 16]) -> Result<(Vec<u8>, bool)> {
    if let Ok(data) = raw_value(security, "Policy\\PolEKList", "") {
        let decrypted = decrypt_lsa_aes(&data, bootkey)?;
        ensure!(decrypted.len() >= 100, "decrypted PolEKList is truncated");
        return Ok((decrypted[68..100].to_vec(), true));
    }
    let data = raw_value(security, "Policy\\PolSecretEncryptionKey", "")?;
    ensure!(data.len() >= 76, "PolSecretEncryptionKey is truncated");
    let mut md5 = Md5::new();
    md5.update(bootkey);
    for _ in 0..1000 {
        md5.update(&data[60..76]);
    }
    let decrypted = rc4_crypt(&md5.finalize(), &data[12..60]);
    ensure!(
        decrypted.len() >= 32,
        "decrypted legacy LSA key is truncated"
    );
    Ok((decrypted[16..32].to_vec(), false))
}

fn secret_by_name(
    security: &RegistryHive,
    name: &str,
    lsa_key: &[u8],
    modern: bool,
) -> Result<Option<Vec<u8>>> {
    let path = format!("Policy\\Secrets\\{name}\\CurrVal");
    let Some(key) = security.open_key(&path)? else {
        return Ok(None);
    };
    let Some(value) = security.values(&key)?.into_iter().next() else {
        return Ok(None);
    };
    let encrypted = value.raw_data();
    if encrypted.is_empty() {
        return Ok(None);
    }
    if modern {
        Ok(Some(decrypt_lsa_aes(encrypted, lsa_key)?))
    } else {
        ensure!(encrypted.len() > 12, "legacy LSA secret is truncated");
        Ok(Some(decrypt_lsa_des(&encrypted[12..], lsa_key)?))
    }
}

fn decrypt_lsa_aes(secret: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    ensure!(secret.len() >= 60, "LSA AES blob is truncated");
    let mut sha = Sha256::new();
    sha.update(key);
    for _ in 0..1000 {
        sha.update(&secret[28..60]);
    }
    let aes_key = sha.finalize();
    let cipher = Aes256::new_from_slice(&aes_key)?;
    let mut output = Vec::with_capacity(secret.len().saturating_sub(60));
    for chunk in secret[60..].chunks(16) {
        let mut raw = [0u8; 16];
        raw[..chunk.len()].copy_from_slice(chunk);
        let mut block = GenericArray::clone_from_slice(&raw);
        cipher.decrypt_block(&mut block);
        output.extend_from_slice(&block);
    }
    Ok(output)
}

fn decrypt_lsa_des(secret: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() >= 7, "legacy LSA key is too short");
    let mut output = Vec::new();
    let mut key_index = 0usize;
    for encrypted in secret.chunks(8) {
        if key_index + 7 > key.len() {
            key_index = 0;
        }
        let des_key = seven_byte_des_key(&key[key_index..key_index + 7]);
        let mut raw = [0u8; 8];
        raw[..encrypted.len()].copy_from_slice(encrypted);
        output.extend_from_slice(&des_decrypt(&des_key, &raw)?);
        key_index += 7;
    }
    ensure!(output.len() >= 8, "legacy LSA plaintext is truncated");
    let length = usize::try_from(le_u32(&output, 0)?)?;
    Ok(slice(&output, 8, length)?.to_vec())
}

fn decode_cache_entry(
    cache_name: &str,
    data: &[u8],
    nlkm: &[u8],
    modern: bool,
) -> Result<Option<CachedumpRecord>> {
    ensure!(data.len() >= 96, "cached logon entry is truncated");
    let username_length = usize::from(le_u16(data, 0)?);
    let domain_length = usize::from(le_u16(data, 2)?);
    let domain_name_length = usize::from(le_u16(data, 60)?);
    if username_length == 0 {
        return Ok(None);
    }
    let challenge = slice(data, 64, 16)?;
    let encrypted = &data[96..];
    let decrypted = if modern {
        ensure!(
            nlkm.len() >= 32,
            "NL$KM secret is too short for AES cache decryption"
        );
        aes128_cbc_decrypt(&nlkm[16..32], challenge, encrypted)?
    } else {
        // HMAC-MD5(nlkm, challenge) without pulling an extra crypto wrapper.
        let key = hmac_md5(nlkm, challenge);
        rc4_crypt(&key, encrypted)
    };
    ensure!(decrypted.len() >= 72, "decrypted cache entry is truncated");
    let hash = slice(&decrypted, 0, 16)?;
    let username_offset = 72usize;
    let domain_offset = username_offset + username_length + 2 * ((username_length / 2) % 2);
    let domain_name_offset = domain_offset + domain_length + 2 * ((domain_length / 2) % 2);
    Ok(Some(CachedumpRecord {
        cache_name: cache_name.to_owned(),
        username: decode_utf16(slice(&decrypted, username_offset, username_length)?)?,
        domain: decode_utf16(slice(&decrypted, domain_offset, domain_length)?)?,
        domain_name: decode_utf16(slice(&decrypted, domain_name_offset, domain_name_length)?)?,
        hash: hex::encode(hash),
    }))
}

fn raw_value(hive: &RegistryHive, path: &str, name: &str) -> Result<Vec<u8>> {
    Ok(hive
        .query_value(path, name)?
        .with_context(|| format!("registry value {path}\\{name} is absent"))?
        .raw_data()
        .to_vec())
}

fn rid_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let bytes = rid.to_le_bytes();
    let first = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[0], bytes[1], bytes[2],
    ];
    let second = [
        bytes[3], bytes[0], bytes[1], bytes[2], bytes[3], bytes[0], bytes[1],
    ];
    (seven_byte_des_key(&first), seven_byte_des_key(&second))
}

fn seven_byte_des_key(source: &[u8]) -> [u8; 8] {
    let mut key = [
        source[0] >> 1,
        ((source[0] & 1) << 6) | (source[1] >> 2),
        ((source[1] & 3) << 5) | (source[2] >> 3),
        ((source[2] & 7) << 4) | (source[3] >> 4),
        ((source[3] & 0xf) << 3) | (source[4] >> 5),
        ((source[4] & 0x1f) << 2) | (source[5] >> 6),
        ((source[5] & 0x3f) << 1) | (source[6] >> 7),
        source[6] & 0x7f,
    ];
    for byte in &mut key {
        *byte <<= 1;
        if byte.count_ones() % 2 == 0 {
            *byte |= 1;
        }
    }
    key
}

fn des_decrypt(key: &[u8; 8], data: &[u8]) -> Result<[u8; 8]> {
    ensure!(data.len() == 8, "DES block is not eight bytes");
    let cipher = Des::new_from_slice(key)?;
    let mut block = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    Ok(block.into())
}

fn aes128_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() == 16, "AES-128 key length is invalid");
    ensure!(iv.len() == 16, "AES CBC IV length is invalid");
    let cipher = Aes128::new_from_slice(key)?;
    let mut previous: [u8; 16] = iv.try_into()?;
    let mut output = Vec::with_capacity(data.len().div_ceil(16) * 16);
    for encrypted in data.chunks(16) {
        let mut raw = [0u8; 16];
        raw[..encrypted.len()].copy_from_slice(encrypted);
        let ciphertext = raw;
        let mut block = GenericArray::clone_from_slice(&raw);
        cipher.decrypt_block(&mut block);
        for index in 0..16 {
            block[index] ^= previous[index];
        }
        output.extend_from_slice(&block);
        previous = ciphertext;
    }
    Ok(output)
}

fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (index, byte) in state.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut j = 0usize;
    for index in 0..256 {
        j = (j + usize::from(state[index]) + usize::from(key[index % key.len()])) & 0xff;
        state.swap(index, j);
    }
    let mut i = 0usize;
    j = 0;
    data.iter()
        .map(|byte| {
            i = (i + 1) & 0xff;
            j = (j + usize::from(state[i])) & 0xff;
            state.swap(i, j);
            let key_byte = state[(usize::from(state[i]) + usize::from(state[j])) & 0xff];
            byte ^ key_byte
        })
        .collect()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut normalized = [0u8; 64];
    if key.len() > 64 {
        normalized[..16].copy_from_slice(&Md5::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Md5::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn plausible_utf16_secret(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    for start in [0usize, 16] {
        let bytes = data.get(start..)?;
        let even = bytes.len() & !1;
        let units = bytes[..even]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        if units.len() >= 2 {
            let text = String::from_utf16_lossy(&units);
            if text
                .chars()
                .all(|character| !character.is_control() || matches!(character, '\r' | '\n' | '\t'))
            {
                return Some(text);
            }
        }
    }
    None
}

fn decode_utf16(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len().is_multiple_of(2), "UTF-16 byte length is odd");
    Ok(String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    ))
}

fn slice(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    data.get(offset..offset.saturating_add(length))
        .context("binary structure range is truncated")
}

fn le_u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(data, offset, 2)?.try_into()?))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(data, offset, 4)?.try_into()?))
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
pub(crate) mod recovery_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_known_vector() {
        assert_eq!(
            hex::encode(rc4_crypt(b"Key", b"Plaintext")),
            "bbf316e8d940af0ad3"
        );
    }

    #[test]
    fn des_keys_have_odd_parity() {
        let (first, second) = rid_des_keys(500);
        for key in [first, second] {
            assert!(key.into_iter().all(|byte| byte.count_ones() % 2 == 1));
        }
    }

    #[test]
    fn sam_hash_absence_is_distinct_from_malformed_data() {
        let hbootkey = [0u8; 16];

        let mut legacy_absent = [0u8; 4];
        legacy_absent[2] = 1;
        assert!(
            decrypt_sam_hash(500, &legacy_absent, 0, 4, &hbootkey, NT_PASSWORD)
                .unwrap()
                .is_none()
        );

        let mut aes_absent = [0u8; 24];
        aes_absent[2] = 2;
        assert!(
            decrypt_sam_hash(500, &aes_absent, 0, 24, &hbootkey, NT_PASSWORD)
                .unwrap()
                .is_none()
        );

        let mut malformed = [0u8; 8];
        malformed[2] = 1;
        assert!(decrypt_sam_hash(500, &malformed, 0, 8, &hbootkey, NT_PASSWORD).is_err());

        let mut malformed_aes = [0u8; 24];
        malformed_aes[2] = 2;
        malformed_aes[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(decrypt_sam_hash(500, &malformed_aes, 0, 24, &hbootkey, NT_PASSWORD).is_err());

        let mut unknown_revision = legacy_absent;
        unknown_revision[3] = 1;
        assert!(decrypt_sam_hash(500, &unknown_revision, 0, 4, &hbootkey, NT_PASSWORD).is_err());
    }
}

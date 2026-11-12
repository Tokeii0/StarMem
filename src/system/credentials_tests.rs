use super::*;

// AES vectors generated independently with PyCryptodome. Salt = bytes(0..32),
// LSA key = bytes(64..96), NL$KM plaintext body = bytes(32..96). The cache uses
// the decrypted NL$KM blob's [16..32] slice, matching the existing decoder contract.
pub(crate) fn security_fixture() -> RegistryHive {
    const POLICY: &str = "00000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f3de44b7ab99bb611dd6993025fb6cff2bf0c3bd30d2fc265d0742e578ace9a76bf0c3bd30d2fc265d0742e578ace9a76bf0c3bd30d2fc265d0742e578ace9a7662236f41bdab3b4b472fd764efaa44b9bed0ae75e1e9f13db066492b84e1f141151409762e1526f25fa5eaacfc39f9b7";
    const NLKM: &str = "00000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1faa02fb745af84c7ee688685f20cf3787759c915923ebb300fecee12c3fcae6e155ab276e1c668022df7177bb9c310cd45aa70d60fe301544925ca3b500b5ea51ba1e9b528d36acfba8623111368614dd";
    const SECRET: &str = "00000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fa1dd029f5168cd2fe886e462900be9e72656018d6e0fa1dc936ccabbcbf1989f98b80ba0f2e1a4bdd670edfaaeb3aba5";
    const CACHE: &str = "0e000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000000102030405060708090a0b0c0d0e0f00000000000000000000000000000000110c14a5f7777ad13148070aa5c74b90a0d4af3812016b85ddfa8d89d90e4b95e6e7d8e241d58d282abc0470dbbd2b2be111d7ca8eeb1919bc3aa4c8d243a9e5cbb3116b5986091f4e9fa6f3d514cb005647070d2e1543b32d33dbb9a2cf9a2c6df3be9a421a351de7795d5fc47a0331dba1dcf14487e65694ad6e503807764a";
    let mut hive = HiveFixture::new();
    let value = hive.value("", &hex::decode(POLICY).unwrap());
    let policy_key = hive.key("PolEKList", &[], &[value], None);
    let mut secret_keys = Vec::new();
    for (name, bytes) in [("NL$KM", NLKM), ("TestSecret", SECRET)] {
        let value = hive.value("", &hex::decode(bytes).unwrap());
        let curr = hive.key("CurrVal", &[], &[value], None);
        secret_keys.push(hive.key(name, &[curr], &[], None));
    }
    let secrets = hive.key("Secrets", &secret_keys, &[], None);
    let policy = hive.key("Policy", &[policy_key, secrets], &[], None);
    let value = hive.value("NL$1", &hex::decode(CACHE).unwrap());
    let cache = hive.key("Cache", &[], &[value], None);
    let root = hive.key("SECURITY", &[policy, cache], &[], None);
    hive.finish(root)
}

#[test]
fn offline_security_decoders_match_independent_aes_vectors() {
    let system = system_fixture(false, false);
    let security = security_fixture();
    let lsa = lsadump_from_hives(&system, &security, 100).unwrap();
    assert!(lsa.complete, "{:?}", lsa.warnings);
    let secret = lsa
        .records
        .iter()
        .find(|record| record.name == "TestSecret")
        .unwrap();
    assert_eq!(
        secret.secret_hex,
        "1c0000000000000000000000000000006600690078007400750072006500200073006500630072006500740000000000"
    );
    let cache = cachedump_from_hives(&system, &security, 100).unwrap();
    assert!(cache.complete, "{:?}", cache.warnings);
    assert_eq!(cache.records.len(), 1);
    assert_eq!(cache.records[0].username, "analyst");
    assert_eq!(cache.records[0].domain, "LAB");
    assert_eq!(cache.records[0].domain_name, "lab.example");
    assert_eq!(cache.records[0].hash, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    assert!(!lsadump_from_hives(&system, &security, 1).unwrap().complete);
}

// Synthetic vectors independently generated with PyCryptodome (AES-CBC,
// ARC4, DES); password "password", RID 1001. No evidence-image secrets.
const EXPECTED_NT: &str = "8846f7eaee8fb117ad06bdd830b7586c";
const LEGACY_KEY: &str = "336cfa7468a918c3c027975e55bb433b6df3e9594da449e669f2d0ef05121cd1";
const AES_KEY: &str = "12cf8bccb05b924da42f1dcf310b61e7937eb90c8f5e504f8b74fbcffa4de059";
const LEGACY_HASH: &str = "0000010059aeee73a4d53742327caa08c64cc9a7";
const AES_HASH: &str = "0000020010000000202122232425262728292a2b2c2d2e2ffc2336ee45c6ebe7f1dac945c3a3c98e06ed62711c57b92a134edec08698ba08";

pub(crate) struct HiveFixture {
    bytes: Vec<u8>,
    next: u32,
}

impl HiveFixture {
    pub(crate) fn new() -> Self {
        let mut bytes = vec![0u8; 0x5000];
        bytes[..4].copy_from_slice(b"regf");
        bytes[0x1000..0x1004].copy_from_slice(b"hbin");
        Self { bytes, next: 0x20 }
    }

    fn cell(&mut self, payload: &[u8]) -> u32 {
        let index = self.next;
        let size = (payload.len() + 4).next_multiple_of(8);
        let start = 0x1000 + index as usize;
        self.bytes[start..start + 4].copy_from_slice(&(-(size as i32)).to_le_bytes());
        self.bytes[start + 4..start + 4 + payload.len()].copy_from_slice(payload);
        self.next += size as u32;
        index
    }

    pub(crate) fn value(&mut self, name: &str, data: &[u8]) -> u32 {
        let data_cell = self.cell(data);
        let mut vk = vec![0u8; 0x14 + name.len()];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
        vk[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        vk[8..12].copy_from_slice(&data_cell.to_le_bytes());
        vk[12..16].copy_from_slice(&3u32.to_le_bytes());
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        vk[0x14..].copy_from_slice(name.as_bytes());
        self.cell(&vk)
    }

    pub(crate) fn key(
        &mut self,
        name: &str,
        children: &[u32],
        values: &[u32],
        class: Option<&str>,
    ) -> u32 {
        let mut nk = vec![0u8; 0x4c + name.len()];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        if !children.is_empty() {
            let mut li = b"li".to_vec();
            li.extend_from_slice(&(children.len() as u16).to_le_bytes());
            li.extend(children.iter().flat_map(|c| c.to_le_bytes()));
            nk[0x14..0x18].copy_from_slice(&(children.len() as u32).to_le_bytes());
            nk[0x1c..0x20].copy_from_slice(&self.cell(&li).to_le_bytes());
        }
        if !values.is_empty() {
            let list = values
                .iter()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>();
            nk[0x24..0x28].copy_from_slice(&(values.len() as u32).to_le_bytes());
            nk[0x28..0x2c].copy_from_slice(&self.cell(&list).to_le_bytes());
        }
        if let Some(class) = class {
            let text = class
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            nk[0x30..0x34].copy_from_slice(&self.cell(&text).to_le_bytes());
            nk[0x4a..0x4c].copy_from_slice(&(text.len() as u16).to_le_bytes());
        }
        nk[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
        nk[0x4c..].copy_from_slice(name.as_bytes());
        self.cell(&nk)
    }

    fn missing_value_list(&mut self, key: u32) {
        let start = 0x1000 + key as usize + 4;
        self.bytes[start + 0x24..start + 0x28].copy_from_slice(&1u32.to_le_bytes());
        self.bytes[start + 0x28..start + 0x2c].copy_from_slice(&0x3f00u32.to_le_bytes());
    }

    pub(crate) fn finish(mut self, root: u32) -> RegistryHive {
        self.bytes[0x24..0x28].copy_from_slice(&root.to_le_bytes());
        RegistryHive::from_bytes(self.bytes).unwrap()
    }
}

pub(crate) fn system_fixture(missing_select: bool, conflicting_set: bool) -> RegistryHive {
    let mut hive = HiveFixture::new();
    let mut children = Vec::new();
    for set in 1..=if conflicting_set { 2 } else { 1 } {
        let mut keys = Vec::new();
        for (index, name) in ["JD", "Skew1", "GBG", "Data"].iter().enumerate() {
            let first = (index * 4 + (set - 1) * 16) as u8;
            let class = hex::encode([first, first + 1, first + 2, first + 3]);
            keys.push(hive.key(name, &[], &[], Some(&class)));
        }
        let lsa = hive.key("Lsa", &keys, &[], None);
        let control = hive.key("Control", &[lsa], &[], None);
        children.push(hive.key(&format!("ControlSet{set:03}"), &[control], &[], None));
    }
    let select = hive.key("Select", &[], &[], None);
    if missing_select {
        hive.missing_value_list(select);
    }
    children.push(select);
    let root = hive.key("SYSTEM", &children, &[], None);
    hive.finish(root)
}

pub(crate) fn sam_fixture(
    aes: bool,
    missing_user: bool,
    missing_extra_value: bool,
) -> RegistryHive {
    let mut hive = HiveFixture::new();
    let mut f = vec![0u8; 0xa8];
    f[0x68..0x6c].copy_from_slice(&(if aes { 2u32 } else { 1 }).to_le_bytes());
    let salt = (32u8..48).collect::<Vec<_>>();
    if aes {
        f[0x74..0x78].copy_from_slice(&32u32.to_le_bytes());
        f[0x78..0x88].copy_from_slice(&salt);
        f[0x88..0xa8].copy_from_slice(&hex::decode(AES_KEY).unwrap());
    } else {
        f[0x70..0x80].copy_from_slice(&salt);
        f[0x80..0xa0].copy_from_slice(&hex::decode(LEGACY_KEY).unwrap());
    }
    let f = hive.value("F", &f);
    let name = "analyst"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let hash = hex::decode(if aes { AES_HASH } else { LEGACY_HASH }).unwrap();
    let mut v = vec![0u8; 0xcc];
    v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
    v[0xa8..0xac].copy_from_slice(&(name.len() as u32).to_le_bytes());
    v[0xac..0xb0].copy_from_slice(&(hash.len() as u32).to_le_bytes());
    v.extend(name);
    v.extend(hash);
    let v = hive.value("V", &v);
    let values = if missing_extra_value {
        vec![v, 0x3e00]
    } else {
        vec![v]
    };
    let good = hive.key("000003E9", &[], &values, None);
    let mut users = vec![good];
    if missing_user {
        let bad = hive.key("000003EA", &[], &[], None);
        hive.missing_value_list(bad);
        users.push(bad);
    }
    let users = hive.key("Users", &users, &[], None);
    let account = hive.key("Account", &[users], &[f], None);
    let domains = hive.key("Domains", &[account], &[], None);
    let sam = hive.key("SAM", &[domains], &[], None);
    let root = hive.key("ROOT", &[sam], &[], None);
    hive.finish(root)
}

#[test]
fn decrypts_independent_legacy_and_aes_sam_vectors() {
    for aes in [false, true] {
        let report = hashdump_from_hives(
            &system_fixture(false, false),
            &sam_fixture(aes, false, false),
            100,
        )
        .unwrap();
        assert!(report.complete, "{:?}", report.warnings);
        assert_eq!(
            report.records,
            vec![HashdumpRecord {
                username: "analyst".to_owned(),
                rid: 1001,
                lm_hash: hex::encode(EMPTY_LM),
                nt_hash: EXPECTED_NT.to_owned(),
            }]
        );
    }
}

#[test]
fn missing_select_does_not_hide_a_complete_control_set() {
    let system = system_fixture(true, false);
    assert!(system.query_value("Select", "Current").is_err());
    let report = hashdump_from_hives(&system, &sam_fixture(true, false, false), 100).unwrap();
    assert_eq!(report.records[0].nt_hash, EXPECTED_NT);
}

#[test]
fn conflicting_bootkeys_are_still_rejected() {
    let error = bootkey(&system_fixture(false, true))
        .unwrap_err()
        .to_string();
    assert!(error.contains("conflicting"));
}

#[test]
fn unreadable_account_does_not_discard_already_decrypted_records() {
    let report = hashdump_from_hives(
        &system_fixture(false, false),
        &sam_fixture(true, true, false),
        100,
    )
    .unwrap();
    assert!(report.available);
    assert!(!report.complete);
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].nt_hash, EXPECTED_NT);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("RID 1002") && warning.contains("0x3f00"))
    );
}

#[test]
fn unreadable_extra_value_is_visible_even_when_user_v_survives() {
    let report = hashdump_from_hives(
        &system_fixture(false, false),
        &sam_fixture(false, false, true),
        100,
    )
    .unwrap();
    assert!(!report.complete);
    assert_eq!(report.records[0].nt_hash, EXPECTED_NT);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("RID 1001") && warning.contains("0x3e00"))
    );
}

#[test]
fn exact_record_limit_is_complete_but_skipped_accounts_are_not() {
    let system = system_fixture(false, false);
    assert!(
        hashdump_from_hives(&system, &sam_fixture(true, false, false), 1)
            .unwrap()
            .complete
    );
    let limited = hashdump_from_hives(&system, &sam_fixture(true, true, false), 1).unwrap();
    assert!(!limited.complete);
    assert!(
        limited
            .warnings
            .iter()
            .any(|warning| warning.contains("limit"))
    );
}

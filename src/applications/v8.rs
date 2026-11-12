//! Offline, data-only V8 heap recovery. No getters, proxies or recovered code run.
//! Layout references: V8 string.tq, map.tq, descriptor-array.tq,
//! property-details.h and sandbox/external-pointer-table.h (13.8 and main).
//! Explicitly validated compressed-pointer layouts are supported; unknown
//! layouts, dictionary properties and external-pointer ambiguity fail closed.
use super::{ApplicationRecord, ApplicationReport, ai};
use crate::{
    address::X64AddressSpace, cancellation::CancellationToken, image::MemoryImage,
    session::AnalysisSession,
};
use anyhow::Result;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};

const MAX_PAGES: usize = 131_072;
const MAX_NODES: usize = 8192;
const MAX_STRING: usize = 262_144;
const MAX_ROOTS: usize = 4096;
const MASK: u64 = 0x000f_ffff_ffff_f000;

trait Memory {
    fn read(&self, va: u64, len: usize) -> Option<Vec<u8>>;
}
struct Resident<'a> {
    image: &'a MemoryImage,
    space: &'a X64AddressSpace<'a>,
    pages: BTreeMap<u64, u64>,
    token: &'a CancellationToken,
    bytes: Cell<usize>,
    exhausted: Cell<bool>,
    cache: RefCell<HashMap<u64, Vec<u8>>>,
}
impl Memory for Resident<'_> {
    fn read(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        if len > MAX_STRING * 2 || self.token.is_cancelled() {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let addr = va.checked_add(out.len() as u64)?;
            let page = addr & !4095;
            let pa = *self.pages.get(&page)?;
            let off = (addr & 4095) as usize;
            let n = (len - out.len()).min(4096 - off);
            let mut cache = self.cache.borrow_mut();
            if !cache.contains_key(&page) {
                if self.bytes.get() >= 512 * 1024 * 1024 {
                    self.exhausted.set(true);
                    return None;
                }
                // Revalidate forward translation, including transition PTEs.
                if self.space.translate(page).ok()? != pa {
                    return None;
                }
                let mut b = vec![0; 4096];
                self.image.read_physical(pa, &mut b).ok()?;
                self.bytes.set(self.bytes.get() + 4096);
                if cache.len() >= 16_384 {
                    cache.clear();
                }
                cache.insert(page, b);
            }
            out.extend_from_slice(cache.get(&page)?.get(off..off + n)?);
        }
        Some(out)
    }
}

/// Bounded resident traversal, including Windows transition pages. Prototype
/// and swapped pages are not synthesized. The normal address translator checks
/// every page again before any object bytes are consumed.
fn resident_pages(
    image: &MemoryImage,
    dtb: u64,
    token: &CancellationToken,
) -> Result<(BTreeMap<u64, u64>, usize, bool)> {
    let mut pages = BTreeMap::new();
    let mut stack = vec![(dtb & MASK, 0u64, 39u32)];
    let (mut entries, mut failed) = (0usize, 0usize);
    while let Some((table, prefix, shift)) = stack.pop() {
        token.check_cancelled()?;
        let mut bytes = [0; 4096];
        if image.read_physical(table, &mut bytes).is_err() {
            failed += 1;
            continue;
        }
        for (i, b) in bytes.chunks_exact(8).enumerate() {
            if shift == 39 && i >= 256 {
                break;
            }
            entries += 1;
            if entries > 2_000_000 || pages.len() >= MAX_PAGES {
                return Ok((pages, failed, true));
            }
            let e = u64::from_le_bytes(b.try_into().unwrap_or_default());
            let present = e & 1 != 0;
            let pa = if present {
                e & MASK
            } else if e & 0xc00 == 0x800 {
                e & 0x0000_dfff_ffff_f000
            } else {
                continue;
            };
            if pa == 0 {
                continue;
            }
            let va = prefix | ((i as u64) << shift);
            if shift == 12 {
                pages.insert(va, pa);
            } else if present && e & 128 != 0 && matches!(shift, 21 | 30) {
                let size = 1u64 << shift;
                for off in (0..size).step_by(4096) {
                    if pages.len() >= MAX_PAGES {
                        return Ok((pages, failed, true));
                    }
                    pages.insert(va + off, (pa & !(size - 1)) + off);
                }
            } else {
                stack.push((pa, va, shift - 9));
            }
        }
    }
    Ok((pages, failed, false))
}

fn u32_at(b: &[u8], n: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(n..n + 4)?.try_into().ok()?))
}
fn u16_at(b: &[u8], n: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(n..n + 2)?.try_into().ok()?))
}
fn pointer(base: u64, tag: u32) -> Option<u64> {
    (tag & 3 == 1).then(|| base + u64::from(tag) - 1)
}
fn smi(tag: u32) -> Option<i32> {
    (tag & 1 == 0).then_some((tag as i32) >> 1)
}

#[derive(Clone, Copy)]
struct Layout {
    map_type: u16,
    array_type: u16,
    proxy_type: u16,
    map_object_type: u16,
    data_tags: &'static [u8],
    direct_offsets: bool,
}
impl Layout {
    fn for_map(ty: u16) -> Option<Self> {
        match ty {
            270 => Some(Self {
                map_type: 270,
                array_type: 2119,
                proxy_type: 297,
                map_object_type: 2112,
                data_tags: &[12, 13],
                direct_offsets: false,
            }),
            275 => Some(Self {
                map_type: 275,
                array_type: 2119,
                // Proxy and observable-Map layouts have not been validated
                // for this profile. Zero deliberately matches neither.
                proxy_type: 0,
                map_object_type: 0,
                data_tags: &[12, 13],
                direct_offsets: false,
            }),
            278 => Some(Self {
                map_type: 278,
                array_type: 2121,
                proxy_type: 309,
                map_object_type: 2114,
                data_tags: &[3],
                direct_offsets: true,
            }),
            _ => None,
        }
    }
}
#[derive(Clone)]
struct Shape {
    words: usize,
    start: usize,
    fields: Vec<(String, u32, u32)>,
    unknown: usize,
}

struct Heap<'a> {
    mem: &'a dyn Memory,
    base: u64,
    layout: Layout,
    ept: Option<u64>,
    map_cache: HashMap<u32, Option<(u16, Vec<u8>)>>,
    shape_cache: HashMap<u32, Option<Shape>>,
    tracing: bool,
    reads: BTreeMap<(u64, usize), String>,
    strings: Vec<Value>,
    nodes: usize,
    unresolved: usize,
    active: HashSet<u32>,
    string_steps: usize,
    trace_bytes: usize,
}
impl<'a> Heap<'a> {
    fn new(mem: &'a dyn Memory, base: u64, layout: Layout) -> Self {
        Self {
            mem,
            base,
            layout,
            ept: None,
            map_cache: HashMap::new(),
            shape_cache: HashMap::new(),
            tracing: false,
            reads: BTreeMap::new(),
            strings: vec![],
            nodes: 0,
            unresolved: 0,
            active: HashSet::new(),
            string_steps: 0,
            trace_bytes: 0,
        }
    }
    fn read(&mut self, va: u64, n: usize) -> Option<Vec<u8>> {
        if self.tracing
            && (self.reads.len() >= MAX_NODES
                || self.trace_bytes.saturating_add(n) > 8 * 1024 * 1024)
        {
            self.unresolved += 1;
            return None;
        }
        let b = self.mem.read(va, n)?;
        if self.tracing {
            if !self.reads.contains_key(&(va, n)) {
                self.trace_bytes += n;
            }
            self.reads
                .entry((va, n))
                .or_insert_with(|| hex::encode(Sha256::digest(&b)));
        }
        Some(b)
    }
    fn word(&mut self, va: u64) -> Option<u32> {
        u32_at(&self.read(va, 4)?, 0)
    }
    fn map(&mut self, tag: u32) -> Option<(u16, Vec<u8>)> {
        if !self.tracing
            && let Some(v) = self.map_cache.get(&tag)
        {
            return v.clone();
        }
        let result = (|| {
            let b = self.read(pointer(self.base, tag)?, 40)?;
            let meta = self.read(pointer(self.base, u32_at(&b, 0)?)?, 16)?;
            if u16_at(&meta, 8)? != self.layout.map_type {
                return None;
            }
            let root = self.read(pointer(self.base, u32_at(&meta, 0)?)?, 16)?;
            if u16_at(&root, 8)? != self.layout.map_type || u32_at(&root, 0)? != u32_at(&meta, 0)? {
                return None;
            }
            Some((u16_at(&b, 8)?, b))
        })();
        if !self.tracing && self.map_cache.len() < 65536 {
            self.map_cache.insert(tag, result.clone());
        }
        result
    }
    fn string_units(&mut self, tag: u32, depth: usize) -> Option<Vec<u16>> {
        self.string_steps += 1;
        if depth > 24 || self.string_steps > 4096 {
            return None;
        }
        let va = pointer(self.base, tag)?;
        let b = self.read(va, 20)?;
        let (ty, _) = self.map(u32_at(&b, 0)?)?;
        let n = u32_at(&b, 8)? as usize;
        if ty >= 128 || n > MAX_STRING {
            return None;
        }
        let one = ty & 8 != 0;
        let out = match ty & 7 {
            0 => {
                let raw = self.read(va + 12, n * if one { 1 } else { 2 })?;
                if one {
                    raw.into_iter().map(u16::from).collect()
                } else {
                    raw.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect()
                }
            }
            1 => {
                let mut a = self.string_units(u32_at(&b, 12)?, depth + 1)?;
                let b = self.string_units(u32_at(&b, 16)?, depth + 1)?;
                if a.len() + b.len() != n {
                    return None;
                }
                a.extend(b);
                a
            }
            2 if ty & 16 == 0 => {
                let handle = u32_at(&b, 16)?;
                if handle == 0 || handle & 63 != 0 {
                    return None;
                }
                let entry = self.read(self.ept? + u64::from(handle >> 6) * 8, 8)?;
                let word = u64::from_le_bytes(entry.try_into().ok()?);
                if word >> 56 != 0 || !self.layout.data_tags.contains(&((word >> 49 & 127) as u8)) {
                    return None;
                }
                let raw = self.read(word & 0xffff_ffff_ffff, n * if one { 1 } else { 2 })?;
                if one {
                    raw.into_iter().map(u16::from).collect()
                } else {
                    raw.chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect()
                }
            }
            3 => {
                let parent = self.string_units(u32_at(&b, 12)?, depth + 1)?;
                let off = smi(u32_at(&b, 16)?)?;
                if off < 0 {
                    return None;
                }
                parent
                    .get(off as usize..(off as usize).checked_add(n)?)?
                    .to_vec()
            }
            5 => self.string_units(u32_at(&b, 12)?, depth + 1)?,
            _ => return None,
        };
        (out.len() == n).then_some(out)
    }
    fn string(&mut self, tag: u32) -> Option<String> {
        self.string_steps = 0;
        String::from_utf16(&self.string_units(tag, 0)?).ok()
    }
    fn shape(&mut self, tag: u32) -> Option<Shape> {
        if !self.tracing
            && let Some(v) = self.shape_cache.get(&tag)
        {
            return v.clone();
        }
        let out = (|| {
            let (ty, b) = self.map(tag)?;
            if ty != 1057 {
                return None;
            }
            let (words, start) = (b[4] as usize, b[5] as usize);
            let flags = u32_at(&b, 12)?;
            let n = (flags >> 10 & 1023) as usize;
            if flags & (1 << 21) != 0
                || !(1..=96).contains(&n)
                || start < 3
                || start > words
                || words > 128
            {
                return None;
            }
            let desc = pointer(self.base, u32_at(&b, 24)?)?;
            let head = self.read(desc, 20)?;
            let (total, used) = (u16_at(&head, 4)? as usize, u16_at(&head, 6)? as usize);
            if used < n || used > total || total > 1024 {
                return None;
            }
            for offset in [16, 20] {
                let Some(raw) = self.read(desc + offset, n * 12) else {
                    continue;
                };
                let mut fields = vec![];
                let mut unknown = 0;
                let mut valid = true;
                for row in raw.chunks_exact(12) {
                    let (key, det, val) = (u32_at(row, 0)?, u32_at(row, 4)?, u32_at(row, 8)?);
                    if det & 1 != 0 {
                        valid = false;
                        break;
                    }
                    if let Some(name) = self.string(key) {
                        if name.len() > 200 || name.chars().any(char::is_control) {
                            valid = false;
                            break;
                        }
                        fields.push((name, det >> 1, val));
                    } else {
                        unknown += 1;
                    }
                }
                if valid && !fields.is_empty() && unknown <= n / 2 {
                    return Some(Shape {
                        words,
                        start,
                        fields,
                        unknown,
                    });
                }
            }
            None
        })();
        if !self.tracing && self.shape_cache.len() < 32768 {
            self.shape_cache.insert(tag, out.clone());
        }
        out
    }
    fn fields(&mut self, va: u64) -> Option<BTreeMap<String, u32>> {
        let tag = self.word(va)?;
        let shape = self.shape(tag)?;
        let mut out = BTreeMap::new();
        self.read(va, shape.words * 4)?;
        self.unresolved += shape.unknown;
        for (name, det, val) in shape.fields {
            if det & 1 != 0 {
                continue;
            } // Accessors are never invoked.
            if det & 32 != 0 {
                out.insert(name, val);
                continue;
            }
            let index = (det >> 19 & 1023) as usize;
            let (inside, slot) = if self.layout.direct_offsets {
                (det & (1 << 30) != 0, index)
            } else if index < shape.words - shape.start {
                (true, shape.start + index)
            } else {
                (false, 2 + index - (shape.words - shape.start))
            };
            let field = if inside {
                if slot < shape.start || slot >= shape.words {
                    return None;
                }
                va + slot as u64 * 4
            } else {
                let prop = pointer(self.base, self.word(va + 4)?)?;
                let head = self.read(prop, 8)?;
                let count = (u32_at(&head, 4)? >> 1 & 1023) as usize;
                if slot < 2 || slot - 2 >= count {
                    return None;
                }
                prop + slot as u64 * 4
            };
            if let Some(v) = self.word(field) {
                out.insert(name, v);
            } else {
                self.unresolved += 1;
            }
        }
        Some(out)
    }
    // MobX observable objects store actual values in an administration object.
    // Its target backlink and named Map/ObservableValue fields are checked; no
    // accessor or JS proxy trap is evaluated.
    fn observable_fields(&mut self, va: u64, tag: u32) -> Option<BTreeMap<String, u32>> {
        let adm = pointer(self.base, self.word(va + 12)?)?;
        let af = self.fields(adm)?;
        if af.get("target_") != Some(&tag)
            || !self.string(*af.get("name_")?)?.starts_with("Observable")
        {
            return None;
        }
        let map = pointer(self.base, *af.get("values_")?)?;
        let map_tag = self.word(map)?;
        if self.map(map_tag)?.0 != self.layout.map_object_type {
            return None;
        }
        let table = pointer(self.base, self.word(map + 12)?)?;
        let b = self.read(table, 20)?;
        let (n, d, buckets) = (
            smi(u32_at(&b, 8)?)?,
            smi(u32_at(&b, 12)?)?,
            smi(u32_at(&b, 16)?)?,
        );
        if n < 0 || d < 0 || buckets <= 0 || n + d > 256 || buckets > 256 {
            return None;
        }
        let mut out = BTreeMap::new();
        for i in 0..n + d {
            let row = self.read(table + 20 + buckets as u64 * 4 + i as u64 * 12, 12)?;
            let Some(key) = self.string(u32_at(&row, 0)?) else {
                continue;
            };
            let value = pointer(self.base, u32_at(&row, 4)?)?;
            let fields = self.fields(value)?;
            if !fields.contains_key("observers_") || !fields.contains_key("name_") {
                return None;
            }
            if let Some(v) = fields.get("value_") {
                out.insert(key, *v);
            }
        }
        Some(out)
    }
    fn value(&mut self, tag: u32, path: &str, depth: usize) -> Value {
        self.nodes += 1;
        if depth > 28 || self.nodes > MAX_NODES {
            self.unresolved += 1;
            return json!({"unresolved":"object_budget"});
        }
        if let Some(n) = smi(tag) {
            return json!(n);
        }
        if !self.active.insert(tag) {
            self.unresolved += 1;
            return json!({"unresolved":"cycle"});
        }
        let result = self.value_inner(tag, path, depth);
        self.active.remove(&tag);
        result.unwrap_or_else(|| {
            self.unresolved += 1;
            json!({"unresolved":"missing_or_unsupported","virtual_address":pointer(self.base,tag)})
        })
    }
    fn value_inner(&mut self, tag: u32, path: &str, depth: usize) -> Option<Value> {
        let va = pointer(self.base, tag)?;
        let b = self.read(va, 20)?;
        let (ty, _) = self.map(u32_at(&b, 0)?)?;
        if ty < 128 {
            let text = self.string(tag)?;
            if self.tracing {
                self.strings.push(json!({"json_pointer":path,"virtual_address":va,"utf8_sha256":hex::encode(Sha256::digest(text.as_bytes())),"utf16_units":text.encode_utf16().count(),"representation":ty&7}));
            }
            return Some(json!(text));
        }
        if ty == 130 {
            return serde_json::Number::from_f64(f64::from_le_bytes(
                b.get(4..12)?.try_into().ok()?,
            ))
            .map(Value::Number);
        }
        if ty == 131 {
            return match self.string(u32_at(&b, 12)?)?.as_str() {
                "true" => Some(json!(true)),
                "false" => Some(json!(false)),
                "null" | "undefined" => Some(Value::Null),
                _ => None,
            };
        }
        if ty == self.layout.proxy_type {
            return Some(self.value(u32_at(&b, 8)?, path, depth + 1));
        }
        if ty == self.layout.array_type {
            let n = smi(u32_at(&b, 12)?)?;
            if !(0..=256).contains(&n) {
                return None;
            }
            let elements = pointer(self.base, u32_at(&b, 8)?)?;
            let head = self.read(elements, 8)?;
            let capacity = smi(u32_at(&head, 4)?)?;
            if capacity < n || capacity > 65536 {
                return None;
            }
            // FixedArray, not double elements. The map size is variable (zero).
            let (et, em) = self.map(u32_at(&head, 0)?)?;
            if et != 205 || em[4] != 0 {
                return None;
            }
            let raw = self.read(elements + 8, n as usize * 4)?;
            return Some(Value::Array(
                (0..n as usize)
                    .map(|i| {
                        self.value(
                            u32_at(&raw, i * 4).unwrap_or(0),
                            &format!("{path}/{i}"),
                            depth + 1,
                        )
                    })
                    .collect(),
            ));
        }
        if ty != 1057 {
            return None;
        }
        let mut fields = self.fields(va)?;
        if fields.is_empty() {
            fields = self.observable_fields(va, tag)?;
        }
        let mut obj = Map::new();
        for (key, val) in fields {
            let ptr = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
            obj.insert(key, self.value(val, &ptr, depth + 1));
        }
        Some(Value::Object(obj))
    }
    fn begin(&mut self) {
        self.tracing = true;
        self.reads.clear();
        self.strings.clear();
        self.nodes = 0;
        self.unresolved = 0;
        self.active.clear();
        self.trace_bytes = 0;
    }
}

fn discover_layout(mem: &dyn Memory, base: u64) -> Option<Layout> {
    // Read-only root maps of the supported layouts reside in the first page.
    // A self-referential MetaMap is required, not merely a coincidental type ID.
    let page = mem.read(base, 4096)?;
    for off in (0..4056).step_by(4) {
        if u32_at(&page, off)? != off as u32 + 1 {
            continue;
        }
        let Some(layout) = Layout::for_map(u16_at(&page, off + 8)?) else {
            continue;
        };
        if page[off + 4] == 10 {
            return Some(layout);
        }
    }
    None
}

fn external_table(
    heap: &mut Heap<'_>,
    pages: &BTreeMap<u64, u64>,
    samples: &[(u32, usize)],
    token: &CancellationToken,
) -> Result<Option<u64>> {
    if samples.len() < 4 {
        return Ok(None);
    }
    let mut candidates = BTreeSet::new();
    let mut checked = HashSet::new();
    let readable = |table: u64, handle: u32, n: usize| -> Option<bool> {
        let b = heap.mem.read(table + u64::from(handle) / 8, 8)?;
        let word = u64::from_le_bytes(b.try_into().unwrap_or_default());
        if word >> 56 != 0 || !heap.layout.data_tags.contains(&((word >> 49 & 127) as u8)) {
            return Some(false);
        }
        let text = heap.mem.read(word & 0xffff_ffff_ffff, n)?;
        Some(text.iter().all(|b| (32..127).contains(b)))
    };
    // A missing target page invalidates that sample, not every other handle.
    // Multiple seeds also allow the first table segment itself to be absent.
    // Visit each resident page once for all seeds. One whole-process pass per
    // seed would evict the bounded cache and consume the read budget before
    // recovering any objects from larger renderers.
    for &page in pages.keys() {
        token.check_cancelled()?;
        for &(seed, length) in samples.iter().take(4) {
            let rel = u64::from(seed) / 8;
            let off = rel & 4095;
            let Some(table) = (page + off).checked_sub(rel) else {
                continue;
            };
            if checked.contains(&table) || readable(table, seed, length) != Some(true) {
                continue;
            }
            checked.insert(table);
            let mut valid = HashSet::new();
            let mut conflicting = false;
            for &(handle, n) in samples {
                match readable(table, handle, n) {
                    Some(true) => {
                        valid.insert(handle);
                    }
                    Some(false) => {
                        conflicting = true;
                        break;
                    }
                    None => {}
                }
            }
            if !conflicting && valid.len() >= 4 {
                candidates.insert(table);
            }
            if candidates.len() > 1 {
                return Ok(None);
            }
        }
    }
    Ok(candidates.first().copied())
}

fn candidate(keys: &HashSet<&str>, app: &str) -> bool {
    (keys.contains("role") && (keys.contains("content") || keys.contains("parts")))
        || (keys.contains("messages") && keys.contains("option"))
        || (app == "千问"
            && (keys.contains("chatRound") && keys.contains("answer")
                || keys.contains("questions") && keys.contains("sessionId")
                || keys.contains("reqId") && keys.contains("content") && keys.contains("status")))
        || (app == "豆包"
            && keys.contains("conversation_id")
            && keys.contains("user_type")
            && (keys.contains("content_blocks_v2") || keys.contains("content_block")))
        || (matches!(app, "WorkBuddy" | "CodeBuddy")
            && keys.contains("sessionId")
            && keys.contains("json")
            && keys.contains("kind"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn analyze(
    session: &AnalysisSession,
    space: &X64AddressSpace<'_>,
    pid: u64,
    eprocess: u64,
    path: Option<&str>,
    app: &str,
    token: &CancellationToken,
    report: &mut ApplicationReport,
) -> Result<()> {
    let dtb = space.directory_table_base();
    let (pages, failures, truncated) = resident_pages(session.image(), dtb, token)?;
    let resident = Resident {
        image: session.image(),
        space,
        pages,
        token,
        bytes: Cell::new(0),
        exhausted: Cell::new(false),
        cache: RefCell::new(HashMap::new()),
    };
    let bases: BTreeSet<_> = resident.pages.keys().map(|v| v & !0xffff_ffff).collect();
    let sid = format!("ai_v8_heap:{pid}:{eprocess:#x}");
    let (mut cages, mut roots, mut partial, mut accepted) = (0usize, 0usize, 0usize, 0usize);
    let mut roots_limited = false;
    let mut unresolved_external_tables = 0;
    for base in bases {
        token.check_cancelled()?;
        let Some(layout) = discover_layout(&resident, base) else {
            continue;
        };
        cages += 1;
        let mut heap = Heap::new(&resident, base, layout);
        let mut strings = vec![];
        let mut samples = vec![];
        let mut handles = HashSet::new();
        for (&va, _) in resident.pages.range(base..base + 0x1_0000_0000) {
            token.check_cancelled()?;
            let Some(page) = resident.read(va, 4096) else {
                continue;
            };
            for off in (0..4084).step_by(4) {
                let Some(tag) = u32_at(&page, off) else {
                    continue;
                };
                if tag & 3 != 1 {
                    continue;
                }
                let Some((ty, _)) = heap.map(tag) else {
                    continue;
                };
                let addr = va + off as u64;
                if ty < 128 {
                    let n = u32_at(&page, off + 8).unwrap_or(0) as usize;
                    if ty == 10
                        && (4..=64).contains(&n)
                        && samples.len() < 32
                        && let Some(b) = resident.read(addr + 16, 4)
                    {
                        let h = u32_at(&b, 0).unwrap_or(0);
                        if h != 0 && h & 63 == 0 && handles.insert(h) {
                            samples.push((h, n));
                        }
                    }
                    if ty & 7 == 0 && (24..=MAX_STRING).contains(&n) {
                        let ch = resident.read(addr + 12, 2);
                        if ch.as_ref().is_some_and(|b| {
                            matches!(b[0], b'{' | b'[') && (ty & 8 != 0 || b[1] == 0)
                        }) {
                            if strings.len() < MAX_ROOTS {
                                strings.push(addr);
                            } else {
                                roots_limited = true;
                            }
                        }
                    }
                }
            }
        }
        heap.ept = external_table(&mut heap, &resident.pages, &samples, token)?;
        if samples.len() >= 4 && heap.ept.is_none() {
            unresolved_external_tables += 1;
        }
        heap.shape_cache.clear();
        let mut candidates = vec![];
        // Once external descriptor names can be read, retain only schema
        // candidates. Counting all JSObjects would truncate busy renderer heaps.
        'objects: for &va in resident
            .pages
            .range(base..base + 0x1_0000_0000)
            .map(|(va, _)| va)
        {
            token.check_cancelled()?;
            let Some(page) = resident.read(va, 4096) else {
                continue;
            };
            for off in (0..4096).step_by(4) {
                let tag = u32_at(&page, off).unwrap_or(0);
                if tag & 3 != 1 {
                    continue;
                }
                let Some(shape) = heap.shape(tag) else {
                    continue;
                };
                let keys: HashSet<_> = shape.fields.iter().map(|f| f.0.as_str()).collect();
                if candidate(&keys, app) {
                    if candidates.len() < MAX_ROOTS {
                        candidates.push(va + off as u64);
                    } else {
                        roots_limited = true;
                        break 'objects;
                    }
                }
            }
        }
        candidates.extend(strings);
        for va in candidates {
            token.check_cancelled()?;
            if report.truncated || resident.exhausted.get() {
                break;
            }
            roots += 1;
            heap.begin();
            let mut value = heap.value((va - base + 1) as u32, "", 0);
            if let Some(s) = value.as_str() {
                if let Ok(v) = serde_json::from_str::<Value>(s) {
                    value = v;
                } else {
                    heap.tracing = false;
                    continue;
                }
            }
            let artifacts = ai::extract(&value, app);
            if artifacts.is_empty() {
                heap.tracing = false;
                continue;
            }
            let mut ranges = vec![];
            // Preserve the byte union without thousands of overlapping map
            // header reads. Adjacent reads merge only within a bounded range.
            let mut merged: Vec<(u64, usize)> = vec![];
            for &(start, n) in heap.reads.keys() {
                if let Some((previous, length)) = merged.last_mut()
                    && start <= *previous + *length as u64
                    && start + n as u64 - *previous <= (MAX_STRING * 2) as u64
                {
                    *length = (*length).max((start + n as u64 - *previous) as usize);
                } else {
                    merged.push((start, n));
                }
            }
            let mut hashed = vec![];
            for (start, n) in merged {
                let Some(bytes) = resident.read(start, n) else {
                    // If the read budget was consumed, retain the original
                    // successful reads and their hashes instead of dropping proof.
                    hashed = heap
                        .reads
                        .iter()
                        .map(|(&(s, n), h)| (s, n, h.clone()))
                        .collect();
                    break;
                };
                hashed.push((start, n, hex::encode(Sha256::digest(&bytes))));
            }
            for (start, n, hash) in hashed {
                let mut segments = vec![];
                let mut off = 0;
                while off < n {
                    let a = start + off as u64;
                    let take = (n - off).min(4096 - (a & 4095) as usize);
                    if let Some(pa) = resident.pages.get(&(a & !4095)) {
                        let pa = pa + (a & 4095);
                        segments.push(json!({"virtual_address":a,"physical_address":pa,"byte_length":take,"source_location":session.image().source_location(pa)}));
                    }
                    off += take;
                }
                ranges.push(json!({"virtual_address":start,"byte_length":n,"sha256":hash,"segments":segments}));
            }
            if heap.unresolved > 0 {
                partial += 1;
            }
            let graph_id = format!("{pid}:{va:#x}");
            let mut retained_graph = false;
            for mut a in artifacts {
                a.data["recovery_method"] = json!("v8_heap");
                let duplicate = report.records.iter_mut().find(|r| {
                    r.source.starts_with("ai_v8_heap:")
                        && r.pid == Some(pid)
                        && r.artifact_kind == a.kind
                        && r.data == a.data
                });
                if let Some(r) = duplicate {
                    if let Some(copies) = r
                        .evidence
                        .get_mut("additional_roots")
                        .and_then(Value::as_array_mut)
                        && copies.len() < 256
                        && !copies.contains(&json!(va))
                    {
                        copies.push(json!(va));
                    }
                    continue;
                }
                accepted += 1;
                retained_graph = true;
                report.push(ApplicationRecord{artifact_kind:a.kind.into(),source:sid.clone(),pid:Some(pid),path:path.map(str::to_owned),
                    summary:a.data.get("text").or_else(||a.data.get("message")).and_then(Value::as_str).unwrap_or(a.kind).chars().take(180).collect(),
                    evidence:json!({"pid":pid,"eprocess":eprocess,"directory_table_base":dtb,"virtual_address":va,"cage_base":base,"layout_map_type":layout.map_type,
                        "external_pointer_table":heap.ept,"external_table_basis":"唯一候选表，至少四个不同句柄的类型和驻留文本一致；未证明 Isolate 归属",
                        "json_pointer":a.pointer,"heap_graph_id":graph_id,
                        "unresolved_nodes":heap.unresolved,"additional_roots":[],"attribution":"页表验证的进程驻留堆对象；引用关系重建，非生成者/发送成功证明"}),data:a.data});
            }
            if retained_graph {
                report.push(ApplicationRecord{artifact_kind:"ai_heap_graph".into(),source:sid.clone(),pid:Some(pid),path:path.map(str::to_owned),summary:format!("{app} 堆对象 {va:#x}"),
                    evidence:json!({"virtual_address":va,"pid":pid,"eprocess":eprocess,"directory_table_base":dtb,"graph_read_ranges":ranges,"string_objects":heap.strings}),
                    data:json!({"application":app,"heap_graph_id":graph_id,"unresolved_nodes":heap.unresolved,"semantics":"消息所引用对象图的读取区间、逐区间 SHA-256 和字符串来源；其他字段可能缺页或不支持"})});
            }
            heap.tracing = false;
        }
    }
    report.source(&sid,true,cages>0 && unresolved_external_tables==0 && !truncated && failures==0 && !roots_limited && !resident.exhausted.get() && partial==0,roots,
        if cages==0 {vec!["未识别到支持的 V8 压缩指针堆；仍保留该软件的其他来源，不能推定无对话".into()]}
        else if unresolved_external_tables>0 {vec!["外部字符串表未能唯一验证，依赖它的字段未恢复".into()]} else {vec![]},
        json!({"application":app,"pid":pid,"heap_cages":cages,"resident_pages":resident.pages.len(),"page_table_failures":failures,"mapping_truncated":truncated,
            "candidate_limit_reached":roots_limited,"read_budget_reached":resident.exhausted.get(),"bytes_read":resident.bytes.get(),"partial_graphs":partial,"recovered_records":accepted,"unresolved_external_tables":unresolved_external_tables}));
    token.check_cancelled()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(Vec<u8>);
    impl Memory for Fixture {
        fn read(&self, va: u64, n: usize) -> Option<Vec<u8>> {
            self.0
                .get(va as usize..(va as usize).checked_add(n)?)
                .map(<[u8]>::to_vec)
        }
    }
    impl Fixture {
        fn word(&mut self, a: usize, v: u32) {
            self.0[a..a + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn map(&mut self, a: usize, ty: u16, words: u8) {
            self.word(a, 0x101);
            self.0[a + 4] = words;
            self.0[a + 5] = 3;
            self.0[a + 8..a + 10].copy_from_slice(&ty.to_le_bytes());
        }
        fn string(&mut self, a: usize, s: &str) {
            self.word(a, 0x201);
            let units: Vec<_> = s.encode_utf16().collect();
            self.word(a + 8, units.len() as u32);
            for (i, c) in units.iter().enumerate() {
                self.0[a + 12 + i * 2..a + 14 + i * 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        fn new(profile: u16) -> Self {
            let mut f = Self(vec![0; 16384]);
            f.map(0x100, profile, 10);
            f.map(0x200, 32, 0);
            f
        }
    }
    #[test]
    fn segmented_strings_are_exact_and_missing_data_is_not_filled() {
        let mut f = Fixture::new(270);
        f.map(0x240, 33, 5);
        f.map(0x280, 35, 5);
        f.string(0x400, "前半😀");
        f.string(0x500, "后半");
        f.word(0x600, 0x241);
        f.word(0x608, 6);
        f.word(0x60c, 0x401);
        f.word(0x610, 0x501);
        f.word(0x700, 0x281);
        f.word(0x708, 2);
        f.word(0x70c, 0x601);
        f.word(0x710, 8);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        h.begin();
        assert_eq!(h.string(0x601).as_deref(), Some("前半😀后半"));
        assert_eq!(h.string(0x701).as_deref(), Some("后半"));
        assert!(h.reads.contains_key(&(0x40c, 8)));
        assert!(h.reads.contains_key(&(0x50c, 4)));
        drop(h);
        f.word(0x610, 0x10001);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert!(h.string(0x601).is_none());
        drop(h);
        f.word(0x610, 0x601);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert!(h.string(0x601).is_none());
    }
    #[test]
    fn property_offsets_distinguish_in_object_and_property_array_layouts() {
        for profile in [270, 275, 278] {
            let mut f = Fixture::new(profile);
            f.map(0x300, 1057, 4);
            f.word(0x30c, 2 << 10);
            f.word(0x318, 0x801);
            f.word(0x804, 0x0002_0002);
            f.string(0x900, "first");
            f.string(0xa00, "second");
            f.word(0x810, 0x901);
            f.word(0x81c, 0xa01);
            let d1 = if profile == 278 {
                (1 << 30) | (3 << 19) | 0x100
            } else {
                0x100
            };
            let d2 = if profile == 278 {
                (2 << 19) | 0x100
            } else {
                (1 << 19) | 0x100
            };
            f.word(0x814, d1 << 1);
            f.word(0x820, d2 << 1);
            f.word(0x400, 0x301);
            f.word(0x404, 0x501);
            f.word(0x40c, 14);
            f.word(0x504, 2);
            f.word(0x508, 22);
            let mut h = Heap::new(&f, 0, Layout::for_map(profile).unwrap());
            h.begin();
            assert_eq!(h.value(0x401, "", 0), json!({"first":7,"second":11}));
        }
    }
    #[test]
    fn external_strings_require_resident_table_and_correct_tag() {
        let mut f = Fixture::new(270);
        f.map(0x240, 10, 5);
        f.word(0x400, 0x241);
        f.word(0x408, 5);
        f.word(0x410, 64);
        f.0[0x1008..0x1010].copy_from_slice(&(0x1200u64 | (13 << 49)).to_le_bytes());
        f.0[0x1200..0x1205].copy_from_slice(b"hello");
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert!(h.string(0x401).is_none());
        h.ept = Some(0x1000);
        h.begin();
        assert_eq!(h.string(0x401).as_deref(), Some("hello"));
        assert!(h.reads.contains_key(&(0x1008, 8)));
        drop(h);
        f.0[0x1008..0x1010].copy_from_slice(&(0x1200u64 | (77 << 49)).to_le_bytes());
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        h.ept = Some(0x1000);
        assert!(h.string(0x401).is_none());
    }
    #[test]
    fn maps_require_a_verified_self_referential_meta_map() {
        let mut f = Fixture::new(270);
        assert!(discover_layout(&f, 0).is_some());
        f.string(0x400, "message");
        f.word(0x100, 0x301);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert!(h.string(0x401).is_none());
        assert!(discover_layout(&f, 0).is_none());
    }
    #[test]
    fn external_table_tolerates_missing_sample_pages_but_rejects_ambiguity() {
        let mut f = Fixture::new(270);
        let samples: Vec<_> = (1..=6).map(|i| (i * 64, 5)).collect();
        for (i, _) in samples.iter().enumerate() {
            let destination = if i == 0 { 0x8000 } else { 0x3000 + i * 16 };
            f.0[0x1008 + i * 8..0x1010 + i * 8]
                .copy_from_slice(&(destination as u64 | (13 << 49)).to_le_bytes());
            if i != 0 {
                f.0[destination..destination + 5].copy_from_slice(b"hello");
            }
        }
        let pages = BTreeMap::from([(0, 0), (0x1000, 0x1000), (0x2000, 0x2000), (0x3000, 0x3000)]);
        let token = CancellationToken::default();
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert_eq!(
            external_table(&mut h, &pages, &samples, &token).unwrap(),
            Some(0x1000)
        );
        drop(h);
        // Four plausible strings do not outweigh a resident conflicting tag.
        f.0.copy_within(0x1008..0x1030, 0x2008);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert_eq!(
            external_table(&mut h, &pages, &samples, &token).unwrap(),
            Some(0x1000)
        );
        drop(h);
        f.0.copy_within(0x1008..0x1038, 0x2008);
        let mut h = Heap::new(&f, 0, Layout::for_map(270).unwrap());
        assert_eq!(
            external_table(&mut h, &pages, &samples, &token).unwrap(),
            None
        );
    }
    #[test]
    fn external_table_fits_one_pass_budget_with_a_small_page_cache() {
        struct Bounded {
            bytes: Fixture,
            cache: RefCell<std::collections::VecDeque<u64>>,
            misses: Cell<usize>,
        }
        impl Memory for Bounded {
            fn read(&self, va: u64, n: usize) -> Option<Vec<u8>> {
                let bytes = self.bytes.read(va, n)?;
                let page = va & !4095;
                let mut cache = self.cache.borrow_mut();
                if !cache.contains(&page) {
                    self.misses.set(self.misses.get() + 1);
                    if self.misses.get() > 160 {
                        return None;
                    }
                    if cache.len() == 8 {
                        cache.pop_front();
                    }
                    cache.push_back(page);
                }
                Some(bytes)
            }
        }
        let mut f = Fixture(vec![0; 0x80000]);
        let samples: Vec<_> = (1..=6).map(|i| (i * 64, 5)).collect();
        for (i, _) in samples.iter().enumerate() {
            f.0[0x70008 + i * 8..0x70010 + i * 8]
                .copy_from_slice(&(0x71000u64 | (13 << 49)).to_le_bytes());
        }
        f.0[0x71000..0x71005].copy_from_slice(b"hello");
        let memory = Bounded {
            bytes: f,
            cache: RefCell::new(Default::default()),
            misses: Cell::new(0),
        };
        let pages = (0..0x80000).step_by(4096).map(|p| (p, p)).collect();
        let mut h = Heap::new(&memory, 0, Layout::for_map(270).unwrap());
        assert_eq!(
            external_table(&mut h, &pages, &samples, &CancellationToken::default()).unwrap(),
            Some(0x70000)
        );
        assert!(memory.misses.get() <= 160);
    }
}

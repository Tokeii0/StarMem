//! Public-PDB-derived layouts, gated by the captured module's exact RSDS identity.
//! These RVAs are module-relative; no case PID, virtual base or recovered text is embedded.
//! See docs/CLIPBOARD_HISTORY.md before adding another layout.

use crate::symbols::CodeViewRecord;

pub(super) struct CodeCheck {
    pub name: &'static str,
    pub rva: u64,
    pub bytes: &'static [u8],
}

pub(super) struct HistoryLayout {
    pub id: &'static str,
    pub textinput_key: &'static str,
    pub combase_key: &'static str,
    pub control_vtables: &'static [u64],
    pub model_vtables: &'static [u64],
    pub vector_vtables: &'static [u64],
    pub item_vtables: &'static [u64],
    pub control_model: usize,
    pub model_items: usize,
    pub vector_storage: usize,
    pub item_text: usize,
    pub item_timestamp: usize,
    pub item_id: usize,
    pub item_type: usize,
    pub textinput_code: &'static [CodeCheck],
    pub combase_code: &'static [CodeCheck],
}

// TextInput.dll 125.1700.0.0. Public PDB has no TPI; field offsets were verified
// against the getters/ABI thunks below, not inferred from adjacent strings.
pub(super) static LAYOUT: HistoryLayout = HistoryLayout {
    id: "textinput-125.1700.0.0-x64-v1",
    textinput_key: "F52D82D0FDCA4BBD81CE0CDB11A665B21",
    combase_key: "BB9940AC1CD2BA87FF0FF664A78A86AF1",
    control_vtables: &[0xb4f4a0, 0xb4f510, 0xb4f550],
    model_vtables: &[0xb52320, 0xb52238, 0xb52268, 0xb521a8],
    vector_vtables: &[0xb512c8, 0xb51318, 0xb51528, 0xb51568],
    item_vtables: &[0xb52fc8, 0xb52f58, 0xb52f88, 0xb532f8, 0xb53348, 0xb532a0, 0xb532c8],
    control_model: 0x148,
    model_items: 0x88,
    vector_storage: 0x60,
    item_text: 0x50,
    item_timestamp: 0x88,
    item_id: 0x3c,
    item_type: 0x38,
    textinput_code: &[
        CodeCheck { name: "ClipboardControl.Model", rva: 0x234720,
            bytes: b"\x40\x53\x48\x83\xec\x20\x48\x8b\x99\x48\x01\x00\x00" },
        CodeCheck { name: "ClipboardControlModel.ClipboardItems", rva: 0x23cc00,
            bytes: b"\x40\x53\x48\x83\xec\x20\x48\x8b\x99\x88\x00\x00\x00" },
        CodeCheck { name: "ClipboardViewItem.Text", rva: 0x14ff5,
            bytes: b"\x48\x8b\x49\x50" },
        CodeCheck { name: "ClipboardViewItem.ItemType", rva: 0x14830,
            bytes: b"\x8b\x41\x38\xc3" },
        CodeCheck { name: "ClipboardViewItem.Id", rva: 0x23c5b0,
            bytes: b"\x0f\x10\x41\x3c\x48\x8b\xc2\xf3\x0f\x7f\x02\xc3" },
        CodeCheck { name: "ClipboardViewItem.UniversalTimestamp", rva: 0x266cb0,
            bytes: b"\x48\x8b\x81\x88\x00\x00\x00\xc3" },
        CodeCheck { name: "Vector.ABI.Size.thunk", rva: 0xb1950,
            bytes: b"\x48\x83\xe9\x08\xe9\x6f\x6c\xfe\xff" },
        CodeCheck { name: "Vector.Size.thunk", rva: 0xb29b0,
            bytes: b"\x48\x83\xe9\x08\xe9\x57\x00\xff\xff" },
        CodeCheck { name: "Vector.Size.storage", rva: 0xa2a10,
            bytes: b"\x48\x8b\x41\x60\x48\x8b\x48\x08\x48\x2b\x08\x48\xc1\xf9\x03\x8b\xc1\xc3" },
    ],
    combase_code: &[
        CodeCheck { name: "WindowsGetStringLen", rva: 0x6b1c0,
            bytes: b"\x33\xc0\x48\x85\xc9\x74\x03\x8b\x41\x04\xc3" },
        CodeCheck { name: "WindowsGetStringRawBuffer", rva: 0xc4740,
            bytes: b"\x48\x85\xc9\x74\x1a\x48\x8b\x41\x10\x48\x85\xd2\x74\x0f\x45\x33\xc0\x48\x85\xc9\x74\x04\x44\x8b\x41\x04\x44\x89\x02\xc3" },
        CodeCheck { name: "WindowsDuplicateString.owned_refcount", rva: 0xa9bc5,
            bytes: b"\xf6\x01\x01\x75\x1a\xf0\xff\x41\x18" },
    ],
};

pub(super) fn select(
    textinput: &CodeViewRecord,
    combase: &CodeViewRecord,
) -> Option<&'static HistoryLayout> {
    (textinput.pdb_name.eq_ignore_ascii_case("TextInput.pdb")
        && textinput
            .symbol_key
            .eq_ignore_ascii_case(LAYOUT.textinput_key)
        && combase.pdb_name.eq_ignore_ascii_case("combase.pdb")
        && combase.symbol_key.eq_ignore_ascii_case(LAYOUT.combase_key))
    .then_some(&LAYOUT)
}

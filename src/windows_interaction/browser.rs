//! Reconstruct the stored SessionService state, keeping its command offsets.
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Tab {
    window: Option<i64>,
    index: Option<i64>,
    selected: Option<i64>,
    navigations: BTreeMap<i64, Value>,
    offsets: Vec<u64>,
}

pub(super) fn stored_tabs(commands: &[Value], stream_complete: bool) -> Vec<Value> {
    let mut tabs = BTreeMap::<i64, Tab>::new();
    let mut selected = BTreeMap::<i64, i64>::new();
    let mut active = None;
    let mut coverage = stream_complete;
    for command in commands {
        let Some(id) = command["command_id"].as_u64() else {
            coverage = false;
            continue;
        };
        let first = command["first_id"].as_i64();
        let second = command["second_id_or_index"].as_i64();
        let tab_id = match id {
            0 => second,
            2 | 7 => first,
            5 | 6 | 11 | 24 => command["tab_id"].as_i64(),
            _ => None,
        };
        if let Some(tab_id) = tab_id {
            let tab = tabs.entry(tab_id).or_default();
            if let Some(offset) = command["file_offset"].as_u64() {
                tab.offsets.push(offset);
            }
            match id {
                0 => tab.window = first,
                2 => tab.index = second,
                7 => tab.selected = second,
                6 => {
                    if let Some(index) = command["navigation_index"].as_i64() {
                        tab.navigations.insert(index, command.clone());
                    }
                }
                5 => {
                    if let Some(index) = command["index_or_count"].as_i64() {
                        tab.navigations.retain(|n, _| *n < index);
                    }
                }
                11 | 24 => {
                    let index = if id == 11 {
                        Some(0)
                    } else {
                        command["index"].as_i64()
                    };
                    let count = if id == 11 {
                        command["index_or_count"].as_i64()
                    } else {
                        command["count"].as_i64()
                    };
                    if let (Some(index), Some(count)) = (index, count) {
                        if index >= 0
                            && count > 0
                            && let Some(end) = index.checked_add(count)
                        {
                            let old = std::mem::take(&mut tab.navigations);
                            for (n, mut value) in old {
                                if n < index {
                                    tab.navigations.insert(n, value);
                                } else if n >= end {
                                    value["navigation_index"] = json!(n - count);
                                    tab.navigations.insert(n - count, value);
                                }
                            }
                        } else {
                            coverage = false;
                        }
                    } else {
                        coverage = false;
                    }
                }
                _ => (),
            }
        } else if id == 8 {
            if let (Some(window), Some(index)) = (first, second) {
                selected.insert(window, index);
            }
        } else if matches!(id, 3 | 16) {
            if let Some(tab) = command["id"].as_i64() {
                tabs.remove(&tab);
            }
        } else if matches!(id, 4 | 17) {
            if let Some(window) = command["id"].as_i64() {
                tabs.retain(|_, tab| tab.window != Some(window));
                selected.remove(&window);
            }
        } else if id == 20 {
            active = command["window_id"].as_i64();
        } else if command["event"] == "unparsed_command" {
            coverage = false;
        }
    }
    tabs.into_iter().map(|(id,tab)| {
        let current=tab.selected.and_then(|index|tab.navigations.get(&index));
        let selected_tab=tab.window.zip(tab.index).and_then(|(window,index)|selected.get(&window).map(|n|*n==index));
        json!({"tab_id":id,"window_id":tab.window,"tab_index":tab.index,"selected_navigation_index":tab.selected,
            "current_navigation":current,"selected_tab":selected_tab,"active_window":tab.window.zip(active).map(|(a,b)|a==b),
            "navigations":tab.navigations.values().collect::<Vec<_>>(),"source_command_offsets":tab.offsets,
            "all_commands_interpreted":coverage,"semantic":"reconstructed_stored_session_not_live_visibility"})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stored_state_applies_navigation_updates_selection_pruning_and_closure() {
        let mut commands = vec![
            json!({"command_id":0,"first_id":10,"second_id_or_index":20}),
            json!({"command_id":2,"first_id":20,"second_id_or_index":0}),
            json!({"command_id":6,"tab_id":20,"navigation_index":0,"url":"https://old"}),
            json!({"command_id":6,"tab_id":20,"navigation_index":1,"url":"https://current"}),
            json!({"command_id":6,"tab_id":20,"navigation_index":1,"url":"https://updated"}),
            json!({"command_id":7,"first_id":20,"second_id_or_index":1}),
            json!({"command_id":8,"first_id":10,"second_id_or_index":0}),
        ];
        let tabs = stored_tabs(&commands, true);
        assert_eq!(tabs[0]["current_navigation"]["url"], "https://updated");
        assert_eq!(tabs[0]["selected_tab"], true);
        commands.push(json!({"command_id":11,"tab_id":20,"index_or_count":1}));
        let tabs = stored_tabs(&commands, true);
        assert_eq!(tabs[0]["navigations"].as_array().unwrap().len(), 1);
        assert!(tabs[0]["current_navigation"].is_null());
        commands.push(json!({"command_id":16,"id":20}));
        assert!(stored_tabs(&commands, true).is_empty());
    }
}

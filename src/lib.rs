/// StarMem crate 的语义版本，供宿主记录产物来源并做缓存兼容性判断。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 当前 StarMem 源码快照的内容构建标识。
///
/// 与语义版本配合使用，避免两个尚未发布、版本号相同的开发构建互认缓存。
pub const BUILD_ID: &str = env!("STARMEM_BUILD_ID");

/// 面向进程内宿主的公共分析/产物契约版本。
///
/// 当可序列化结果或宿主调用语义出现不兼容变化时必须递增。
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const INTEGRATION_API_VERSION: u32 = 5;
pub const RAW_OBJECT_SCHEMA_VERSION: u32 = raw_objects::RAW_OBJECT_SCHEMA_VERSION;

pub mod accounts;
pub mod acquisition;
pub mod address;
pub mod api;
pub mod applications;
pub mod artifacts;
pub mod browser_artifacts;
pub mod browser_pages;
pub mod browser_session;
pub mod build_info;
pub mod cancellation;
pub mod clipboard;
pub mod cobaltstrike;
pub mod collection;
pub mod command_registry;
pub mod cookies;
pub mod csv_report;
pub mod database;
pub mod dns_scan;
pub mod downloads;
pub mod eventlog;
pub mod evidence;
pub mod image;
pub mod image_avml;
pub mod image_qevm;
pub mod image_xen;
pub mod linux;
pub mod linux_bash;
pub mod linux_files;
pub mod linux_info;
pub mod linux_ir;
pub mod linux_kernel_plugins;
pub mod linux_network;
pub mod linux_pagecache;
pub mod linux_passwd;
pub mod linux_process;
pub mod linux_symbols;
pub mod linux_system_map;
pub mod live;
pub mod live_windows;
pub mod macos;
pub mod mouse_history;
pub mod output_policy;
pub mod packet_scan;
pub mod process_dump;
pub mod profile;
pub mod progress;
pub mod qq;
pub mod raw_objects;
pub mod registry;
pub mod resources;
pub mod scan;
pub mod session;
pub mod sqlite_recover;
pub mod symbols;
pub mod system;
pub mod terminal_history;
pub mod wechat;
pub mod wechat_chat;
pub mod windows;
pub mod windows_execution;
pub mod windows_interaction;
pub mod windows_recent_files;
pub mod windows_timeline;

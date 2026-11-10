//! External-consumer contract: this test imports only the stable host facade
//! (plus the root compatibility constant) exactly as LovelyMem will.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, to_value};
use starmem::INTEGRATION_API_VERSION;
use starmem::api::{
    ERROR_API_VERSION_MISMATCH, ExecutionContext, HostImageOptions, HostSymbolOptions,
    OpenSessionRequest, PlatformHint, ProcessStringArguments, ProgressEvent, RunRequest, Session,
    capabilities, command_catalog,
};

#[test]
fn stable_facade_exposes_catalog_and_serializable_requests() {
    let capabilities = capabilities();
    assert_eq!(
        capabilities.integration_api_version,
        INTEGRATION_API_VERSION
    );
    assert_eq!(capabilities.host_api_schema_version, 1);
    assert!(
        capabilities
            .runnable_command_ids
            .iter()
            .any(|command| command == "windows.process-string")
    );

    let catalog = command_catalog().unwrap();
    assert!(catalog.by_id("pslist").is_some());
    assert!(catalog.by_id("windows.process-string").is_some());

    let arguments = to_value(ProcessStringArguments::new("StarMem"))
        .unwrap()
        .as_object()
        .cloned()
        .unwrap_or_else(Map::new);
    let request = RunRequest {
        integration_api_version: INTEGRATION_API_VERSION,
        request_id: "external-consumer-1".to_owned(),
        command_id: "windows.process-string".to_owned(),
        arguments,
    };
    let value = to_value(request).unwrap();
    assert_eq!(value["integration_api_version"], Value::from(5));
    assert_eq!(value["arguments"]["text"], "StarMem");
}

#[test]
fn version_handshake_rejects_before_evidence_io() {
    let events = Arc::new(Mutex::new(Vec::<ProgressEvent>::new()));
    let captured = Arc::clone(&events);
    let context = ExecutionContext::default().with_progress(Arc::new(move |event| {
        captured.lock().unwrap().push(event);
    }));
    let result = Session::open(
        OpenSessionRequest {
            integration_api_version: INTEGRATION_API_VERSION + 1,
            request_id: "wrong-version".to_owned(),
            image_path: PathBuf::from("must-not-be-opened.mem"),
            platform: PlatformHint::Auto,
            image: HostImageOptions::default(),
            symbols: HostSymbolOptions::default(),
        },
        &context,
    );
    let error = match result {
        Ok(_) => panic!("an incompatible API version must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code, ERROR_API_VERSION_MISMATCH);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn stable_host_types_are_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Session>();
    assert_send_sync::<ExecutionContext>();
}

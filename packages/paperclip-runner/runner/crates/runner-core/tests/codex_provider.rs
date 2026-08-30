use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use paperclip_runner_core::codex_provider::{
    CodexProvider, CodexProviderConfig, CodexProviderEvent,
};
use paperclip_runner_core::durable::{Command, CommandExecutor, DurableRunnerError, PolledEvent};
use paperclip_runner_core::provider_backend::CodexCommandExecutor;
use paperclip_runner_core::provider_bridge::{AuthorizedTool, ToolResult};
use paperclip_runner_core::provider_events::normalize_codex_notification;
use serde_json::{json, Value};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

fn temporary_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "paperclip-runner-codex-{label}-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("create Codex integration-test directory");
    directory
}

fn provider_config(directory: &Path, switches: &[&str]) -> CodexProviderConfig {
    let mut args = vec![
        "--state-file".to_owned(),
        directory
            .join("fake-state.json")
            .to_string_lossy()
            .into_owned(),
        "--call-log".to_owned(),
        directory.join("calls.log").to_string_lossy().into_owned(),
    ];
    args.extend(switches.iter().map(|value| (*value).to_owned()));
    CodexProviderConfig {
        provider: "codex".to_owned(),
        driver: "codex_app_server".to_owned(),
        provider_version: "fake-1".to_owned(),
        command: PathBuf::from(env!("CARGO_BIN_EXE_fake-codex-app-server")),
        args,
        cwd: std::env::current_dir()
            .expect("resolve test cwd")
            .to_string_lossy()
            .into_owned(),
        model: Some("test-model".to_owned()),
        provider_session_id: None,
        instructions: "Stay inside the test workspace.".to_owned(),
        approval_policy: "never".to_owned(),
    }
}

fn task_context_tool() -> AuthorizedTool {
    AuthorizedTool {
        operation_id: "get_task_context".to_owned(),
        version: 1,
        description: "Read task context.".to_owned(),
        input_schema: json!({"type": "object"}),
        response_schema: json!({"type": "object"}),
    }
}

fn command(id: &str, sequence: u64, command_type: &str, payload: Value) -> Command {
    Command {
        schema: "paperclip.prp.command.v1".to_owned(),
        command_id: id.to_owned(),
        controller_seq: sequence,
        command_type: command_type.to_owned(),
        issued_at: "2026-08-24T00:00:00.000Z".to_owned(),
        deadline_at: None,
        precondition: None,
        payload,
    }
}

fn call_count(directory: &Path, method: &str) -> usize {
    fs::read_to_string(directory.join("calls.log"))
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == method)
        .count()
}

fn poll_and_ack(
    executor: &mut CodexCommandExecutor,
) -> Result<Vec<PolledEvent>, DurableRunnerError> {
    let events = executor.poll_events()?;
    executor.acknowledge_events(events.len())?;
    Ok(events)
}

#[test]
fn codex_transport_buffers_notifications_while_waiting_for_responses() {
    let directory = temporary_directory("buffering");
    let config = provider_config(&directory, &["--notification-before-response"]);
    let mut provider = CodexProvider::start(&config, None).expect("start fake Codex provider");
    let event = provider
        .poll()
        .expect("poll buffered notification")
        .expect("buffered notification is available");
    let CodexProviderEvent::Notification { method, params } = event else {
        panic!("expected the pre-response warning notification");
    };
    assert_eq!(method, "warning");
    let normalized = normalize_codex_notification(&method, &params);
    assert_eq!(normalized[0].event_type, "provider.notice.recorded");

    provider
        .start_turn("Complete the fake task.", &config.cwd)
        .expect("start provider turn");
    let mut event_types = Vec::new();
    for _ in 0..16 {
        if let Some(CodexProviderEvent::Notification { method, params }) =
            provider.poll().expect("poll provider event")
        {
            event_types.extend(
                normalize_codex_notification(&method, &params)
                    .into_iter()
                    .map(|event| event.event_type),
            );
        }
        if event_types.iter().any(|event| event == "turn.completed") {
            break;
        }
    }
    assert!(event_types.iter().any(|event| event == "turn.started"));
    assert!(event_types.iter().any(|event| event == "item.completed"));
    assert!(event_types.iter().any(|event| event == "usage.reported"));
    assert!(event_types.iter().any(|event| event == "turn.completed"));
    provider.shutdown().expect("stop provider");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_dynamic_tool_round_trips_through_the_provider_boundary() {
    let directory = temporary_directory("dynamic-tool");
    let config = provider_config(&directory, &["--require-dynamic-tool", "--emit-tool-call"]);
    let mut provider = CodexProvider::start_with_tools(&config, [task_context_tool()], None)
        .expect("start Codex with an authorized tool");
    provider
        .start_turn("Inspect the fake task.", &config.cwd)
        .expect("start provider turn");

    let mut delivered = false;
    let mut completed = false;
    for _ in 0..32 {
        match provider.poll().expect("poll semantic tool event") {
            Some(CodexProviderEvent::ToolCall {
                call_id,
                operation_id,
                input,
            }) => {
                assert_eq!(call_id, "semantic-call-1");
                assert_eq!(operation_id, "get_task_context");
                assert_eq!(input, json!({}));
                assert!(provider
                    .deliver_tool_result(&ToolResult {
                        call_id: call_id.clone(),
                        operation_id: "another_operation".to_owned(),
                        result: json!({"ok": true}),
                        is_error: false,
                    })
                    .is_err());
                assert!(provider
                    .deliver_tool_result(&ToolResult {
                        call_id: call_id.clone(),
                        operation_id: operation_id.clone(),
                        result: json!({"value": "x".repeat(1024 * 1024)}),
                        is_error: false,
                    })
                    .is_err());
                provider
                    .deliver_tool_result(&ToolResult {
                        call_id,
                        operation_id,
                        result: json!({"ok": true, "task": {"id": "task-1"}}),
                        is_error: false,
                    })
                    .expect("deliver correlated semantic result");
                delivered = true;
            }
            Some(CodexProviderEvent::Notification { method, .. }) if method == "turn/completed" => {
                completed = true;
                break;
            }
            _ => {}
        }
    }
    assert!(delivered, "Codex emitted its authorized tool call");
    assert!(completed, "Codex completed after the semantic result");
    provider.shutdown().expect("stop provider");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_rejects_replay_of_a_completed_tool_call_id_in_the_same_turn() {
    let directory = temporary_directory("completed-tool-call-replay");
    let config = provider_config(
        &directory,
        &[
            "--require-dynamic-tool",
            "--emit-tool-call",
            "--replay-completed-tool-call",
        ],
    );
    let mut provider = CodexProvider::start_with_tools(&config, [task_context_tool()], None)
        .expect("start Codex with an authorized tool");
    provider
        .start_turn("Inspect the fake task once.", &config.cwd)
        .expect("start provider turn");

    let first_call = (0..32)
        .find_map(|_| match provider.poll().expect("poll first tool call") {
            Some(CodexProviderEvent::ToolCall {
                call_id,
                operation_id,
                ..
            }) => Some((call_id, operation_id)),
            _ => None,
        })
        .expect("observe the first semantic tool call");
    provider
        .deliver_tool_result(&ToolResult {
            call_id: first_call.0,
            operation_id: first_call.1,
            result: json!({"ok": true, "task": {"id": "task-1"}}),
            is_error: false,
        })
        .expect("deliver the first semantic result");

    let replay_error = (0..32)
        .find_map(|_| provider.poll().err())
        .expect("same-turn replay of the completed call id is rejected");
    assert!(
        replay_error
            .to_string()
            .contains("reused a completed tool call id"),
        "unexpected replay error: {replay_error}"
    );

    let _ = provider.shutdown();
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_completion_cancels_pending_tool_request_before_releasing_capacity() {
    let directory = temporary_directory("completed-tool-call");
    let config = provider_config(
        &directory,
        &[
            "--require-dynamic-tool",
            "--emit-tool-call",
            "--complete-after-tool-call",
        ],
    );
    let mut provider = CodexProvider::start_with_tools(&config, [task_context_tool()], None)
        .expect("start Codex with an authorized tool");
    provider
        .start_turn("Complete without waiting for the tool result.", &config.cwd)
        .expect("start provider turn");

    let first_call = (0..32)
        .find_map(
            |_| match provider.poll().expect("poll first provider turn") {
                Some(CodexProviderEvent::ToolCall {
                    call_id,
                    operation_id,
                    ..
                }) => Some((call_id, operation_id)),
                _ => None,
            },
        )
        .expect("observe the first semantic tool call");
    let completed = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll first completion"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(completed, "Codex completed with a tool call still pending");
    for _ in 0..100 {
        if call_count(&directory, "tool-response:failure") == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(
        call_count(&directory, "tool-response:failure"),
        1,
        "Paperclip explicitly resolves the provider RPC as cancelled",
    );
    assert!(provider
        .deliver_tool_result(&ToolResult {
            call_id: first_call.0,
            operation_id: first_call.1,
            result: json!({"ok": true}),
            is_error: false,
        })
        .is_err());

    provider
        .start_turn("Reuse the released provider identities.", &config.cwd)
        .expect("start another provider turn");
    let second_call = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll second provider turn"),
            Some(CodexProviderEvent::ToolCall { call_id, .. })
                if call_id == "semantic-call-1"
        )
    });
    assert!(second_call, "the next turn can reuse the released call id");

    provider.shutdown().expect("stop provider");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_completion_survives_failed_pending_request_cancellation() {
    let directory = temporary_directory("completed-tool-call-provider-exit");
    let config = provider_config(
        &directory,
        &[
            "--require-dynamic-tool",
            "--emit-tool-call",
            "--complete-after-tool-call",
            "--exit-after-tool-call-completion",
        ],
    );
    let mut provider = CodexProvider::start_with_tools(&config, [task_context_tool()], None)
        .expect("start Codex with an authorized tool");
    provider
        .start_turn("Complete and exit with a tool call pending.", &config.cwd)
        .expect("start provider turn");

    let call = (0..32)
        .find_map(|_| match provider.poll().expect("poll pending tool call") {
            Some(CodexProviderEvent::ToolCall {
                call_id,
                operation_id,
                ..
            }) => Some((call_id, operation_id)),
            _ => None,
        })
        .expect("observe the pending semantic tool call");
    std::thread::sleep(std::time::Duration::from_millis(50));

    let completed = (0..32).any(|_| {
        matches!(
            provider
                .poll()
                .expect("the received completion survives closed provider stdin"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(completed, "the terminal notification remains authoritative");
    assert!(provider
        .deliver_tool_result(&ToolResult {
            call_id: call.0,
            operation_id: call.1,
            result: json!({"ok": true}),
            is_error: false,
        })
        .is_err());

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn clean_idle_provider_exit_preserves_completed_turn_success() {
    let directory = temporary_directory("completion-output-clean-provider-exit");
    let config = provider_config(
        &directory,
        &[
            "--emit-post-completion-warning",
            "--exit-after-turn-completion",
        ],
    );
    let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
    provider
        .start_turn("Complete, produce idle output, then exit.", &config.cwd)
        .expect("start provider turn");

    let mut completion_seen = false;
    let mut post_completion_output_seen = false;
    let mut clean_exit = None;
    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < exit_deadline {
        match provider.poll().expect("poll completion and clean exit") {
            Some(CodexProviderEvent::Notification { method, .. }) => {
                completion_seen |= method == "turn/completed";
                post_completion_output_seen |= completion_seen && method == "warning";
            }
            Some(CodexProviderEvent::Exited {
                success,
                completed_turn_authoritative,
                completion_reconciles_exit,
                ..
            }) => {
                clean_exit = Some((
                    success,
                    completed_turn_authoritative,
                    completion_reconciles_exit,
                ));
                break;
            }
            Some(_) | None => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert!(completion_seen);
    assert!(post_completion_output_seen);
    assert_eq!(clean_exit, Some((true, true, false)));
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn clean_provider_exit_does_not_refail_a_completed_turn() {
    let directory = temporary_directory("completion-then-clean-exit");
    let config = provider_config(
        &directory,
        &[
            "--emit-post-completion-warning",
            "--exit-after-turn-completion",
            "--exit-after-thread-read",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Complete before exiting cleanly."}),
        ))
        .expect("start provider turn");

    let mut event_types = Vec::new();
    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < exit_deadline {
        event_types.extend(
            poll_and_ack(&mut executor)
                .expect("poll completion and clean exit")
                .into_iter()
                .map(|event| event.event_type),
        );
        if event_types.iter().any(|event| event == "turn.completed")
            && event_types
                .iter()
                .any(|event| event == "provider.notice.recorded")
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // The warning is ordered after the terminal and before the clean exit, so
    // seeing it proves the completed process entered the idle/output path that
    // previously cleared expected shutdown authority.
    assert!(event_types.iter().any(|event| event == "turn.completed"));
    assert!(event_types
        .iter()
        .any(|event| event == "provider.notice.recorded"));
    for _ in 0..32 {
        event_types.extend(
            poll_and_ack(&mut executor)
                .expect("poll after provider exit")
                .into_iter()
                .map(|event| event.event_type),
        );
    }

    assert!(!event_types.iter().any(|event| event == "session.failed"));
    let persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after clean exit"),
    )
    .expect("parse provider state after clean exit");
    assert_eq!(persisted["lifecycle"], "session_open");
    assert!(persisted["activeProviderTurnId"].is_null());

    drop(executor);
    let mut recovered = CodexCommandExecutor::new(&directory);
    let recovered_events = poll_and_ack(&mut recovered)
        .expect("poll clean exit from a freshly resumed completed thread");
    assert!(!recovered_events
        .iter()
        .any(|event| event.event_type == "session.failed"));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn post_completion_observation_does_not_hide_same_or_resumed_process_failure() {
    let directory = temporary_directory("completion-then-nonzero-exit");
    let config = provider_config(
        &directory,
        &[
            "--emit-post-completion-warning",
            "--fail-after-turn-completion",
            "--fail-after-turn-completion-delay-ms",
            "250",
            "--fail-after-thread-read",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Complete before exiting with an error."}),
        ))
        .expect("start provider turn");

    let mut event_types = Vec::new();
    let first_exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < first_exit_deadline {
        event_types.extend(
            poll_and_ack(&mut executor)
                .expect("poll completion and nonzero exit")
                .into_iter()
                .map(|event| event.event_type),
        );
        if event_types.iter().any(|event| event == "turn.completed")
            && event_types
                .iter()
                .any(|event| event == "provider.notice.recorded")
            && event_types.iter().any(|event| event == "session.failed")
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert!(event_types.iter().any(|event| event == "turn.completed"));
    assert!(event_types
        .iter()
        .any(|event| event == "provider.notice.recorded"));
    assert!(!event_types
        .iter()
        .any(|event| event == "session.reconciled"));
    assert!(event_types.iter().any(|event| event == "session.failed"));
    assert!(!event_types.iter().any(|event| event == "turn.failed"));
    let persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after nonzero exit"),
    )
    .expect("parse provider state after nonzero exit");
    assert_eq!(persisted["lifecycle"], "provider_exited");
    assert_eq!(persisted["completedTurnAuthoritative"], true);
    assert_eq!(persisted["providerProcessGeneration"], 1);
    assert_eq!(persisted["completedTurnProcessGeneration"], 1);

    // A fresh process restores the durable completed turn, probes it with
    // thread/read, and then exits nonzero. Recovery preserves the completed
    // run outcome, while the later idle provider failure remains visible.
    let mut recovered = CodexCommandExecutor::new(&directory);
    let mut recovered_event_types = Vec::new();
    let recovered_exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < recovered_exit_deadline {
        recovered_event_types.extend(
            poll_and_ack(&mut recovered)
                .expect("poll restored provider after idle crash")
                .into_iter()
                .map(|event| event.event_type),
        );
        if recovered_event_types
            .iter()
            .any(|event| event == "session.failed")
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(recovered_event_types
        .iter()
        .any(|event| event == "session.failed"));
    assert!(!recovered_event_types
        .iter()
        .any(|event| event == "turn.failed"));
    assert_eq!(
        recovered_event_types
            .iter()
            .filter(|event| event.as_str() == "session.reconciled")
            .count(),
        1,
        "recovery is reconciled once, but the resumed provider exit fails its session"
    );
    let recovered_persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after resumed exit"),
    )
    .expect("parse provider state after resumed exit");
    assert_eq!(recovered_persisted["lifecycle"], "provider_exited");
    assert_eq!(recovered_persisted["providerProcessGeneration"], 2);
    assert_eq!(recovered_persisted["completedTurnProcessGeneration"], 1);
    assert_eq!(call_count(&directory, "thread/read"), 1);

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn rejected_replacement_turn_start_preserves_result_and_exit_authority() {
    let directory = temporary_directory("completion-then-rejected-turn-start");
    let config = provider_config(&directory, &["--reject-second-turn-start"]);
    let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
    provider
        .start_turn("Complete the first turn.", &config.cwd)
        .expect("start first provider turn");
    let first_completed = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll first turn"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(
        first_completed,
        "observe the authoritative first completion"
    );

    provider
        .start_turn("Reject replacement work.", &config.cwd)
        .expect_err("the replacement turn/start returns a definite rejection");
    let mut buffered_notification_seen = false;
    let rejected_start_exit = (0..64).find_map(|_| {
        match provider
            .poll()
            .expect("poll exit after rejected replacement start")
        {
            Some(CodexProviderEvent::Notification { method, params })
                if method == "warning"
                    && params.get("message").and_then(Value::as_str)
                        == Some("buffered before replacement rejection") =>
            {
                buffered_notification_seen = true;
                None
            }
            Some(CodexProviderEvent::Exited {
                success,
                completed_turn_authoritative,
                completion_reconciles_exit,
                ..
            }) => Some((
                success,
                completed_turn_authoritative,
                completion_reconciles_exit,
            )),
            _ => None,
        }
    });
    assert!(buffered_notification_seen);
    assert_eq!(rejected_start_exit, Some((false, true, false)));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn rejected_replacement_turn_start_does_not_hide_contradictory_turn_evidence() {
    let directory = temporary_directory("completion-then-contradictory-rejection");
    let config = provider_config(
        &directory,
        &[
            "--reject-second-turn-start",
            "--emit-turn-before-rejected-second-start",
        ],
    );
    let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
    provider
        .start_turn("Complete the first turn.", &config.cwd)
        .expect("start first provider turn");
    let first_completed = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll first turn"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(
        first_completed,
        "observe the authoritative first completion"
    );

    provider
        .start_turn(
            "Reject replacement work after contradictory evidence.",
            &config.cwd,
        )
        .expect_err("the replacement turn/start returns a definite rejection");
    let duplicate_error = provider
        .start_turn(
            "Do not duplicate contradictory replacement work.",
            &config.cwd,
        )
        .expect_err("provider-work evidence makes the rejected response ambiguous");
    assert!(
        duplicate_error
            .to_string()
            .contains("unresolved ambiguous provider turn start"),
        "unexpected duplicate-start error: {duplicate_error}"
    );
    let mut contradictory_turn_seen = false;
    let rejected_start_exit = (0..64).find_map(|_| {
        match provider
            .poll()
            .expect("poll exit after contradictory replacement rejection")
        {
            Some(CodexProviderEvent::Notification { method, params })
                if method == "turn/started"
                    && params.pointer("/turn/id").and_then(Value::as_str)
                        == Some("provider-turn-contradiction") =>
            {
                contradictory_turn_seen = true;
                None
            }
            Some(CodexProviderEvent::Exited {
                success,
                completed_turn_authoritative,
                completion_reconciles_exit,
                ..
            }) => Some((
                success,
                completed_turn_authoritative,
                completion_reconciles_exit,
            )),
            _ => None,
        }
    });
    assert!(contradictory_turn_seen);
    assert_eq!(
        provider.active_provider_turn_id(),
        Some("provider-turn-contradiction")
    );
    assert_eq!(rejected_start_exit, Some((false, false, false)));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn ambiguous_or_dead_replacement_start_preserves_result_not_exit_authority() {
    for (label, switch) in [
        (
            "accepted-before-response",
            "--fail-after-accepting-second-turn-before-response",
        ),
        ("malformed-error", "--malformed-error-second-turn-start"),
        ("missing-turn-id", "--missing-id-second-turn-start"),
    ] {
        let directory = temporary_directory(label);
        let config = provider_config(&directory, &[switch]);
        let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
        provider
            .start_turn("Complete the first turn.", &config.cwd)
            .expect("start first provider turn");
        let first_completed = (0..32).any(|_| {
            matches!(
                provider.poll().expect("poll first turn"),
                Some(CodexProviderEvent::Notification { method, .. })
                    if method == "turn/completed"
            )
        });
        assert!(
            first_completed,
            "observe the authoritative first completion for {label}"
        );

        provider
            .start_turn("Accept replacement work before failing.", &config.cwd)
            .expect_err("the accepted replacement turn has no valid response");
        let ambiguous_start_exit = (0..64).find_map(|_| {
            match provider
                .poll()
                .expect("poll exit after ambiguous replacement start")
            {
                Some(CodexProviderEvent::Exited {
                    success,
                    completed_turn_authoritative,
                    completion_reconciles_exit,
                    ..
                }) => Some((
                    success,
                    completed_turn_authoritative,
                    completion_reconciles_exit,
                )),
                _ => None,
            }
        });
        assert_eq!(
            ambiguous_start_exit,
            Some((false, true, false)),
            "{label} must retain the completed result without hiding the provider failure"
        );

        fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
    }
}

#[test]
fn ambiguous_replacement_turn_adopts_one_later_completion_identity() {
    for (label, switch, omit_started) in [
        (
            "accepted-before-response-with-completion",
            "--fail-after-accepting-second-turn-before-response",
            false,
        ),
        (
            "malformed-error-with-completion",
            "--malformed-error-second-turn-start",
            false,
        ),
        (
            "missing-turn-id-with-completion",
            "--missing-id-second-turn-start",
            true,
        ),
    ] {
        let directory = temporary_directory(label);
        let mut switches = vec![switch, "--complete-ambiguous-second-turn"];
        if omit_started {
            switches.push("--omit-ambiguous-turn-started");
        }
        let config = provider_config(&directory, &switches);
        let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
        provider
            .start_turn("Complete the first turn.", &config.cwd)
            .expect("start first provider turn");
        let first_completed = (0..32).any(|_| {
            matches!(
                provider.poll().expect("poll first turn"),
                Some(CodexProviderEvent::Notification { method, .. })
                    if method == "turn/completed"
            )
        });
        assert!(
            first_completed,
            "observe the authoritative first completion for {label}"
        );

        provider
            .start_turn("Complete accepted replacement work.", &config.cwd)
            .expect_err("the accepted replacement turn has no valid response");
        let unresolved_error = provider
            .start_turn("Do not start duplicate replacement work.", &config.cwd)
            .expect_err("an unresolved ambiguous start bounds replacement work to one turn");
        assert!(
            unresolved_error
                .to_string()
                .contains("unresolved ambiguous provider turn start"),
            "unexpected unresolved-start error for {label}: {unresolved_error}"
        );

        let mut replacement_started = false;
        let mut replacement_completed = false;
        let replacement_exit = (0..128).find_map(|_| {
            match provider
                .poll()
                .expect("poll evidence for accepted replacement turn")
            {
                Some(CodexProviderEvent::Notification { method, params })
                    if method == "turn/started" =>
                {
                    assert_eq!(
                        params.pointer("/turn/id").and_then(Value::as_str),
                        Some("provider-turn-2")
                    );
                    replacement_started = true;
                    None
                }
                Some(CodexProviderEvent::Notification { method, params })
                    if method == "turn/completed" =>
                {
                    assert_eq!(
                        params.pointer("/turn/id").and_then(Value::as_str),
                        Some("provider-turn-2")
                    );
                    replacement_completed = true;
                    None
                }
                Some(CodexProviderEvent::Exited {
                    success,
                    completed_turn_authoritative,
                    completion_reconciles_exit,
                    ..
                }) => Some((
                    success,
                    completed_turn_authoritative,
                    completion_reconciles_exit,
                )),
                _ => None,
            }
        });
        assert!(
            replacement_started,
            "the replacement identity should be established before replaying its output for {label}"
        );
        assert!(
            replacement_completed,
            "observe replacement completion for {label}"
        );
        assert_eq!(
            replacement_exit,
            Some((false, true, true)),
            "the replacement completion, not the old result, reconciles the provider exit for {label}"
        );

        fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
    }
}

#[test]
fn ambiguous_replacement_turn_rejects_conflicting_later_identity() {
    let directory = temporary_directory("conflicting-ambiguous-turn-identities");
    let config = provider_config(
        &directory,
        &[
            "--missing-id-second-turn-start",
            "--conflicting-ambiguous-second-turn",
        ],
    );
    let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
    provider
        .start_turn("Complete the first turn.", &config.cwd)
        .expect("start first provider turn");
    let first_completed = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll first turn"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(
        first_completed,
        "observe the authoritative first completion"
    );

    provider
        .start_turn("Accept replacement work ambiguously.", &config.cwd)
        .expect_err("the replacement response omits its turn identity");
    let replacement_started = provider
        .poll()
        .expect("poll replacement start")
        .expect("replacement start is available");
    assert!(matches!(
        replacement_started,
        CodexProviderEvent::Notification { method, params }
            if method == "turn/started"
                && params.pointer("/turn/id").and_then(Value::as_str)
                    == Some("provider-turn-2")
    ));
    assert_eq!(provider.active_provider_turn_id(), Some("provider-turn-2"));

    let conflicting_completion = provider
        .poll()
        .expect_err("a second replacement identity must fail closed");
    assert!(
        conflicting_completion
            .to_string()
            .contains("another active turn"),
        "unexpected conflicting-identity error: {conflicting_completion}"
    );
    assert_eq!(provider.active_provider_turn_id(), Some("provider-turn-2"));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn clean_exit_after_ambiguous_replacement_start_fails_the_durable_session() {
    let directory = temporary_directory("durable-clean-exit-after-ambiguous-turn-start");
    let config = provider_config(
        &directory,
        &["--exit-after-accepting-second-turn-before-response"],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "first-turn",
            3,
            "turn.start",
            json!({"text": "Complete the first turn."}),
        ))
        .expect("start first provider turn");

    let mut first_events = Vec::new();
    for _ in 0..32 {
        first_events.extend(
            poll_and_ack(&mut executor)
                .expect("poll first turn")
                .into_iter()
                .map(|event| event.event_type),
        );
        if first_events.iter().any(|event| event == "turn.completed") {
            break;
        }
    }
    assert!(first_events.iter().any(|event| event == "turn.completed"));

    executor
        .execute(&command(
            "ambiguous-turn",
            4,
            "turn.start",
            json!({"text": "Accept replacement work before exiting cleanly."}),
        ))
        .expect_err("accepted replacement start loses its response");
    let persisted_after_start: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after ambiguous start"),
    )
    .expect("parse provider state after ambiguous start");
    assert_eq!(persisted_after_start["completedTurnAuthoritative"], true);
    assert_eq!(persisted_after_start["completedTurnProcessGeneration"], 1);
    assert_eq!(
        persisted_after_start["completedProviderTurnId"],
        "provider-turn-1"
    );

    let mut exit_events = Vec::new();
    for _ in 0..64 {
        exit_events.extend(
            poll_and_ack(&mut executor)
                .expect("poll provider after ambiguous start")
                .into_iter()
                .map(|event| event.event_type),
        );
        if exit_events.iter().any(|event| event == "session.failed") {
            break;
        }
    }
    assert!(exit_events.iter().any(|event| event == "session.failed"));
    assert!(!exit_events
        .iter()
        .any(|event| event == "session.reconciled"));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn durable_ambiguous_start_recovers_a_distinct_active_replacement_after_process_loss() {
    let directory = temporary_directory("durable-ambiguous-active-recovery");
    let config = provider_config(
        &directory,
        &[
            "--fail-after-accepting-second-turn-before-response",
            "--retain-ambiguous-second-turn-active",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "first-turn",
            3,
            "turn.start",
            json!({"text": "Complete the first turn."}),
        ))
        .expect("start first provider turn");
    for _ in 0..32 {
        if poll_and_ack(&mut executor)
            .expect("poll first turn")
            .iter()
            .any(|event| event.event_type == "turn.completed")
        {
            break;
        }
    }

    executor
        .execute(&command(
            "ambiguous-turn",
            4,
            "turn.start",
            json!({"text": "Accept replacement work without returning its identity."}),
        ))
        .expect_err("replacement acceptance loses its response");
    let persisted_ambiguous: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after ambiguous start"),
    )
    .expect("parse provider state after ambiguous start");
    assert_eq!(persisted_ambiguous["ambiguousTurnStartPending"], true);
    assert_eq!(
        persisted_ambiguous["completedProviderTurnId"],
        "provider-turn-1"
    );

    executor.shutdown().expect("stop first provider process");
    drop(executor);

    let mut recovered = CodexCommandExecutor::new(&directory);
    let snapshot = recovered
        .execute(&command("snapshot", 5, "session.snapshot", json!({})))
        .expect("reconcile active replacement turn");
    assert_eq!(snapshot.result["status"], "turn_active");
    assert_eq!(snapshot.result["activeProviderTurnId"], "provider-turn-2");
    let persisted_recovered: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read recovered provider state"),
    )
    .expect("parse recovered provider state");
    assert_eq!(persisted_recovered["ambiguousTurnStartPending"], false);
    assert_eq!(persisted_recovered["completedTurnAuthoritative"], false);
    assert!(persisted_recovered["completedProviderTurnId"].is_null());

    recovered
        .shutdown()
        .expect("stop recovered provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn replacement_item_is_not_persisted_before_ambiguous_turn_identity() {
    let directory = temporary_directory("durable-ambiguous-item-recovery");
    let config = provider_config(
        &directory,
        &[
            "--missing-id-second-turn-start",
            "--hold-ambiguous-second-turn-after-item",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "first-turn",
            3,
            "turn.start",
            json!({"text": "Complete the first turn."}),
        ))
        .expect("start first provider turn");
    for _ in 0..32 {
        if poll_and_ack(&mut executor)
            .expect("poll first turn")
            .iter()
            .any(|event| event.event_type == "turn.completed")
        {
            break;
        }
    }

    executor
        .execute(&command(
            "ambiguous-turn",
            4,
            "turn.start",
            json!({"text": "Emit replacement output before terminal authority."}),
        ))
        .expect_err("replacement response omits its identity");
    assert!(
        poll_and_ack(&mut executor)
            .expect("defer identity-less replacement output")
            .is_empty(),
        "replacement output must not escape before its turn identity"
    );
    let persisted_before_loss: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state before process loss"),
    )
    .expect("parse provider state before process loss");
    assert_eq!(persisted_before_loss["ambiguousTurnStartPending"], true);
    assert_ne!(
        persisted_before_loss["lastAgentMessage"],
        "Replacement output before terminal authority."
    );

    executor.shutdown().expect("stop first provider process");
    drop(executor);

    let mut recovered = CodexCommandExecutor::new(&directory);
    let snapshot = recovered
        .execute(&command("snapshot", 5, "session.snapshot", json!({})))
        .expect("reconcile the still-active replacement turn");
    assert_eq!(snapshot.result["status"], "turn_active");
    assert_eq!(snapshot.result["activeProviderTurnId"], "provider-turn-2");
    let persisted_recovered: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read recovered provider state"),
    )
    .expect("parse recovered provider state");
    assert_eq!(persisted_recovered["ambiguousTurnStartPending"], false);
    assert_ne!(
        persisted_recovered["lastAgentMessage"],
        "Replacement output before terminal authority."
    );

    recovered
        .shutdown()
        .expect("stop recovered provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn completed_ambiguous_replacement_fails_closed_after_process_loss() {
    let directory = temporary_directory("durable-ambiguous-completed-recovery");
    let config = provider_config(
        &directory,
        &[
            "--missing-id-second-turn-start",
            "--complete-ambiguous-second-turn-before-response",
            "--omit-ambiguous-turn-started",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "first-turn",
            3,
            "turn.start",
            json!({"text": "Complete the first turn."}),
        ))
        .expect("start first provider turn");
    for _ in 0..32 {
        if poll_and_ack(&mut executor)
            .expect("poll first turn")
            .iter()
            .any(|event| event.event_type == "turn.completed")
        {
            break;
        }
    }

    executor
        .execute(&command(
            "ambiguous-turn",
            4,
            "turn.start",
            json!({"text": "Complete replacement work before returning an invalid response."}),
        ))
        .expect_err("replacement response omits its identity");
    executor.shutdown().expect("stop first provider process");
    drop(executor);

    let mut recovered = CodexCommandExecutor::new(&directory);
    let recovery_error = recovered
        .execute(&command("snapshot", 5, "session.snapshot", json!({})))
        .expect_err("completed ambiguous work without durable identity must fail closed");
    assert!(
        recovery_error
            .to_string()
            .contains("cannot safely recover an ambiguous Codex turn start"),
        "unexpected ambiguous recovery error: {recovery_error}"
    );
    let repeated_poll_error = recovered
        .poll_events()
        .expect_err("a repeated poll must retain the fail-closed recovery state");
    assert!(
        repeated_poll_error
            .to_string()
            .contains("cannot safely recover an ambiguous Codex turn start"),
        "unexpected repeated ambiguous recovery error: {repeated_poll_error}"
    );
    assert_eq!(call_count(&directory, "turn/start"), 2);
    let persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read fail-closed provider state"),
    )
    .expect("parse fail-closed provider state");
    assert_eq!(persisted["ambiguousTurnStartPending"], true);
    assert_eq!(persisted["completedProviderTurnId"], "provider-turn-1");

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn ambiguous_replacement_completion_replaces_durable_turn_authority() {
    let directory = temporary_directory("durable-ambiguous-turn-completion");
    let config = provider_config(
        &directory,
        &[
            "--missing-id-second-turn-start",
            "--complete-ambiguous-second-turn",
        ],
    );
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "first-turn",
            3,
            "turn.start",
            json!({"text": "Complete the first turn."}),
        ))
        .expect("start first provider turn");

    let mut first_events = Vec::new();
    for _ in 0..32 {
        first_events.extend(
            poll_and_ack(&mut executor)
                .expect("poll first turn")
                .into_iter()
                .map(|event| event.event_type),
        );
        if first_events.iter().any(|event| event == "turn.completed") {
            break;
        }
    }
    assert!(first_events.iter().any(|event| event == "turn.completed"));

    executor
        .execute(&command(
            "ambiguous-turn",
            4,
            "turn.start",
            json!({"text": "Complete replacement work after the malformed response."}),
        ))
        .expect_err("accepted replacement response omits its turn identity");

    let mut replacement_events = Vec::new();
    for _ in 0..64 {
        replacement_events.extend(
            poll_and_ack(&mut executor)
                .expect("poll accepted replacement evidence")
                .into_iter()
                .map(|event| event.event_type),
        );
        if replacement_events
            .iter()
            .any(|event| event == "session.reconciled")
        {
            break;
        }
    }
    assert!(replacement_events
        .iter()
        .any(|event| event == "turn.started"));
    assert!(replacement_events
        .iter()
        .any(|event| event == "turn.completed"));
    assert!(replacement_events
        .iter()
        .any(|event| event == "session.reconciled"));

    let persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after replacement completion"),
    )
    .expect("parse provider state after replacement completion");
    assert_eq!(persisted["activeProviderTurnId"], Value::Null);
    assert_eq!(persisted["completedTurnAuthoritative"], true);
    assert_eq!(persisted["completedTurnProcessGeneration"], 1);
    assert_eq!(persisted["completedProviderTurnId"], "provider-turn-2");

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn accepted_replacement_turn_revokes_prior_authority_before_idle_crash() {
    let directory = temporary_directory("completion-then-new-turn-failure");
    let config = provider_config(&directory, &["--fail-after-second-turn-start"]);
    let mut provider = CodexProvider::start(&config, None).expect("start Codex provider");
    provider
        .start_turn("Complete the first turn.", &config.cwd)
        .expect("start first provider turn");
    let first_completed = (0..32).any(|_| {
        matches!(
            provider.poll().expect("poll first turn"),
            Some(CodexProviderEvent::Notification { method, .. })
                if method == "turn/completed"
        )
    });
    assert!(
        first_completed,
        "observe the authoritative first completion"
    );

    provider
        .start_turn("Start genuinely new provider work.", &config.cwd)
        .expect("start second provider turn");
    let second_exit = (0..64).find_map(|_| match provider.poll().expect("poll second turn") {
        Some(CodexProviderEvent::Exited {
            success,
            completed_turn_authoritative,
            completion_reconciles_exit,
            ..
        }) => Some((
            success,
            completed_turn_authoritative,
            completion_reconciles_exit,
        )),
        _ => None,
    });
    assert_eq!(second_exit, Some((false, false, false)));

    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_rejects_a_tool_call_that_was_not_advertised() {
    let directory = temporary_directory("unauthorized-tool");
    let config = provider_config(&directory, &["--emit-tool-call"]);
    let mut provider = CodexProvider::start(&config, None).expect("start Codex without tools");
    provider
        .start_turn("Attempt an unavailable tool.", &config.cwd)
        .expect("start provider turn");
    let error = (0..32)
        .find_map(|_| provider.poll().err())
        .expect("unauthorized provider tool call is rejected");
    assert!(error.to_string().contains("unauthorized tool"));
    let _ = provider.shutdown();
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_resume_advertises_the_same_authorized_tools() {
    let directory = temporary_directory("dynamic-tool-resume");
    let config = provider_config(&directory, &["--require-dynamic-tool"]);
    let mut provider =
        CodexProvider::start_with_tools(&config, [task_context_tool()], Some("codex-thread-1"))
            .expect("resume Codex with the run-scoped tool set");
    assert_eq!(provider.thread_id(), "codex-thread-1");
    provider.shutdown().expect("stop provider");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn durable_backend_resumes_the_active_thread_without_restarting_the_turn() {
    let directory = temporary_directory("resume");
    let config = provider_config(&directory, &["--hold-turn"]);
    let mut first = CodexCommandExecutor::new(&directory);
    first
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    first
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    first
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Hold this turn for recovery."}),
        ))
        .expect("start held provider turn");
    assert_eq!(call_count(&directory, "turn/start"), 1);
    first.shutdown().expect("stop first provider process");
    drop(first);

    let mut recovered = CodexCommandExecutor::new(&directory);
    let snapshot = recovered
        .execute(&command("snapshot", 4, "session.snapshot", json!({})))
        .expect("restore provider session");
    assert_eq!(snapshot.result["status"], "turn_active");
    assert_eq!(snapshot.result["activeProviderTurnId"], "provider-turn-1");
    assert_eq!(call_count(&directory, "turn/start"), 1);
    assert_eq!(call_count(&directory, "thread/resume"), 1);
    assert_eq!(call_count(&directory, "thread/read"), 1);

    recovered
        .execute(&command("interrupt", 5, "turn.interrupt", json!({})))
        .expect("interrupt recovered provider turn");
    let mut terminal_seen = false;
    for _ in 0..16 {
        let events = poll_and_ack(&mut recovered).expect("poll interrupted turn");
        terminal_seen |= events
            .iter()
            .any(|event| event.event_type == "turn.interrupted");
        if terminal_seen {
            break;
        }
    }
    assert!(terminal_seen);
    recovered
        .shutdown()
        .expect("stop recovered provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn provider_exit_preserves_and_reconciles_the_active_turn() {
    let directory = temporary_directory("exit-active-turn");
    let config = provider_config(&directory, &["--exit-after-turn-start"]);
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    executor
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Keep the native turn active while the provider exits."}),
        ))
        .expect("start provider turn");

    let mut provider_exit_seen = false;
    for _ in 0..32 {
        provider_exit_seen |= poll_and_ack(&mut executor)
            .expect("poll provider exit")
            .iter()
            .any(|event| event.event_type == "session.failed");
        if provider_exit_seen {
            break;
        }
    }
    assert!(provider_exit_seen);
    let persisted: Value = serde_json::from_slice(
        &fs::read(directory.join("codex-provider-state.json"))
            .expect("read provider state after exit"),
    )
    .expect("parse provider state after exit");
    assert_eq!(persisted["lifecycle"], "provider_exited");
    assert_eq!(persisted["activeProviderTurnId"], "provider-turn-1");

    let interrupted = executor
        .execute(&command("interrupt", 4, "turn.interrupt", json!({})))
        .expect("interrupt reconciled provider turn");
    assert_eq!(interrupted.result["status"], "interrupt_requested");
    assert_eq!(call_count(&directory, "thread/resume"), 1);
    assert_eq!(call_count(&directory, "thread/read"), 1);
    assert_eq!(call_count(&directory, "turn/interrupt"), 1);

    let mut terminal_seen = false;
    for _ in 0..32 {
        terminal_seen |= poll_and_ack(&mut executor)
            .expect("poll reconciled interruption")
            .iter()
            .any(|event| event.event_type == "turn.interrupted");
        if terminal_seen {
            break;
        }
    }
    assert!(terminal_seen);
    executor.shutdown().expect("stop resumed provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn unacknowledged_provider_events_survive_executor_restart() {
    let directory = temporary_directory("pending-event-recovery");
    let config = provider_config(&directory, &["--emit-question"]);
    let mut first = CodexCommandExecutor::new(&directory);
    first
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare Codex provider");
    first
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open Codex session");
    first
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Emit a durable question."}),
        ))
        .expect("start provider turn");

    let mut retained = None;
    for _ in 0..32 {
        let events = first.poll_events().expect("poll provider events");
        if events
            .iter()
            .any(|event| event.event_type == "runtime_request.created")
        {
            retained = Some(events);
            break;
        }
        first
            .acknowledge_events(events.len())
            .expect("acknowledge events before the question");
    }
    let retained = retained.expect("observe a durable runtime request");
    first.shutdown().expect("stop first provider process");
    drop(first);

    let mut recovered = CodexCommandExecutor::new(&directory);
    let replayed = recovered
        .poll_events()
        .expect("reload unacknowledged provider events");
    assert_eq!(&replayed[..retained.len()], retained.as_slice());
    recovered
        .acknowledge_events(replayed.len())
        .expect("acknowledge reloaded provider events");
    recovered
        .shutdown()
        .expect("stop recovered provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn structured_question_round_trips_through_the_normalized_backend() {
    let directory = temporary_directory("questions");
    let config = provider_config(&directory, &["--emit-question"]);
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({"provider": config}),
        ))
        .expect("prepare provider");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open provider session");
    let started = executor
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Ask for deployment input."}),
        ))
        .expect("start provider turn");
    assert_eq!(started.events.len(), 1);
    assert_eq!(started.events[0].0, "turn.accepted");

    let mut question_set = None;
    let mut provider_started_events = 0;
    for _ in 0..16 {
        for event in poll_and_ack(&mut executor).expect("poll question") {
            provider_started_events += usize::from(event.event_type == "turn.started");
            if event.event_type == "runtime_request.created" {
                assert_eq!(
                    event.payload["request"]["schema"],
                    "paperclip.runtime_request.v2"
                );
                question_set = event.payload.pointer("/request/input").cloned();
            }
        }
        if question_set.is_some() {
            break;
        }
    }
    let question_set = question_set.expect("normalized question set is emitted");
    assert_eq!(provider_started_events, 1);
    assert_eq!(question_set["schema"], "paperclip.question_set.v1");
    assert_eq!(
        question_set["questions"][0]["options"][0]["label"],
        "Staging"
    );

    executor
        .execute(&command(
            "resolve",
            4,
            "request.resolve",
            json!({
                "requestId": "runtime-request-1",
                "response": {
                    "schema": "paperclip.question_response.v1",
                    "answers": {"environment": {"selectedOptionIds": ["option-1"]}}
                }
            }),
        ))
        .expect("deliver normalized response");
    let mut completed = false;
    for _ in 0..16 {
        completed |= poll_and_ack(&mut executor)
            .expect("poll completed question turn")
            .iter()
            .any(|event| event.event_type == "turn.completed");
        if completed {
            break;
        }
    }
    assert!(completed);
    executor.shutdown().expect("stop provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

#[test]
fn codex_completion_emits_the_bound_result_before_the_terminal_event() {
    let directory = temporary_directory("completion-contract");
    let config = provider_config(&directory, &[]);
    let mut executor = CodexCommandExecutor::new(&directory);
    executor
        .execute(&command(
            "prepare",
            1,
            "run.prepare",
            json!({
                "provider": config,
                "completionContract": {
                    "revision": "sha256:test-contract",
                    "criterionIds": ["criterion_test_task"]
                }
            }),
        ))
        .expect("prepare provider with completion contract");
    executor
        .execute(&command("open", 2, "session.open", json!({})))
        .expect("open provider session");
    executor
        .execute(&command(
            "turn",
            3,
            "turn.start",
            json!({"text": "Complete the fake native run."}),
        ))
        .expect("start provider turn");

    let mut emitted = Vec::new();
    for _ in 0..32 {
        emitted.extend(poll_and_ack(&mut executor).expect("poll terminal events"));
        if emitted
            .iter()
            .any(|event| event.event_type == "run.terminal")
        {
            break;
        }
    }
    let result_index = emitted
        .iter()
        .position(|event| event.event_type == "run.result.proposed")
        .expect("result proposal is emitted");
    let terminal_index = emitted
        .iter()
        .position(|event| event.event_type == "run.terminal")
        .expect("terminal event is emitted");
    assert!(result_index < terminal_index);
    assert_eq!(
        emitted[result_index].payload["summary"],
        "Codex completed the fake turn."
    );
    assert_eq!(
        emitted[result_index].payload["completionClaim"]["contractRevision"],
        "sha256:test-contract"
    );
    assert_eq!(
        emitted[terminal_index].payload["runTerminalState"],
        "succeeded"
    );

    executor.shutdown().expect("stop provider process");
    fs::remove_dir_all(directory).expect("remove Codex integration-test directory");
}

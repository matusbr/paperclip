use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FakeState {
    thread_id: String,
    active_turn_id: Option<String>,
}

fn argument(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

fn send(value: Value) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn load_state(path: &Path) -> FakeState {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| FakeState {
            thread_id: "codex-thread-1".to_owned(),
            active_turn_id: None,
        })
}

fn save_state(path: &Path, state: &FakeState) -> io::Result<()> {
    fs::write(path, serde_json::to_vec_pretty(state)?)
}

fn log_call(path: Option<&Path>, method: &str) -> io::Result<()> {
    let Some(path) = path else { return Ok(()) };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{method}")
}

fn has_task_context_tool(message: &Value) -> bool {
    message
        .pointer("/params/dynamicTools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools.iter().any(|tool| {
                tool.get("name").and_then(Value::as_str) == Some("get_task_context")
                    && tool.get("description").and_then(Value::as_str) == Some("Read task context.")
                    && tool.pointer("/inputSchema/type").and_then(Value::as_str) == Some("object")
            })
        })
}

fn finish_turn(state_path: &Path, state: &mut FakeState, status: &str) -> io::Result<()> {
    let turn_id = state
        .active_turn_id
        .clone()
        .unwrap_or_else(|| "provider-turn-1".to_owned());
    send(json!({
        "method": "item/completed",
        "params": {"item": {
            "id": "message-1",
            "type": "agentMessage",
            "status": "completed",
            "text": "Codex completed the fake turn."
        }}
    }))?;
    send(json!({
        "method": "thread/tokenUsage/updated",
        "params": {
            "threadId": state.thread_id,
            "tokenUsage": {
                "total": {"inputTokens": 12, "outputTokens": 3},
                "last": {"inputTokens": 12, "outputTokens": 3, "requests": 1}
            }
        }
    }))?;
    send(json!({
        "method": "turn/completed",
        "params": {"turn": {"id": turn_id, "status": status}}
    }))?;
    state.active_turn_id = None;
    save_state(state_path, state)
}

fn emit_ambiguous_turn_evidence(
    state_path: &Path,
    state: &mut FakeState,
    emit_turn_started: bool,
    conflicting_identity: bool,
) -> io::Result<()> {
    let turn_id = state
        .active_turn_id
        .clone()
        .unwrap_or_else(|| "provider-turn-2".to_owned());
    if emit_turn_started {
        send(json!({
            "method": "turn/started",
            "params": {"turn": {"id": turn_id}}
        }))?;
    }
    if conflicting_identity {
        send(json!({
            "method": "turn/completed",
            "params": {"turn": {"id": "provider-turn-conflict", "status": "completed"}}
        }))
    } else {
        finish_turn(state_path, state, "completed")
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let state_path =
        PathBuf::from(argument(&args, "--state-file").ok_or("--state-file is required")?);
    let call_log = argument(&args, "--call-log").map(PathBuf::from);
    let emit_question = args.iter().any(|value| value == "--emit-question");
    let emit_tool_call = args.iter().any(|value| value == "--emit-tool-call");
    let replay_completed_tool_call = args
        .iter()
        .any(|value| value == "--replay-completed-tool-call");
    let complete_after_tool_call = args
        .iter()
        .any(|value| value == "--complete-after-tool-call");
    let exit_after_tool_call_completion = args
        .iter()
        .any(|value| value == "--exit-after-tool-call-completion");
    let require_dynamic_tool = args.iter().any(|value| value == "--require-dynamic-tool");
    let hold_turn = args.iter().any(|value| value == "--hold-turn");
    let exit_after_turn_start = args.iter().any(|value| value == "--exit-after-turn-start");
    let exit_after_turn_completion = args
        .iter()
        .any(|value| value == "--exit-after-turn-completion");
    let emit_post_completion_warning = args
        .iter()
        .any(|value| value == "--emit-post-completion-warning");
    let fail_after_turn_completion = args
        .iter()
        .any(|value| value == "--fail-after-turn-completion");
    let fail_after_second_turn_start = args
        .iter()
        .any(|value| value == "--fail-after-second-turn-start");
    let reject_second_turn_start = args
        .iter()
        .any(|value| value == "--reject-second-turn-start");
    let emit_turn_before_rejected_second_start = args
        .iter()
        .any(|value| value == "--emit-turn-before-rejected-second-start");
    let malformed_error_second_turn_start = args
        .iter()
        .any(|value| value == "--malformed-error-second-turn-start");
    let missing_id_second_turn_start = args
        .iter()
        .any(|value| value == "--missing-id-second-turn-start");
    let fail_after_accepting_second_turn_before_response = args
        .iter()
        .any(|value| value == "--fail-after-accepting-second-turn-before-response");
    let exit_after_accepting_second_turn_before_response = args
        .iter()
        .any(|value| value == "--exit-after-accepting-second-turn-before-response");
    let complete_ambiguous_second_turn = args
        .iter()
        .any(|value| value == "--complete-ambiguous-second-turn");
    let retain_ambiguous_second_turn_active = args
        .iter()
        .any(|value| value == "--retain-ambiguous-second-turn-active");
    let hold_ambiguous_second_turn_after_item = args
        .iter()
        .any(|value| value == "--hold-ambiguous-second-turn-after-item");
    let complete_ambiguous_second_turn_before_response = args
        .iter()
        .any(|value| value == "--complete-ambiguous-second-turn-before-response");
    let conflicting_ambiguous_second_turn = args
        .iter()
        .any(|value| value == "--conflicting-ambiguous-second-turn");
    let omit_ambiguous_turn_started = args
        .iter()
        .any(|value| value == "--omit-ambiguous-turn-started");
    let fail_after_thread_read = args.iter().any(|value| value == "--fail-after-thread-read");
    let exit_after_thread_read = args.iter().any(|value| value == "--exit-after-thread-read");
    let fail_after_turn_completion_delay_ms =
        argument(&args, "--fail-after-turn-completion-delay-ms")
            .map(|value| value.parse::<u64>())
            .transpose()?;
    let pre_response_notification = args
        .iter()
        .any(|value| value == "--notification-before-response");
    let mut state = load_state(&state_path);
    let mut turn_start_count = 0_u64;

    for line in io::stdin().lock().lines() {
        let message: Value = serde_json::from_str(&line?)?;
        if message.get("method").is_none() && message.get("id") == Some(&json!("runtime-request-1"))
        {
            finish_turn(&state_path, &mut state, "completed")?;
            continue;
        }
        if message.get("method").is_none() && message.get("id") == Some(&json!("tool-request-1")) {
            if message.pointer("/result/success") == Some(&json!(false)) {
                log_call(call_log.as_deref(), "tool-response:failure")?;
                if state.active_turn_id.is_some() {
                    finish_turn(&state_path, &mut state, "failed")?;
                }
                continue;
            }
            if message.pointer("/result/success") != Some(&json!(true)) {
                return Err("semantic tool response omitted success".into());
            }
            let text = message
                .pointer("/result/contentItems/0/text")
                .and_then(Value::as_str)
                .ok_or("semantic tool response omitted content text")?;
            let result: Value = serde_json::from_str(text)?;
            if result != json!({"ok": true, "task": {"id": "task-1"}}) {
                return Err("semantic tool response changed the operation result".into());
            }
            if replay_completed_tool_call {
                send(json!({
                    "id": "tool-request-replay",
                    "method": "item/tool/call",
                    "params": {
                        "threadId": state.thread_id,
                        "turnId": state.active_turn_id,
                        "callId": "semantic-call-1",
                        "tool": "get_task_context",
                        "arguments": {}
                    }
                }))?;
                continue;
            }
            finish_turn(&state_path, &mut state, "completed")?;
            continue;
        }
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            continue;
        };
        log_call(call_log.as_deref(), method)?;
        let id = message.get("id").cloned();
        match method {
            "initialize" => send(json!({
                "id": id,
                "result": {"user": {"sessionId": "codex-account-session"}}
            }))?,
            "initialized" => {}
            "thread/start" => {
                if require_dynamic_tool && !has_task_context_tool(&message) {
                    return Err("thread/start omitted the authorized dynamic tool".into());
                }
                state.thread_id = "codex-thread-1".to_owned();
                state.active_turn_id = None;
                save_state(&state_path, &state)?;
                if pre_response_notification {
                    send(json!({
                        "method": "warning",
                        "params": {"message": "buffered before thread response"}
                    }))?;
                }
                send(json!({
                    "id": id,
                    "result": {"thread": {"id": state.thread_id, "sessionId": "codex-account-session"}}
                }))?;
            }
            "thread/resume" => {
                if require_dynamic_tool && !has_task_context_tool(&message) {
                    return Err("thread/resume omitted the authorized dynamic tool".into());
                }
                send(json!({
                    "id": id,
                    "result": {"thread": {"id": state.thread_id, "sessionId": "codex-account-session"}}
                }))?;
            }
            "thread/read" => {
                let turns = state
                    .active_turn_id
                    .as_ref()
                    .map(|turn_id| vec![json!({"id": turn_id, "status": "inProgress"})])
                    .unwrap_or_default();
                send(json!({
                    "id": id,
                    "result": {"thread": {"id": state.thread_id, "turns": turns}}
                }))?;
                if fail_after_thread_read {
                    return Err("configured failure after thread read".into());
                } else if exit_after_thread_read {
                    return Ok(());
                }
            }
            "turn/start" => {
                turn_start_count += 1;
                if reject_second_turn_start && turn_start_count == 2 {
                    send(json!({
                        "method": "warning",
                        "params": {"message": "buffered before replacement rejection"}
                    }))?;
                    if emit_turn_before_rejected_second_start {
                        send(json!({
                            "method": "turn/started",
                            "params": {"turn": {"id": "provider-turn-contradiction"}}
                        }))?;
                    }
                    send(json!({
                        "id": id,
                        "error": {"code": -32000, "message": "replacement turn rejected"}
                    }))?;
                    return Err("configured failure after second turn rejection".into());
                }
                let emits_ambiguous_turn_evidence = turn_start_count == 2
                    && (complete_ambiguous_second_turn
                        || complete_ambiguous_second_turn_before_response
                        || conflicting_ambiguous_second_turn);
                let provider_turn_id = if emits_ambiguous_turn_evidence
                    || (turn_start_count == 2
                        && (retain_ambiguous_second_turn_active
                            || hold_ambiguous_second_turn_after_item))
                {
                    "provider-turn-2"
                } else {
                    "provider-turn-1"
                };
                state.active_turn_id = Some(provider_turn_id.to_owned());
                save_state(&state_path, &state)?;
                if complete_ambiguous_second_turn_before_response && turn_start_count == 2 {
                    emit_ambiguous_turn_evidence(
                        &state_path,
                        &mut state,
                        !omit_ambiguous_turn_started,
                        false,
                    )?;
                }
                if fail_after_accepting_second_turn_before_response && turn_start_count == 2 {
                    if emits_ambiguous_turn_evidence
                        && !complete_ambiguous_second_turn_before_response
                    {
                        emit_ambiguous_turn_evidence(
                            &state_path,
                            &mut state,
                            !omit_ambiguous_turn_started,
                            conflicting_ambiguous_second_turn,
                        )?;
                    }
                    return Err("configured failure after accepting second turn".into());
                }
                if exit_after_accepting_second_turn_before_response && turn_start_count == 2 {
                    return Ok(());
                }
                if malformed_error_second_turn_start && turn_start_count == 2 {
                    send(json!({"id": id, "error": {}}))?;
                    if emits_ambiguous_turn_evidence
                        && !complete_ambiguous_second_turn_before_response
                    {
                        emit_ambiguous_turn_evidence(
                            &state_path,
                            &mut state,
                            !omit_ambiguous_turn_started,
                            conflicting_ambiguous_second_turn,
                        )?;
                    }
                    return Err("configured failure after malformed turn error".into());
                }
                if missing_id_second_turn_start && turn_start_count == 2 {
                    send(json!({
                        "id": id,
                        "result": {"turn": {"status": "inProgress"}}
                    }))?;
                    if hold_ambiguous_second_turn_after_item {
                        send(json!({
                            "method": "item/completed",
                            "params": {"item": {
                                "id": "replacement-message-before-terminal",
                                "type": "agentMessage",
                                "status": "completed",
                                "text": "Replacement output before terminal authority."
                            }}
                        }))?;
                        continue;
                    }
                    if emits_ambiguous_turn_evidence
                        && !complete_ambiguous_second_turn_before_response
                    {
                        emit_ambiguous_turn_evidence(
                            &state_path,
                            &mut state,
                            !omit_ambiguous_turn_started,
                            conflicting_ambiguous_second_turn,
                        )?;
                    }
                    return Err("configured failure after missing turn identity".into());
                }
                send(json!({
                    "id": id,
                    "result": {"turn": {"id": "provider-turn-1", "status": "inProgress"}}
                }))?;
                send(json!({
                    "method": "turn/started",
                    "params": {"turn": {"id": "provider-turn-1"}}
                }))?;
                if fail_after_second_turn_start && turn_start_count == 2 {
                    return Err("configured failure after second turn start".into());
                } else if exit_after_turn_start {
                    return Ok(());
                } else if emit_tool_call {
                    send(json!({
                        "id": "tool-request-1",
                        "method": "item/tool/call",
                        "params": {
                            "threadId": state.thread_id,
                            "turnId": "provider-turn-1",
                            "callId": "semantic-call-1",
                            "tool": "get_task_context",
                            "arguments": {}
                        }
                    }))?;
                    if complete_after_tool_call {
                        finish_turn(&state_path, &mut state, "completed")?;
                        if exit_after_tool_call_completion {
                            return Ok(());
                        }
                    }
                } else if emit_question {
                    send(json!({
                        "id": "runtime-request-1",
                        "method": "item/tool/requestUserInput",
                        "params": {
                            "threadId": state.thread_id,
                            "turnId": "provider-turn-1",
                            "itemId": "question-item-1",
                            "isBlocking": true,
                            "title": "Deployment input",
                            "questions": [{
                                "id": "environment",
                                "header": "Environment",
                                "question": "Where should we deploy?",
                                "options": [
                                    {"label": "Staging", "description": "Deploy safely."},
                                    {"label": "Production", "description": "Deploy directly."}
                                ]
                            }]
                        }
                    }))?;
                } else if !hold_turn {
                    finish_turn(&state_path, &mut state, "completed")?;
                    if emit_post_completion_warning {
                        send(json!({
                            "method": "warning",
                            "params": {"message": "provider remained live after terminal"}
                        }))?;
                    }
                    if fail_after_turn_completion {
                        if let Some(delay_ms) = fail_after_turn_completion_delay_ms {
                            thread::sleep(Duration::from_millis(delay_ms));
                            // Make the post-terminal liveness observation
                            // deterministic even when parallel tests delay the
                            // controller's next poll until after this process
                            // exits.
                            send(json!({
                                "method": "warning",
                                "params": {"message": "provider remained live after terminal"}
                            }))?;
                        }
                        return Err("configured failure after turn completion".into());
                    }
                    if exit_after_turn_completion {
                        return Ok(());
                    }
                }
            }
            "turn/steer" => send(json!({"id": id, "result": {"accepted": true}}))?,
            "turn/interrupt" => {
                send(json!({"id": id, "result": {"accepted": true}}))?;
                finish_turn(&state_path, &mut state, "interrupted")?;
            }
            _ if id.is_some() => send(json!({
                "id": id,
                "error": {"code": -32601, "message": format!("unsupported fake method {method}")}
            }))?,
            _ => {}
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fake-codex-app-server: {error}");
            ExitCode::FAILURE
        }
    }
}

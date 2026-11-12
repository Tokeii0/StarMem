//! Data-only adapters. Never execute recovered prompts, tools or JavaScript.
use serde_json::{Value, json};

pub(super) fn process_app(name: &str) -> Option<&'static str> {
    match super::basename(name).as_str() {
        "workbuddy.exe" => Some("WorkBuddy"),
        "codebuddy.exe" => Some("CodeBuddy"),
        "qianwen.exe" => Some("千问"),
        "doubao.exe" => Some("豆包"),
        "chatgpt.exe" => Some("ChatGPT"),
        "claude.exe" => Some("Claude"),
        "codex.exe" => Some("Codex"),
        "cursor.exe" => Some("Cursor"),
        "windsurf.exe" => Some("Windsurf"),
        "trae.exe" => Some("Trae"),
        "lm studio.exe" | "lmstudio.exe" => Some("LM Studio"),
        "ollama.exe" | "ollama app.exe" => Some("Ollama"),
        "cherry studio.exe" | "cherrystudio.exe" => Some("Cherry Studio"),
        "chatbox.exe" => Some("Chatbox"),
        "jan.exe" => Some("Jan"),
        "anythingllm.exe" => Some("AnythingLLM"),
        _ => None,
    }
}

pub(super) fn path_app(path: &str) -> Option<&'static str> {
    let p = super::normalized(path);
    // Exact components prevent report filenames and arbitrary mentions becoming apps.
    for part in p.split('\\') {
        let app = match part {
            ".workbuddy" | "workbuddy" => "WorkBuddy",
            ".codebuddy" | "codebuddy" => "CodeBuddy",
            "qianwen" | "qianwenapp" => "千问",
            "doubao" => "豆包",
            "chatgpt" => "ChatGPT",
            ".claude" | "claude" => "Claude",
            ".codex" | "codex" => "Codex",
            "cursor" | ".cursor" => "Cursor",
            "windsurf" | ".windsurf" => "Windsurf",
            "trae" | "trae cn" => "Trae",
            ".lmstudio" | "lm studio" => "LM Studio",
            ".ollama" | "ollama" => "Ollama",
            "cherry-studio" | "cherry studio" => "Cherry Studio",
            "chatbox" => "Chatbox",
            "jan" | ".jan" => "Jan",
            "anythingllm" => "AnythingLLM",
            "open-webui" | "open_webui" => "Open WebUI",
            ".gemini" => "Gemini CLI",
            ".continue" => "Continue",
            "github.copilot-chat" => "GitHub Copilot",
            _ => continue,
        };
        return Some(app);
    }
    None
}

pub(super) struct Artifact {
    pub kind: &'static str,
    pub pointer: String,
    pub data: Value,
}

fn content(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() && s.len() <= 128 * 1024 => {
            // Doubao and some desktop clients wrap text blocks in JSON strings.
            if s.starts_with('{')
                && let Ok(j) = serde_json::from_str::<Value>(s)
                && let Some(t) = j.get("text").and_then(Value::as_str)
            {
                return Some(t.to_owned());
            }
            Some(s.clone())
        }
        Value::Array(a) => {
            let mut texts = Vec::new();
            let mut size = 0;
            for v in a.iter().take(256) {
                let text = if v.is_string() {
                    content(v)
                } else {
                    // Only textual message blocks, never tool arguments/results as assistant text.
                    let ty = v.get("type").and_then(Value::as_str).unwrap_or("text");
                    if matches!(ty, "text" | "input_text" | "output_text") {
                        v.get("text").and_then(content)
                    } else {
                        None
                    }
                };
                if let Some(t) = text {
                    size += t.len();
                    if size > 128 * 1024 {
                        return None;
                    }
                    texts.push(t);
                }
            }
            (!texts.is_empty()).then(|| texts.join("\n"))
        }
        Value::Object(m) => m.get("parts").and_then(content).or_else(|| {
            m.get("text")
                .and_then(Value::as_str)
                .and_then(|_| content(&m["text"]))
        }),
        _ => None,
    }
}

fn scalar(v: &Value, names: &[&str]) -> Value {
    names
        .iter()
        .find_map(|n| {
            v.get(*n)
                .filter(|v| v.is_string() || v.is_number())
                .cloned()
        })
        .unwrap_or(Value::Null)
}

/// No context is borrowed from a neighboring object. A recovered message with
/// no conversation ID stays unassigned. JSON pointers identify enclosing blobs.
pub(super) fn extract(v: &Value, app: &str) -> Vec<Artifact> {
    let mut out = Vec::new();
    walk(v, app, "", 0, &mut out);
    out
}

fn walk(v: &Value, app: &str, path: &str, depth: usize, out: &mut Vec<Artifact>) {
    if depth > 24 || out.len() >= 256 {
        return;
    }
    if let Some(m) = v.as_object() {
        if app == "千问" && qwen_heap(v, path, out) {
            return;
        }
        if app == "千问" {
            qianwen(v, path, out);
        }
        if app == "豆包" {
            doubao(v, path, out);
            if doubao_message(v, path, out) {
                return;
            }
        }
        if matches!(app, "WorkBuddy" | "CodeBuddy")
            && v.get("kind").and_then(Value::as_str) == Some("message")
            && v.get("sessionId").and_then(Value::as_str).is_some()
            && v.pointer("/json/type").and_then(Value::as_str) == Some("error")
            && let Some(message) = v.pointer("/json/error/message").and_then(Value::as_str)
        {
            out.push(Artifact{kind:"ai_client_event",pointer:path.into(),data:json!({"application":app,"session_id":v.get("sessionId"),
                "message":message,"code":v.pointer("/json/error/code"),"source_format":"workbuddy_transport_event",
                "semantics":"客户端通信事件，不是用户或助手的对话正文"})});
            return;
        }
        let direct_role = v
            .get("role")
            .and_then(Value::as_str)
            .or_else(|| v.pointer("/author/role").and_then(Value::as_str));
        let ty = v.get("type").and_then(Value::as_str);
        let role = direct_role
            .or_else(|| match ty {
                Some("user_message") => Some("user"),
                Some("agent_message") => Some("assistant"),
                Some("user" | "assistant") if m.contains_key("content") => ty,
                Some("gemini") if app == "Gemini CLI" => Some("assistant"),
                _ => None,
            })
            .or_else(|| {
                if app == "Cursor" && m.contains_key("bubbleId") {
                    match v.get("type").and_then(Value::as_u64) {
                        Some(1) => Some("user"),
                        Some(2) => Some("assistant"),
                        _ => None,
                    }
                } else {
                    None
                }
            });
        if let Some(role) =
            role.filter(|r| matches!(*r, "user" | "assistant" | "system" | "tool" | "model"))
        {
            let body = ["content", "parts", "text", "message"]
                .iter()
                .find_map(|key| v.get(*key).and_then(content));
            if let Some(body) = body {
                out.push(Artifact {kind:"ai_message", pointer:path.into(), data:json!({
                    "application":app,"role":role,"text":body,
                    "message_id":scalar(v,&["id","message_id","messageId","bubbleId","uuid"]),
                    "conversation_id":scalar(v,&["conversation_id","conversationId","session_id","sessionId","chatId"]),
                    "timestamp_raw":scalar(v,&["timestamp","created_at","create_time","createdAt"]),
                    "model":scalar(v,&["model","model_name"]),
                    "semantics":"驻留结构中的角色与正文；不是发送或服务端接收证明"})});
            }
        }
        // Session summaries are separate from messages; identifiers do not imply history completeness.
        if (m.contains_key("messages")
            || m.contains_key("mapping")
            || m.contains_key("conversation"))
            && let Some(title) = v
                .get("title")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 4096)
        {
            out.push(Artifact {kind:"ai_conversation",pointer:path.into(),data:json!({"application":app,"title":title,
                "conversation_id":scalar(v,&["id","conversation_id","conversationId","sessionId"]),"semantics":"会话元数据"})});
        }
        for (key, child) in m {
            if out.len() >= 256 {
                break;
            }
            // Do not interpret examples, source code, prompt text or embedded tool input as messages.
            if [
                "content",
                "text",
                "prompt",
                "input",
                "arguments",
                "tool_input",
                "systemPrompt",
            ]
            .contains(&key.as_str())
            {
                continue;
            }
            let ptr = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
            if child.is_array() || child.is_object() {
                walk(child, app, &ptr, depth + 1, out);
            }
        }
    } else if let Some(a) = v.as_array() {
        for (i, child) in a.iter().take(4096).enumerate() {
            if out.len() >= 256 {
                break;
            }
            walk(child, app, &format!("{path}/{i}"), depth + 1, out);
        }
    }
}

fn qianwen(v: &Value, path: &str, out: &mut Vec<Artifact>) {
    if v.get("biz_id").and_then(Value::as_str) == Some("ai_qwen") {
        if v.get("scene").and_then(Value::as_str) == Some("chat")
            && v.get("req_id").and_then(Value::as_str).is_some()
            && let Some(messages) = v.get("messages").and_then(Value::as_array)
        {
            for (i, msg) in messages.iter().take(256).enumerate() {
                if out.len() >= 256 {
                    break;
                }
                let Some(body) = msg
                    .get("content")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && s.len() <= 128 * 1024)
                else {
                    continue;
                };
                if msg.get("mime_type").and_then(Value::as_str) != Some("text/plain")
                    || msg.pointer("/meta_data/ori_query").and_then(Value::as_str) != Some(body)
                {
                    continue;
                }
                out.push(Artifact {kind:"ai_message",pointer:format!("{path}/messages/{i}"),data:json!({
                    "application":"千问","role":"user","text":body,"request_id":v.get("req_id"),
                    "conversation_id":v.get("session_id"),"parent_request_id":v.get("parent_req_id"),"topic_id":v.get("topic_id"),
                    "model":v.get("model"),"status_raw":msg.get("status"),"source_format":"qwen_chat_v2_request",
                    "semantics":"千问客户端请求，content 与 ori_query 一致；发送成功需与响应或会话同步记录核对"})});
            }
        }
        if v.get("event").and_then(Value::as_str) == Some("dialogue_sync")
            && v.pointer("/content/target").and_then(Value::as_str) == Some("session")
            && let Some(entries) = v.pointer("/content/payload").and_then(Value::as_array)
        {
            for (i, e) in entries.iter().take(256).enumerate() {
                if out.len() >= 256 {
                    break;
                }
                if e.get("session_id").and_then(Value::as_str).is_none() {
                    continue;
                }
                out.push(Artifact{kind:"ai_conversation",pointer:format!("{path}/content/payload/{i}"),data:json!({
                    "application":"千问","conversation_id":e.get("session_id"),"title":e.get("title"),"operation":v.pointer("/content/op_type"),
                    "created_at_ms":e.get("created_at"),"updated_at_ms":e.get("updated_at"),"last_req_timestamp_ms":e.get("last_req_timestamp"),
                    "last_complete_req_pos":e.get("last_complete_req_pos"),"source_format":"qwen_dialogue_sync",
                    "semantics":"会话同步元数据；标题不代替用户正文，更新时间不直接等同发送时间"})});
            }
        }
    }
    // Decode only the documented-by-observation realtime transport field, not
    // arbitrary JSON embedded in message text or tool arguments.
    if v.get("appid").and_then(Value::as_str) == Some("qwen_win")
        && v.get("serviceid").and_then(Value::as_str) == Some("chat_realtime_sync")
        && let Some(s) = v.pointer("/msg/data").and_then(Value::as_str)
        && s.len() <= 128 * 1024
        && let Ok(j) = serde_json::from_str::<Value>(s)
    {
        qianwen(&j, &format!("{path}/msg/data@json"), out);
    }
}

fn doubao(v: &Value, path: &str, out: &mut Vec<Artifact>) {
    // The send envelope (option + conversation + messages) distinguishes a
    // client request from a server's recent-conversation response.
    if v.pointer("/option/create_time_ms")
        .and_then(Value::as_u64)
        .is_none()
        || !(v.get("conversation").is_some_and(Value::is_object)
            || v.get("client_meta").is_some_and(Value::is_object))
    {
        return;
    }
    let Some(messages) = v.get("messages").and_then(Value::as_array) else {
        return;
    };
    for (i, m) in messages.iter().take(256).enumerate() {
        if out.len() >= 256 {
            break;
        }
        let Some(id) = m.get("local_message_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(blocks) = m.get("content_block").and_then(Value::as_array) else {
            continue;
        };
        let texts: Vec<_> = blocks
            .iter()
            .filter_map(|b| {
                b.pointer("/content/text_block/text")
                    .and_then(Value::as_str)
            })
            .collect();
        let body = texts.join("\n");
        if body.is_empty() || body.len() > 128 * 1024 {
            continue;
        }
        out.push(Artifact{kind:"ai_message",pointer:format!("{path}/messages/{i}"),data:json!({"application":"豆包","role":"user","text":body,"message_id":id,
            "conversation_id":v.pointer("/conversation/conversation_id").or_else(||v.pointer("/client_meta/conversation_id")),
            "local_conversation_id":v.pointer("/client_meta/local_conversation_id"),"timestamp_raw":v.pointer("/option/create_time_ms"),"timestamp_unit":"milliseconds","status_raw":m.get("message_status"),
            "source_format":"doubao_send_envelope","semantics":"客户端发送请求；状态码保持原值，未推定服务端已接收"})});
    }
}

fn nonempty(v: &Value, key: &str) -> bool {
    v.get(key)
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.len() <= 256)
}

/// Client state is linked through actual question/answer references. Tabbed
/// alternatives are separate answer variants, not concatenated or deduplicated
/// just because their request IDs match.
fn qwen_heap(v: &Value, path: &str, out: &mut Vec<Artifact>) -> bool {
    let (round, ptr) = if let Some(r) = v.get("chatRound") {
        (r, format!("{path}/chatRound"))
    } else {
        (v, path.to_owned())
    };
    if nonempty(round, "sessionId") && round.get("questions").is_some_and(Value::is_array) {
        for (qi, q) in round["questions"]
            .as_array()
            .into_iter()
            .flatten()
            .take(256)
            .enumerate()
        {
            if !nonempty(q, "id") {
                continue;
            }
            let qp = format!("{ptr}/questions/{qi}");
            if let Some(cards) = q.get("cards").and_then(Value::as_array) {
                for (ci, c) in cards.iter().enumerate() {
                    if c.get("mimeType").and_then(Value::as_str) == Some("text/plain")
                        && let Some(body) = c.get("content").and_then(content)
                    {
                        out.push(Artifact{kind:"ai_message",pointer:format!("{qp}/cards/{ci}"),data:json!({"application":"千问","role":"user","text":body,
                            "message_id":q.get("id"),"conversation_id":round.get("sessionId"),"round_id":round.get("id"),"model":q.get("model"),
                            "source_format":"qwen_client_question","semantics":"千问会话对象引用的用户文本卡片；正文与关联由内存结构恢复"})});
                    }
                }
            }
            if let Some(answers) = q.get("answers").and_then(Value::as_array) {
                for (i, a) in answers.iter().enumerate() {
                    qwen_answer(a, &format!("{qp}/answers/{i}"), round.get("sessionId"), out);
                }
            }
        }
        return true;
    }
    if nonempty(v, "reqId")
        && v.get("content").is_some_and(Value::is_object)
        && nonempty(v, "status")
    {
        qwen_answer(v, path, None, out);
        return true;
    }
    false
}

fn qwen_answer(v: &Value, path: &str, conversation: Option<&Value>, out: &mut Vec<Artifact>) {
    if !nonempty(v, "reqId") {
        return;
    }
    let Some(cards) = v.pointer("/content/cards").and_then(Value::as_array) else {
        return;
    };
    for (ci, c) in cards.iter().enumerate() {
        let mut texts = vec![];
        let mime = c.get("mimeType").and_then(Value::as_str).unwrap_or("");
        if matches!(mime, "text/plain" | "text/markdown")
            && let Some(text) = c.get("content").and_then(content)
        {
            texts.push((
                format!("{path}/content/cards/{ci}"),
                Value::Null,
                Value::Null,
                text,
                c.get("status").cloned().unwrap_or(Value::Null),
            ));
        }
        if mime == "multi_load/iframe"
            && let Some(loads) = c.pointer("/metaData/multi_load").and_then(Value::as_array)
        {
            for (li, l) in loads.iter().enumerate() {
                if l.get("type").and_then(Value::as_str) != Some("tab_container") {
                    continue;
                }
                for (ti, t) in l
                    .pointer("/content/tabs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    if nonempty(t, "tab_id")
                        && let Some(text) = t.get("content").and_then(content)
                    {
                        texts.push((format!("{path}/content/cards/{ci}/metaData/multi_load/{li}/content/tabs/{ti}"),t["tab_id"].clone(),t["tab_title"].clone(),text,t["status"].clone()));
                    }
                }
            }
        }
        for (ptr, variant, title, text, status) in texts {
            if out.len() >= 256 {
                return;
            }
            out.push(Artifact{kind:"ai_message",pointer:ptr,data:json!({"application":"千问","role":"assistant","text":text,
                "request_id":v.get("reqId"),"conversation_id":conversation,"topic_id":v.get("topicId"),"variant_id":variant,"variant_title":title,
                "timestamp_raw":v.get("createTime"),"timestamp_unit":"milliseconds","model":v.get("model"),"status_raw":status,
                "generation_complete":status.as_str().map(|s|s=="complete"),"source_format":"qwen_client_answer",
                "semantics":"千问回答卡片原文；多候选回答分别保留，生成完成状态取自对应卡片/标签页，不推定全部历史已恢复"})});
        }
    }
}

fn doubao_message(v: &Value, path: &str, out: &mut Vec<Artifact>) -> bool {
    if !nonempty(v, "conversation_id")
        || !v
            .get("create_time")
            .is_some_and(|v| v.is_string() || v.is_number())
    {
        return false;
    }
    let role = match v.get("user_type").and_then(Value::as_u64) {
        Some(1) => "user",
        Some(2) => "assistant",
        _ => return false,
    };
    let blocks = v
        .get("content_blocks_v2")
        .or_else(|| v.get("content_block"))
        .and_then(Value::as_array);
    let Some(blocks) = blocks else {
        return false;
    };
    let mut texts = vec![];
    let mut finished = true;
    let mut known_finish = true;
    for b in blocks {
        if b.get("block_type").and_then(Value::as_u64) != Some(10000) {
            continue;
        }
        if let Some(text) = b.pointer("/content/text_block/text").and_then(content) {
            texts.push(text);
            match b.get("is_finish").and_then(Value::as_bool) {
                Some(b) => finished &= b,
                None => known_finish = false,
            }
        }
    }
    let body = texts.join("\n");
    if body.is_empty() || body.len() > 128 * 1024 {
        return false;
    }
    out.push(Artifact{kind:"ai_message",pointer:path.into(),data:json!({"application":"豆包","role":role,"text":body,
        "message_id":scalar(v,&["message_id","unique_id","local_message_id"]),"local_message_id":v.get("local_message_id"),
        "conversation_id":v.get("conversation_id"),"local_conversation_id":v.get("local_conversation_id"),"reply_id":v.get("reply_id"),
        "timestamp_raw":v.get("create_time"),"timestamp_unit":"client_raw","status_raw":v.get("status"),
        "generation_complete":if known_finish {Some(finished)}else{None},"source_format":"doubao_client_message",
        "semantics":"豆包消息对象：user_type 1 为用户、2 为助手；仅恢复文本块，搜索参考材料不混入助手正文"})});
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_heap_answers_preserve_variants_and_stream_completion() {
        let long = "原文😀".repeat(600);
        let answer = json!({"reqId":"r1","status":"generating","createTime":1786678000000u64,
            "content":{"cards":[{"mimeType":"multi_load/iframe","metaData":{"multi_load":[{"type":"tab_container","content":{"tabs":[
                {"tab_id":"a","tab_title":"回答一","content":long,"status":"processing"},
                {"tab_id":"b","tab_title":"回答二","content":"第二份回答","status":"complete"}]}}]}}]}});
        let round = json!({"sessionId":"s1","questions":[{"id":"q1","cards":[{"mimeType":"text/plain","content":"提问"}],"answers":[answer]}]});
        let rows = extract(&round, "千问");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1].data["text"], long);
        assert_eq!(rows[1].data["generation_complete"], false);
        assert_eq!(rows[2].data["generation_complete"], true);
        assert_eq!(rows[2].data["conversation_id"], "s1");
        assert_eq!(rows[2].data["variant_id"], "b");
    }
    #[test]
    fn doubao_client_meta_and_memory_messages_exclude_search_reference_text() {
        let block = json!({"block_type":10000,"is_finish":false,"content":{"text_block":{"text":"真正的消息"}}});
        let request = json!({"client_meta":{"conversation_id":"","local_conversation_id":"local_1"},"option":{"create_time_ms":1786678000000u64},
            "messages":[{"local_message_id":"m1","content_block":[block.clone()]}]});
        let rows = extract(&request, "豆包");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].data["local_conversation_id"], "local_1");
        let v = json!({"conversation_id":"c1","message_id":"m2","user_type":2,"create_time":1786678000000u64,"content_blocks_v2":[block,
            {"block_type":10025,"content":{"search_query_result_block":{"text":"网页原文"}}}]});
        let rows = extract(&v, "豆包");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].data["text"], "真正的消息");
        assert_eq!(rows[0].data["role"], "assistant");
        assert_eq!(rows[0].data["generation_complete"], false);
        assert!(
            extract(
                &json!({"role":{"typeName":"ZodEnum"},"content":{"typeName":"ZodString"}}),
                "WorkBuddy"
            )
            .is_empty()
        );
    }
    #[test]
    fn qianwen_request_and_nested_sync_keep_distinct_time_semantics() {
        let request = json!({"biz_id":"ai_qwen","scene":"chat","req_id":"r1","session_id":"s1","model":"Qwen",
            "messages":[{"mime_type":"text/plain","content":"中文问题","meta_data":{"ori_query":"中文问题"},"status":"complete"}]});
        let rows = extract(&request, "千问");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].data["role"], "user");
        assert_eq!(rows[0].data["conversation_id"], "s1");
        let sync = json!({"biz_id":"ai_qwen","event":"dialogue_sync","content":{"target":"session","op_type":"update","payload":[{"session_id":"s1","title":"自动标题","last_req_timestamp":123456789,"updated_at":123456999}]}});
        let outer = json!({"appid":"qwen_win","serviceid":"chat_realtime_sync","msg":{"data":sync.to_string()}});
        let rows = extract(&outer, "千问");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "ai_conversation");
        assert!(rows[0].pointer.contains("@json"));
        assert_eq!(rows[0].data["last_req_timestamp_ms"], 123456789);
        assert!(extract(&request, "WorkBuddy").is_empty());
    }
    #[test]
    fn common_formats_keep_roles_and_do_not_borrow_identifiers() {
        let samples = [
            (
                "Codex",
                json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"答复"}]}}),
            ),
            (
                "Claude",
                json!({"type":"user","sessionId":"outer","message":{"role":"user","content":"提问"}}),
            ),
            (
                "ChatGPT",
                json!({"mapping":{"a":{"message":{"author":{"role":"assistant"},"content":{"parts":["回复"]}}}}}),
            ),
            (
                "WorkBuddy",
                json!({"role":"user","sessionId":"s1","content":[{"type":"input_text","text":"测试"}]}),
            ),
        ];
        for (app, v) in samples {
            let r = extract(&v, app);
            assert_eq!(r.len(), 1);
            assert!(r[0].data["text"].is_string());
        }
        assert!(extract(&json!({"text":"assistant", "token":"secret"}), "WorkBuddy").is_empty());
        let r = extract(
            &json!({"sessionId":"outside","message":{"role":"user","content":"hello"}}),
            "Claude",
        );
        assert!(r[0].data["conversation_id"].is_null());
    }
    #[test]
    fn paths_are_component_scoped() {
        assert_eq!(
            path_app(r"C:\Users\a\.workbuddy\projects\a.jsonl"),
            Some("WorkBuddy")
        );
        assert_eq!(path_app(r"C:\NotWorkBuddy\chat.json"), None);
    }
}

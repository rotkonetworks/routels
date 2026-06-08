// LSP server backed by the same per-platform linters used by the CLI.
//
// One stdio session = one tower-lsp `LspService`. The server keeps an open
// document map keyed by URI; on every didOpen/didChange/didSave it re-lints
// the document and publishes diagnostics. Hover and completion are static
// per-platform maps for v1.

use crate::bird;
use crate::debian;
use crate::diag::{Diagnostic, Severity};
use crate::eos;
use crate::frr;
use crate::haproxy;
use crate::mikrotik;
use crate::nft;
use crate::sysctl;
use crate::vyos;
use crate::wireguard;

use dashmap::DashMap;
use std::sync::Arc;
use tower_lsp::jsonrpc::Result as RpcResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Platform {
    Eos,
    Frr,
    Vyos,
    Mikrotik,
    Bird,
    Nft,
    Debian,
    Wireguard,
    Haproxy,
    Sysctl,
}

impl Platform {
    fn from_language_id(id: &str) -> Option<Self> {
        match id {
            "eos" | "arista" => Some(Self::Eos),
            "frr" | "vtysh" | "frrouting" => Some(Self::Frr),
            "vyos" => Some(Self::Vyos),
            "routeros" | "mikrotik" => Some(Self::Mikrotik),
            "bird" => Some(Self::Bird),
            "nftables" | "nft" => Some(Self::Nft),
            "debinterfaces" | "interfaces" => Some(Self::Debian),
            "wireguard" | "wg-quick" => Some(Self::Wireguard),
            "haproxy" => Some(Self::Haproxy),
            "sysctl" => Some(Self::Sysctl),
            _ => None,
        }
    }

    fn lint(self, file: &str, src: &str) -> Vec<Diagnostic> {
        match self {
            Self::Eos => eos::lint(file, src),
            Self::Frr => frr::lint(file, src),
            Self::Vyos => vyos::lint(file, src),
            Self::Mikrotik => mikrotik::lint(file, src),
            Self::Bird => bird::lint(file, src),
            Self::Nft => nft::lint(file, src),
            Self::Debian => debian::lint(file, src),
            Self::Wireguard => wireguard::lint(file, src),
            Self::Haproxy => haproxy::lint(file, src),
            Self::Sysctl => sysctl::lint(file, src),
        }
    }
}

struct DocState {
    platform: Platform,
    text: String,
}

struct Backend {
    client: Client,
    docs: Arc<DashMap<Url, DocState>>,
}

impl Backend {
    fn new(client: Client) -> Self {
        Self {
            client,
            docs: Arc::new(DashMap::new()),
        }
    }

    async fn refresh(&self, uri: Url) {
        let Some(doc) = self.docs.get(&uri) else {
            return;
        };
        let file_name = uri.to_string();
        let diags = doc.platform.lint(&file_name, &doc.text);
        let lsp_diags: Vec<Diagnostic_> = diags.into_iter().map(to_lsp_diag).collect();
        self.client.publish_diagnostics(uri, lsp_diags, None).await;
    }
}

// Local alias so the variable name doesn't collide with our own `Diagnostic`.
type Diagnostic_ = tower_lsp::lsp_types::Diagnostic;

fn to_lsp_diag(d: Diagnostic) -> Diagnostic_ {
    let line = d.line.saturating_sub(1) as u32;
    let col = d.col.saturating_sub(1) as u32;
    let range = Range {
        start: Position {
            line,
            character: col,
        },
        end: Position {
            line,
            character: col + 1,
        },
    };
    let severity = Some(match d.severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
        Severity::Hint => DiagnosticSeverity::HINT,
    });
    Diagnostic_ {
        range,
        severity,
        code: Some(NumberOrString::String(d.code.to_string())),
        code_description: None,
        source: Some("routels".to_string()),
        message: d.message,
        related_information: None,
        tags: None,
        data: None,
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> RpcResult<InitializeResult> {
        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "routels".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![" ".to_string(), "/".to_string()]),
                    ..Default::default()
                }),
                inlay_hint_provider: Some(OneOf::Left(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "routels LSP ready")
            .await;
    }

    async fn shutdown(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn did_open(&self, p: DidOpenTextDocumentParams) {
        let Some(platform) = Platform::from_language_id(&p.text_document.language_id) else {
            return;
        };
        let uri = p.text_document.uri.clone();
        self.docs.insert(
            uri.clone(),
            DocState {
                platform,
                text: p.text_document.text,
            },
        );
        self.refresh(uri).await;
    }

    async fn did_change(&self, p: DidChangeTextDocumentParams) {
        let uri = p.text_document.uri.clone();
        if let Some(mut doc) = self.docs.get_mut(&uri) {
            // FULL sync: last change carries the full text.
            if let Some(change) = p.content_changes.into_iter().last() {
                doc.text = change.text;
            }
        }
        self.refresh(uri).await;
    }

    async fn did_save(&self, p: DidSaveTextDocumentParams) {
        if let Some(text) = p.text {
            if let Some(mut doc) = self.docs.get_mut(&p.text_document.uri) {
                doc.text = text;
            }
        }
        self.refresh(p.text_document.uri).await;
    }

    async fn did_close(&self, p: DidCloseTextDocumentParams) {
        self.docs.remove(&p.text_document.uri);
        // Clear any stale diagnostics.
        self.client
            .publish_diagnostics(p.text_document.uri, vec![], None)
            .await;
    }

    async fn hover(&self, p: HoverParams) -> RpcResult<Option<Hover>> {
        let uri = p.text_document_position_params.text_document.uri;
        let pos = p.text_document_position_params.position;
        let Some(doc) = self.docs.get(&uri) else {
            return Ok(None);
        };
        let Some(line) = doc.text.lines().nth(pos.line as usize) else {
            return Ok(None);
        };
        let token = word_at(line, pos.character as usize);
        if token.is_empty() {
            return Ok(None);
        }
        let docs = crate::lsp_docs::hover_lookup(doc.platform_kind(), &token);
        Ok(docs.map(|text| Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: text.to_string(),
            }),
            range: None,
        }))
    }

    async fn code_action(&self, p: CodeActionParams) -> RpcResult<Option<CodeActionResponse>> {
        let uri = p.text_document.uri.clone();
        let Some(doc) = self.docs.get(&uri) else {
            return Ok(None);
        };
        let mut actions: Vec<CodeActionOrCommand> = Vec::new();

        for d in &p.context.diagnostics {
            let Some(NumberOrString::String(code)) = &d.code else {
                continue;
            };
            let line_no = d.range.start.line as usize;
            let line = doc.text.lines().nth(line_no).unwrap_or("");

            match code.as_str() {
                // Insert `exit-address-family` at the appropriate indent.
                "FRR053" => {
                    let indent = " ".repeat(line.len() - line.trim_start().len());
                    let insert = format!("{indent}exit-address-family\n");
                    actions.push(code_action_edit(
                        &uri,
                        "Insert `exit-address-family`",
                        Range {
                            start: Position {
                                line: (line_no as u32) + 1,
                                character: 0,
                            },
                            end: Position {
                                line: (line_no as u32) + 1,
                                character: 0,
                            },
                        },
                        insert,
                        Some(d.clone()),
                    ));
                }
                // Replace leading tabs with 3 spaces (EOS convention).
                "EOS001" => {
                    let tabs = line.chars().take_while(|c| *c == '\t').count();
                    if tabs > 0 {
                        let new_indent = "   ".repeat(tabs);
                        let rest = &line[tabs..];
                        let new_line = format!("{}{}", new_indent, rest);
                        actions.push(code_action_edit(
                            &uri,
                            "Convert leading tabs to spaces (3 each)",
                            Range {
                                start: Position {
                                    line: line_no as u32,
                                    character: 0,
                                },
                                end: Position {
                                    line: line_no as u32,
                                    character: line.len() as u32,
                                },
                            },
                            new_line,
                            Some(d.clone()),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(Some(actions))
    }

    async fn inlay_hint(&self, p: InlayHintParams) -> RpcResult<Option<Vec<InlayHint>>> {
        let uri = p.text_document.uri;
        let Some(doc) = self.docs.get(&uri) else {
            return Ok(None);
        };
        let mut hints = Vec::new();
        let start_line = p.range.start.line as usize;
        let end_line = p.range.end.line as usize;
        for (i, line) in doc.text.lines().enumerate() {
            if i < start_line || i > end_line {
                continue;
            }
            for hint in inlay_hints_for_line(i as u32, line) {
                hints.push(hint);
            }
        }
        Ok(Some(hints))
    }

    async fn completion(&self, p: CompletionParams) -> RpcResult<Option<CompletionResponse>> {
        let uri = p.text_document_position.text_document.uri;
        let Some(doc) = self.docs.get(&uri) else {
            return Ok(None);
        };
        let items: Vec<CompletionItem> = crate::lsp_docs::completion_keywords(doc.platform_kind())
            .iter()
            .map(|(label, detail)| CompletionItem {
                label: label.to_string(),
                detail: Some(detail.to_string()),
                kind: Some(CompletionItemKind::KEYWORD),
                ..Default::default()
            })
            .collect();
        Ok(Some(CompletionResponse::Array(items)))
    }
}

// expose platform to the docs module via a small kind enum (decouples lsp_docs from this file)
impl DocState {
    fn platform_kind(&self) -> crate::lsp_docs::Kind {
        match self.platform {
            Platform::Eos => crate::lsp_docs::Kind::Eos,
            Platform::Frr => crate::lsp_docs::Kind::Frr,
            Platform::Vyos => crate::lsp_docs::Kind::Vyos,
            Platform::Mikrotik => crate::lsp_docs::Kind::Mikrotik,
            Platform::Bird => crate::lsp_docs::Kind::Bird,
            Platform::Nft => crate::lsp_docs::Kind::Nft,
            Platform::Debian => crate::lsp_docs::Kind::Debian,
            Platform::Wireguard => crate::lsp_docs::Kind::Wireguard,
            Platform::Haproxy => crate::lsp_docs::Kind::Haproxy,
            Platform::Sysctl => crate::lsp_docs::Kind::Sysctl,
        }
    }
}

fn code_action_edit(
    uri: &Url,
    title: &str,
    range: Range,
    new_text: String,
    triggering: Option<Diagnostic_>,
) -> CodeActionOrCommand {
    let mut changes = std::collections::HashMap::new();
    changes.insert(uri.clone(), vec![TextEdit { range, new_text }]);
    CodeActionOrCommand::CodeAction(CodeAction {
        title: title.to_string(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: triggering.map(|d| vec![d]),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn inlay_hints_for_line(line_no: u32, line: &str) -> Vec<InlayHint> {
    let mut out = Vec::new();
    // ASN hint after `as N` / `as-number N` / `remote-as N` / `local as N` / `router bgp N`
    for cap in find_asn_positions(line) {
        if let Some(label) = asn_class(cap.value) {
            out.push(make_hint(line_no, cap.end_col, format!(" ({})", label)));
        }
    }
    // IPv4 prefix size hint: `1.2.3.0/24` → ` (256 IPs)`
    for cap in find_ipv4_cidr_positions(line) {
        if let Some(size) = ipv4_prefix_size(cap.value) {
            out.push(make_hint(line_no, cap.end_col, format!(" ({} IPs)", size)));
        }
    }
    // Well-known port hint: standalone `=N` after dst-port/src-port/port keys.
    for cap in find_port_positions(line) {
        if let Some(name) = well_known_port(cap.value) {
            out.push(make_hint(line_no, cap.end_col, format!(" ({})", name)));
        }
    }
    out
}

fn make_hint(line: u32, col: u32, label: String) -> InlayHint {
    InlayHint {
        position: Position {
            line,
            character: col,
        },
        label: InlayHintLabel::String(label),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: None,
        padding_right: None,
        data: None,
    }
}

struct Capture<'a> {
    value: &'a str,
    end_col: u32,
}

fn find_asn_positions(line: &str) -> Vec<Capture<'_>> {
    let mut out = Vec::new();
    // Patterns: ` as N`, ` remote-as N`, ` local as N`, `router bgp N`, `system-as N`
    for marker in [
        " as ",
        " remote-as ",
        " local as ",
        "router bgp ",
        " system-as ",
    ] {
        if let Some(idx) = line.find(marker) {
            let after = &line[idx + marker.len()..];
            let end_in_after = after
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after.len());
            let v = &after[..end_in_after];
            if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) {
                out.push(Capture {
                    value: v,
                    end_col: (idx + marker.len() + end_in_after) as u32,
                });
            }
        }
    }
    out
}

fn find_ipv4_cidr_positions(line: &str) -> Vec<Capture<'_>> {
    // Naive scan: find <d.d.d.d/N> by reading runs of [digit . / ].
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit() || bytes[i] == b'.' || bytes[i] == b'/')
            {
                i += 1;
            }
            let tok = &line[start..i];
            if tok.contains('/')
                && tok.matches('.').count() == 3
                && crate::diag::is_valid_ipv4_cidr(tok)
            {
                out.push(Capture {
                    value: tok,
                    end_col: i as u32,
                });
            }
            continue;
        }
        i += 1;
    }
    out
}

fn find_port_positions(line: &str) -> Vec<Capture<'_>> {
    let mut out = Vec::new();
    for key in ["dst-port=", "src-port=", "port="] {
        let mut start = 0;
        while let Some(off) = line[start..].find(key) {
            let val_start = start + off + key.len();
            let after = &line[val_start..];
            let end_in_after = after
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after.len());
            let v = &after[..end_in_after];
            if !v.is_empty() {
                out.push(Capture {
                    value: v,
                    end_col: (val_start + end_in_after) as u32,
                });
            }
            start = val_start + end_in_after;
        }
    }
    out
}

fn asn_class(s: &str) -> Option<&'static str> {
    let n: u32 = s.parse().ok()?;
    Some(match n {
        0 => "reserved",
        1..=23455 => "public",
        23456 => "AS_TRANS",
        23457..=64495 => "public",
        64496..=64511 => "doc/16-bit",
        64512..=65534 => "private/16-bit",
        65535 => "reserved",
        65536..=65551 => "doc/32-bit",
        4200000000..=4294967294 => "private/32-bit",
        4294967295 => "reserved",
        _ => "public/32-bit",
    })
}

fn ipv4_prefix_size(s: &str) -> Option<u64> {
    let (_, p) = s.split_once('/')?;
    let n: u32 = p.parse().ok()?;
    if n > 32 {
        return None;
    }
    Some(1u64 << (32 - n))
}

fn well_known_port(s: &str) -> Option<&'static str> {
    let n: u16 = s.parse().ok()?;
    Some(match n {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp-server",
        68 => "dhcp-client",
        80 => "http",
        110 => "pop3",
        123 => "ntp",
        143 => "imap",
        179 => "bgp",
        443 => "https",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        3306 => "mysql",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        51820 => "wireguard",
        _ => return None,
    })
}

fn word_at(line: &str, col: usize) -> String {
    // Extract a contiguous run of [A-Za-z0-9_/-] around `col`.
    let bytes = line.as_bytes();
    if col > bytes.len() {
        return String::new();
    }
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'/';
    let mut start = col;
    while start > 0 && is_word(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = col;
    while end < bytes.len() && is_word(bytes[end]) {
        end += 1;
    }
    line[start..end].to_string()
}

pub fn run() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let (service, socket) = LspService::new(Backend::new);
        Server::new(stdin, stdout, socket).serve(service).await;
    });
}

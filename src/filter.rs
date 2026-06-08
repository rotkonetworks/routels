// Diagnostic post-processing pipeline.
//
// A `DiagFilter` transforms `Vec<Diagnostic>` end-to-end. Filters compose with
// `and_then`, so each concern (dedup, severity threshold, code ignores, …) is
// a small named function instead of a branch inside `main`.
//
// This is the Finagle Filter idea, scaled down: synchronous, no Service trait,
// just `Vec<Diagnostic> -> Vec<Diagnostic>`. We don't go further because the
// rest of routels is a one-shot CLI, where async/Service buys nothing.

use crate::diag::{Diagnostic, Severity};
use std::collections::HashSet;

pub type DiagFilter = Box<dyn Fn(Vec<Diagnostic>) -> Vec<Diagnostic>>;

pub struct Pipeline {
    filters: Vec<DiagFilter>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    pub fn and_then(mut self, f: DiagFilter) -> Self {
        self.filters.push(f);
        self
    }

    pub fn run(&self, mut diags: Vec<Diagnostic>) -> Vec<Diagnostic> {
        for f in &self.filters {
            diags = f(diags);
        }
        diags
    }
}

/// Keep diagnostics at or above the given severity (Error is the highest).
pub fn severity_min(min: Severity) -> DiagFilter {
    let cutoff = min.rank();
    Box::new(move |diags| {
        diags
            .into_iter()
            .filter(|d| d.severity.rank() <= cutoff)
            .collect()
    })
}

/// Drop diagnostics whose code matches any of the given codes.
pub fn ignore_codes(codes: Vec<String>) -> DiagFilter {
    let set: HashSet<String> = codes.into_iter().collect();
    Box::new(move |diags| {
        diags
            .into_iter()
            .filter(|d| !set.contains(d.code))
            .collect()
    })
}

/// Collapse exact duplicates (same file/line/col/code/message).
pub fn dedup() -> DiagFilter {
    Box::new(|diags| {
        let mut seen: HashSet<(String, usize, usize, &'static str, String)> = HashSet::new();
        let mut out = Vec::with_capacity(diags.len());
        for d in diags {
            let key = (d.file.clone(), d.line, d.col, d.code, d.message.clone());
            if seen.insert(key) {
                out.push(d);
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(sev: Severity, code: &'static str) -> Diagnostic {
        Diagnostic::new("f", 1, 1, sev, code, "msg")
    }

    #[test]
    fn severity_min_keeps_severe() {
        let input = vec![
            d(Severity::Error, "A"),
            d(Severity::Warning, "B"),
            d(Severity::Info, "C"),
            d(Severity::Hint, "D"),
        ];
        let out = severity_min(Severity::Warning)(input);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|x| x.code == "A"));
        assert!(out.iter().any(|x| x.code == "B"));
    }

    #[test]
    fn ignore_codes_drops_matches() {
        let input = vec![d(Severity::Error, "A"), d(Severity::Error, "B")];
        let out = ignore_codes(vec!["A".into()])(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, "B");
    }

    #[test]
    fn dedup_collapses_duplicates() {
        let input = vec![
            d(Severity::Error, "A"),
            d(Severity::Error, "A"),
            d(Severity::Error, "B"),
        ];
        let out = dedup()(input);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn pipeline_composes_in_order() {
        let p = Pipeline::new()
            .and_then(ignore_codes(vec!["A".into()]))
            .and_then(dedup());
        let out = p.run(vec![
            d(Severity::Error, "A"),
            d(Severity::Error, "B"),
            d(Severity::Error, "B"),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, "B");
    }
}

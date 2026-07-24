// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **deterministic, rule-based v1 prompt compressor** — the whole of Headroom's shrinking logic,
//! kept as a pure, dependency-light module so it is exhaustively unit-testable without any FFI, JSON,
//! or engine state.
//!
//! ## Design: conservative, lossless-of-meaning, deterministic
//!
//! v1 is a RULE-BASED normalizer, NOT an ML/semantic compressor. It only removes redundancy that a
//! reader/model cannot distinguish from the original:
//!
//! 1. **Trailing whitespace** on every line is stripped (`"foo   "` → `"foo"`).
//! 2. **Runs of intra-line whitespace** (spaces/tabs) collapse to a single space, EXCEPT leading
//!    indentation, which is preserved (indentation can be meaningful — code, YAML, markdown lists).
//! 3. **Runs of blank lines** collapse to a single blank line (`"\n\n\n\n"` → `"\n\n"`).
//! 4. **Consecutive identical non-blank lines** de-duplicate to one (`"go\ngo\ngo"` → `"go"`).
//!
//! Every rule is IDEMPOTENT (compressing twice equals compressing once) and DETERMINISTIC (no RNG, no
//! clock, no map iteration order). Nothing that changes meaning is touched: distinct lines are never
//! merged, non-adjacent duplicates are never removed (a repeated instruction 40 lines apart may be
//! deliberate emphasis), and word/token content inside a line is never dropped — only whitespace runs
//! are normalized. A single space between words is never removed, so no two words are ever fused.
//!
//! Repeated *system-prompt blocks* are handled by an additional SAFE rule:
//!
//! 5. **A run of an identical multi-line block repeated back-to-back** collapses to one copy — but
//!    ONLY when the text is EXACTLY N adjacent copies of the same block and nothing else (`AB AB AB`
//!    → `AB`). This is detected structurally (the whole normalized body is checked for being a clean
//!    K-fold repetition of its first `len/K` lines) so it can never merge two *different* blocks or
//!    drop content that isn't a whole-body exact repeat. A pasted-twice system prompt is the canonical
//!    case. Anything not a clean whole-body repetition is left untouched (abstain-on-uncertainty).
//!
//! Rule 5 runs at the whole-(field) granularity AFTER rules 1–4, so single-line adjacent duplicates
//! are already handled by rule 4 and rule 5 only adds the multi-line-block case.
//!
//! ## FUTURE (a judgment call, flagged for review)
//!
//! A semantic/LLMLingua-style compressor (drop low-information tokens, summarize, budget by perplexity)
//! would save far more but is inherently LOSSY and non-deterministic, needs a model + network, and
//! cannot make the "never drops non-redundant content" guarantee this gate rests on. It is deliberately
//! OUT of v1. When/if added it must be OPT-IN (an explicit aggressiveness level), never the default,
//! and must not weaken the abstain-on-uncertainty posture.

/// How aggressively to compress. v1 exposes only the two SAFE rule-sets; both are lossless-of-meaning.
/// A future `Semantic` level (lossy, model-backed) would slot in here as an explicit opt-in — never a
/// silent default (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// Trailing-whitespace strip + blank-run collapse ONLY. The most conservative useful setting.
    Conservative,
    /// Everything in `Conservative` PLUS intra-line whitespace-run collapse and consecutive-identical
    /// -line de-duplication. The default: still lossless-of-meaning, just a bit more thorough.
    #[default]
    Balanced,
}

impl Level {
    /// Parse the operator-facing knob string. Unknown/empty → the safe default (`Balanced`); an
    /// operator typo can never make the gate MORE aggressive than documented.
    pub fn parse(s: &str) -> Level {
        match s.trim().to_ascii_lowercase().as_str() {
            "conservative" | "min" | "low" => Level::Conservative,
            // "balanced" and anything unrecognized both resolve to the safe default.
            _ => Level::Balanced,
        }
    }

    /// The stable wire name (for `describe`/`status` echo).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Conservative => "conservative",
            Level::Balanced => "balanced",
        }
    }
}

/// Collapse every run of spaces/tabs in `s` to a single space, but PRESERVE leading indentation (the
/// run of whitespace at the very start of the string). Returns `s` untouched (borrowed) when there is
/// nothing to change, so the common already-normalized line allocates nothing.
fn collapse_inner_ws(s: &str) -> std::borrow::Cow<'_, str> {
    // Fast path: no run of 2+ inner spaces/tabs and no tab to normalize → nothing to do.
    let indent_len = s.len() - s.trim_start_matches([' ', '\t']).len();
    let rest = &s[indent_len..];
    let mut needs = false;
    let mut prev_ws = false;
    for c in rest.chars() {
        let ws = c == ' ' || c == '\t';
        if ws && (prev_ws || c == '\t') {
            needs = true;
            break;
        }
        prev_ws = ws;
    }
    if !needs {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..indent_len]); // keep indentation verbatim
    let mut prev_ws = false;
    for c in rest.chars() {
        let ws = c == ' ' || c == '\t';
        if ws {
            if !prev_ws {
                out.push(' ');
            }
            prev_ws = true;
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    std::borrow::Cow::Owned(out)
}

/// The core v1 compressor: apply the deterministic rule-set at `level` to one text blob. Returns an
/// OWNED `String` (the caller decides whether it changed by comparing lengths/equality). Guarantees:
/// idempotent, deterministic, never fuses two distinct words, never drops a non-blank, non-duplicate
/// line, never removes a non-adjacent duplicate.
pub fn compress(text: &str, level: Level) -> String {
    // Split on '\n', normalizing away '\r' so CRLF and LF inputs compress identically (deterministic
    // across platforms). We rebuild with '\n' only.
    let mut out_lines: Vec<std::borrow::Cow<'_, str>> = Vec::new();
    let mut prev_was_blank = false;
    let mut prev_line: Option<String> = None;

    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        // Rule 1: strip trailing whitespace (both levels).
        let trimmed = line.trim_end_matches([' ', '\t']);
        // Rule 2 (Balanced only): collapse inner whitespace runs, preserving indentation.
        let normalized: std::borrow::Cow<'_, str> = match level {
            Level::Balanced => collapse_inner_ws(trimmed),
            Level::Conservative => std::borrow::Cow::Borrowed(trimmed),
        };
        let is_blank = normalized.trim().is_empty();

        // Rule 3: collapse a RUN of blank lines to a single blank line (both levels).
        if is_blank {
            if prev_was_blank {
                continue; // swallow the extra blank
            }
            prev_was_blank = true;
            prev_line = None; // a blank breaks a run of identical non-blank lines
            out_lines.push(std::borrow::Cow::Owned(String::new()));
            continue;
        }
        prev_was_blank = false;

        // Rule 4 (Balanced only): drop a line identical to the immediately preceding kept line.
        if level == Level::Balanced {
            if let Some(prev) = &prev_line {
                if prev.as_str() == normalized.as_ref() {
                    continue; // consecutive duplicate → keep only the first
                }
            }
            prev_line = Some(normalized.to_string());
        }
        out_lines.push(normalized);
    }

    // Rebuild. Drop leading/trailing blank lines the rules may have surfaced (a wholly-empty edge is
    // never information) but preserve interior single blanks. This keeps the transform a pure shrink.
    while out_lines
        .first()
        .map(|l| l.trim().is_empty())
        .unwrap_or(false)
    {
        out_lines.remove(0);
    }
    while out_lines
        .last()
        .map(|l| l.trim().is_empty())
        .unwrap_or(false)
    {
        out_lines.pop();
    }
    let lines: Vec<&str> = out_lines.iter().map(|c| c.as_ref()).collect();
    // Rule 5 (Balanced only): if the whole body is a clean K-fold repetition of a multi-line block,
    // reduce it to one copy. Single-line adjacent dups are already handled by rule 4.
    let lines = if level == Level::Balanced {
        dedup_repeated_block(&lines)
    } else {
        &lines[..]
    };
    lines.join("\n")
}

/// If `lines` is EXACTLY K adjacent copies of the same block (K >= 2, block length >= 2 lines),
/// return just the first copy; otherwise return `lines` unchanged. Only a CLEAN whole-body repetition
/// qualifies — this can never merge two different blocks nor drop a non-repeated tail, so it is
/// lossless-of-meaning (a genuinely duplicated system prompt is the canonical case).
fn dedup_repeated_block<'a>(lines: &'a [&'a str]) -> &'a [&'a str] {
    let n = lines.len();
    if n < 4 {
        // Fewer than 4 lines can't be a >=2-line block repeated >=2 times (single-line repeats are
        // rule 4's job).
        return lines;
    }
    // Try each candidate period `p` that divides `n`, from smallest block up. The smallest clean
    // period gives the fullest collapse (`AB AB AB` collapses to `AB`, not `ABAB`).
    for p in 2..=(n / 2) {
        if !n.is_multiple_of(p) {
            continue;
        }
        let k = n / p; // number of repeats
        if k < 2 {
            continue;
        }
        let is_clean = (0..n).all(|i| lines[i] == lines[i % p]);
        if is_clean {
            return &lines[..p];
        }
    }
    lines
}

/// A conservative char-count "token" proxy: v1 has no tokenizer (no ML, no network), so savings are
/// reported in CHARACTERS, honestly labeled as such. A rough token estimate (chars/4) is offered
/// alongside so an operator has an order-of-magnitude read without us claiming tokenizer precision.
pub fn approx_tokens(chars: usize) -> usize {
    // ~4 chars/token is the common English rule of thumb; deliberately a coarse ESTIMATE, never
    // presented as an exact provider token count.
    chars / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DETERMINISM: the same input always yields byte-identical output (no RNG/clock/order effects).
    #[test]
    fn deterministic() {
        let input = "hello   world\n\n\n  keep\tindent  here\nkeep indent here\n";
        let a = compress(input, Level::Balanced);
        let b = compress(input, Level::Balanced);
        assert_eq!(a, b);
    }

    /// IDEMPOTENCE: compressing an already-compressed blob is a no-op (a fixed point).
    #[test]
    fn idempotent() {
        for level in [Level::Conservative, Level::Balanced] {
            let input =
                "a  b\n\n\n\nc   c\nc   c\n   indented    text\ntrailing space   \n\n\nend\n";
            let once = compress(input, level);
            let twice = compress(&once, level);
            assert_eq!(once, twice, "level {level:?} must be idempotent");
        }
    }

    /// Rule 1: trailing whitespace is stripped on every line.
    #[test]
    fn strips_trailing_whitespace() {
        assert_eq!(
            compress("foo   \nbar\t\t\n", Level::Conservative),
            "foo\nbar"
        );
    }

    /// Rule 2 (Balanced): inner whitespace runs collapse to one space, indentation preserved; tabs in
    /// the body become a single space. Conservative leaves inner runs alone.
    #[test]
    fn collapses_inner_ws_balanced_only() {
        assert_eq!(compress("a     b\tc", Level::Balanced), "a b c");
        assert_eq!(
            compress("    keep    indent", Level::Balanced),
            "    keep indent"
        );
        // Conservative does NOT collapse inner runs (only trailing + blank runs).
        assert_eq!(compress("a     b", Level::Conservative), "a     b");
    }

    /// Rule 3: a run of blank lines collapses to a single blank line (both levels).
    #[test]
    fn collapses_blank_runs() {
        assert_eq!(compress("x\n\n\n\n\ny", Level::Conservative), "x\n\ny");
        assert_eq!(compress("x\n\n\n\n\ny", Level::Balanced), "x\n\ny");
    }

    /// Rule 4 (Balanced): consecutive identical lines de-dup to one; a duplicated multi-line SYSTEM
    /// BLOCK pasted back-to-back collapses line-for-line into a single copy.
    #[test]
    fn dedups_consecutive_identical_lines_and_blocks() {
        assert_eq!(compress("go\ngo\ngo\nstop", Level::Balanced), "go\nstop");
    }

    /// Rule 5 (Balanced): a clean K-fold whole-body repetition of a multi-line block collapses to one
    /// copy — but a repetition with a DIFFERENT tail, or two DISTINCT blocks, is left untouched.
    #[test]
    fn dedups_repeated_multiline_block() {
        let block = "You are a helpful assistant.\nAlways be concise.";
        // Pasted twice → one copy.
        assert_eq!(
            compress(&format!("{block}\n{block}"), Level::Balanced),
            block
        );
        // Pasted three times → still one copy (clean 3-fold).
        assert_eq!(
            compress(&format!("{block}\n{block}\n{block}"), Level::Balanced),
            block
        );
        // A repeat with an extra distinct tail is NOT a clean whole-body repetition → untouched.
        let with_tail = format!("{block}\n{block}\nExtra distinct line.");
        assert_eq!(compress(&with_tail, Level::Balanced), with_tail);
        // Two DISTINCT adjacent blocks are never merged.
        let two = "line one\nline two\nline three\nline four";
        assert_eq!(compress(two, Level::Balanced), two);
    }

    /// NEVER DROPS NON-REDUNDANT CONTENT: distinct lines survive; NON-ADJACENT duplicates survive
    /// (a repeated instruction far apart may be deliberate); words are never fused.
    #[test]
    fn never_drops_non_redundant() {
        // Distinct lines all survive.
        let input = "alpha\nbeta\ngamma";
        assert_eq!(compress(input, Level::Balanced), input);
        // A duplicate separated by other content is NOT removed.
        let apart = "remember X\ndo something else\nremember X";
        assert_eq!(compress(apart, Level::Balanced), apart);
        // Two distinct single-space-separated words are never fused.
        assert_eq!(compress("cat dog", Level::Balanced), "cat dog");
        // A line that is only meaningful whitespace-normalized keeps all its words.
        assert_eq!(
            compress("the  quick   brown  fox", Level::Balanced),
            "the quick brown fox"
        );
    }

    /// The transform is a pure SHRINK: output length is always <= input length (never grows).
    #[test]
    fn never_grows() {
        for input in [
            "already tight",
            "lots     of     space\n\n\n\ndup\ndup\n",
            "",
            "\n\n\n",
            "单行 unicode 保留",
        ] {
            for level in [Level::Conservative, Level::Balanced] {
                let out = compress(input, level);
                assert!(
                    out.len() <= input.len(),
                    "compress grew {input:?} at {level:?}: {out:?}"
                );
            }
        }
    }

    /// CRLF and LF inputs compress to the same LF output (cross-platform determinism).
    #[test]
    fn normalizes_crlf() {
        assert_eq!(
            compress("a\r\nb\r\n", Level::Balanced),
            compress("a\nb\n", Level::Balanced)
        );
    }

    /// Empty / whitespace-only input compresses to empty (nothing to say, nothing surfaced).
    #[test]
    fn empty_and_whitespace_only() {
        assert_eq!(compress("", Level::Balanced), "");
        assert_eq!(compress("   \n\t\n  \n", Level::Balanced), "");
    }

    /// Level parsing resolves unknown/empty to the safe default, never to something MORE aggressive.
    #[test]
    fn level_parse_defaults_safe() {
        assert_eq!(Level::parse("conservative"), Level::Conservative);
        assert_eq!(Level::parse("Balanced"), Level::Balanced);
        assert_eq!(Level::parse(""), Level::Balanced);
        assert_eq!(Level::parse("HYPER-AGGRESSIVE-LOSSY"), Level::Balanced);
        assert_eq!(Level::default(), Level::Balanced);
    }
}

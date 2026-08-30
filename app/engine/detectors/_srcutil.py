"""Shared plumbing for the ECDAT source-code detectors (JavaScript/TypeScript, Java, Go).

Everything in here is deliberately dependency-free (stdlib only).  The three
detectors that use it -- ``source_js``, ``source_java``, ``source_go`` -- all
follow the same shape:

    1.  Walk the target tree, honouring the scan policy, and read text files.
    2.  Mask comments and string bodies so that identifier matching never fires
        inside a comment or an unrelated string ("crypto.createHash" written in
        a doc-comment is not a finding).
    3.  Turn the file into a flat list of :class:`CallSite` records -- from a
        real tree-sitter parse when the grammar is installed, from the masked
        tokenizer otherwise.  Both paths produce *the same* record type, so all
        of the crypto knowledge lives in one place per language.
    4.  Classify each call site, extract parameters (key size, curve, mode,
        padding) and merge the result into :class:`Artefact` objects through
        :class:`Collector`, attaching file + line + evidence provenance.

Invariants this module guarantees for every detector built on it
----------------------------------------------------------------
*   **Path convention.**  ``Occurrence.file`` is always a POSIX path *relative
    to the scan root* (``a/b/c.js``, never ``/abs/a/b/c.js`` and never
    ``a\\b\\c.js``).  ``iter_source_files`` is the single place that computes
    it, so every consumer -- ``serializers/_common.relative_path``,
    ``sarif._location``, ``gate._path_ignored``, ``recommend.generate_fix`` --
    sees one convention.
*   **Glob semantics.**  All path matching goes through :func:`glob_match`,
    which delegates to ``app.engine.policy.glob_match`` when that module is
    importable and otherwise uses a local implementation with *the same*
    ``**/`` and ``/**`` semantics.  ``fnmatch`` is never used on a path,
    because ``fnmatch("node_modules/x.js", "**/node_modules/**")`` is False.
*   **Policy delegation.**  If the caller hands us an object exposing a
    callable ``is_ignored`` (i.e. ``app.engine.policy.Policy``), that method
    decides exclusions.  Only when no policy rules are resolvable do the
    built-in :data:`BUILTIN_IGNORE_DIRS` / :data:`BUILTIN_IGNORE_GLOBS` apply,
    and those constants are exported so the other detectors share one table
    rather than each keeping a private copy.
*   **Digest provenance.**  :class:`Collector` records the digest length of any
    hash artefact in ``params.extra`` (``variant`` / ``digest_size`` / ``hash``
    for HMAC), so the risk engine and knowledge base never have to re-derive a
    digest size from the family string ``"SHA-2"``, which carries none.

Nothing in here raises on malformed input; callers collect problems into the
``errors`` list that ends up on ``ScanResult.errors``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

try:  # normal case: imported as app.engine.detectors._srcutil
    from ..models import Artefact, Occurrence, Params
except Exception:  # pragma: no cover - fallback for odd sys.path setups
    from app.engine.models import Artefact, Occurrence, Params  # type: ignore

# The policy module owns glob semantics for the whole engine.  Import it if we
# can; the local fallback below implements identical semantics so behaviour is
# the same either way (and a missing module never crashes a scan).
try:  # pragma: no cover - exercised implicitly
    from ..policy import glob_match as _policy_glob_match  # type: ignore
except Exception:  # pragma: no cover
    try:
        from app.engine.policy import glob_match as _policy_glob_match  # type: ignore
    except Exception:
        _policy_glob_match = None  # type: ignore[assignment]

__all__ = [
    "BUILTIN_IGNORE_DIRS",
    "BUILTIN_IGNORE_GLOBS",
    "glob_match",
    "PolicyView",
    "iter_source_files",
    "Masked",
    "mask_source",
    "CallSite",
    "iter_calls",
    "iter_composites",
    "load_ts_parser",
    "node_text",
    "walk_nodes",
    "lit_str",
    "lit_int",
    "lit_bool",
    "all_strings",
    "obj_prop",
    "collapse_ws",
    "normalize_curve",
    "hash_info",
    "digest_bits",
    "parse_openssl_cipher",
    "parse_java_transformation",
    "parse_jwt_alg",
    "tls_version",
    "pqc_info",
    "canon_name",
    "Collector",
    "MAX_EVIDENCE",
]

MAX_EVIDENCE = 220
DEFAULT_MAX_FILE_BYTES = 2_000_000
MAX_LINE_LEN_BEFORE_MINIFIED = 8000

#: Directories that are never source-of-record for the scanned project.  These
#: are a *fallback* only: a policy that resolves any ignore rule of its own
#: takes precedence (see :class:`PolicyView`).  Exported so the Python detector
#: can share the table instead of keeping a second, divergent copy.
BUILTIN_IGNORE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".idea", ".vscode", ".gradle", ".mvn",
        "node_modules", "bower_components", "jspm_packages",
        "dist", "build", "out", "target", "vendor", "third_party",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
        "venv", ".venv", "env", "site-packages",
        ".next", ".nuxt", ".cache", ".parcel-cache", ".turbo",
        "coverage", "htmlcov", "Pods", "DerivedData",
    }
)

#: Generated / bundled artefacts.  Unlike the directory list this is a
#: *generated-code guard* rather than a policy opinion: a minified bundle has
#: no line numbers worth reporting.  A policy can still switch it off with
#: ``use_default_excludes: false``.
BUILTIN_IGNORE_GLOBS = (
    "*.min.js", "*.bundle.js", "*.min.mjs", "*-min.js", "*.map",
    "*.min.css", "*_pb.js", "*.pb.go", "*_pb2.py", "*.generated.*",
)

# Backwards-compatible aliases (older detector code imported these names).
DEFAULT_EXCLUDE_DIRS = BUILTIN_IGNORE_DIRS
DEFAULT_EXCLUDE_GLOBS = BUILTIN_IGNORE_GLOBS


# --------------------------------------------------------------------------
# glob matching (single source of truth, shared with app.engine.policy)
# --------------------------------------------------------------------------
_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _translate_glob(pattern: str) -> re.Pattern[str]:
    """Compile a path glob with git-style ``**`` semantics.

    ``**/`` matches zero or more leading path segments, so ``**/node_modules/**``
    matches ``node_modules/a.js`` *and* ``src/node_modules/a.js``.  A trailing
    ``/**`` matches the directory itself and everything beneath it.  A single
    ``*`` never crosses ``/``.
    """
    cached = _GLOB_CACHE.get(pattern)
    if cached is not None:
        return cached
    p = pattern.replace("\\", "/").strip()
    out: list[str] = ["^"]
    i, n = 0, len(p)
    while i < n:
        c = p[i]
        if c == "*":
            if p[i : i + 3] == "**/":
                out.append("(?:[^/]+/)*")   # zero or more whole segments
                i += 3
                continue
            if p[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "/":
            if p[i : i + 3] == "/**" and i + 3 == n:
                out.append("(?:/.*)?")      # the dir itself and its contents
                i += 3
                continue
            out.append("/")
            i += 1
            continue
        if c == "[":
            j = i + 1
            if j < n and p[j] in "!^":
                j += 1
            if j < n and p[j] == "]":
                j += 1
            while j < n and p[j] != "]":
                j += 1
            if j < n:
                body = p[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
                continue
            out.append(re.escape("["))
            i += 1
            continue
        out.append(re.escape(c))
        i += 1
    out.append("$")
    try:
        compiled = re.compile("".join(out))
    except re.error:  # pragma: no cover - defensive
        compiled = re.compile(re.escape(p) + "$")
    _GLOB_CACHE[pattern] = compiled
    return compiled


def _policy_arg_order() -> str | None:
    """Work out whether ``policy.glob_match`` takes (path, pattern) or (pattern, path).

    The two orders are indistinguishable at the call site and getting it wrong
    fails *silently* (every match returns False, so nothing is ever excluded),
    so bind by parameter name rather than by guessing.  Returns ``None`` when
    the signature is unreadable, in which case we use the local implementation.
    """
    if _policy_glob_match is None:
        return None
    try:
        import inspect

        names = [p.lower() for p in inspect.signature(_policy_glob_match).parameters]
    except Exception:
        return None
    if len(names) < 2:
        return None
    first = names[0]
    if any(tok in first for tok in ("path", "candidate", "target", "value", "name")):
        return "path_first"
    if any(tok in first for tok in ("pat", "glob", "rule", "spec")):
        return "pattern_first"
    return None


_POLICY_ARG_ORDER = _policy_arg_order()


def _path_glob(pattern: str, path: str) -> bool:
    """Core path-glob match, delegating to the policy module when possible."""
    if _POLICY_ARG_ORDER is not None and _policy_glob_match is not None:
        try:
            if _POLICY_ARG_ORDER == "path_first":
                return bool(_policy_glob_match(path, pattern))
            return bool(_policy_glob_match(pattern, path))
        except Exception:
            pass
    return bool(_translate_glob(pattern).match(path))


def _is_name_pattern(pattern: str) -> bool:
    """True for git-style name patterns such as ``*.min.js`` (no separator)."""
    body = pattern[3:] if pattern.startswith("**/") else pattern
    return "/" not in body


def glob_match(pattern: str, path: str) -> bool:
    """True when ``path`` (a POSIX, root-relative path) matches ``pattern``.

    Path matching is delegated to ``app.engine.policy.glob_match`` when that
    module is importable, so the whole engine shares one implementation of the
    ``**/`` and ``/**`` semantics; an identical local translator is used
    otherwise.  On top of that, a pattern containing no separator is treated as
    a *name* pattern (git semantics) and is also tried against the basename and
    every path segment, so ``*.min.js`` excludes ``dist/a.min.js``.
    """
    if not pattern:
        return False
    path = str(path).replace("\\", "/").lstrip("./")
    pat = str(pattern).replace("\\", "/").strip()
    if pat.endswith("/"):
        pat += "**"
    if _path_glob(pat, path):
        return True
    if _is_name_pattern(pat):
        rx = _translate_glob(pat[3:] if pat.startswith("**/") else pat)
        for segment in path.split("/"):
            if rx.match(segment):
                return True
    return False


# --------------------------------------------------------------------------
# policy handling
# --------------------------------------------------------------------------
_IGNORE_KEYS: tuple[str, ...] = (
    "ignore_paths", "exclude_globs", "excludes", "exclude", "exclude_paths",
    "ignore_globs", "ignores", "ignore", "skip", "skip_paths",
)
_INCLUDE_KEYS: tuple[str, ...] = ("include_globs", "includes", "include", "only", "only_paths")


def _policy_get(policy: Any, names: Sequence[str], default: Any = None) -> Any:
    """Read ``names`` from a policy object/dict, including one nested level."""
    if policy is None:
        return default
    containers: list[Any] = [policy]
    data = getattr(policy, "data", None)
    if isinstance(data, dict):
        containers.append(data)
    for sub in ("scan", "files", "source", "filters", "options"):
        for base in (policy, data):
            if base is None:
                continue
            try:
                nested = base.get(sub) if isinstance(base, dict) else getattr(base, sub, None)
            except Exception:
                nested = None
            if nested is not None:
                containers.append(nested)
    for container in containers:
        for name in names:
            try:
                if isinstance(container, dict):
                    if name in container and container[name] is not None:
                        return container[name]
                else:
                    value = getattr(container, name, None)
                    if value is not None and not callable(value):
                        return value
            except Exception:
                continue
    return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k in value.keys()]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(v) for v in value]
    return []


class PolicyView:
    """Duck-typed read-only view over whatever the caller passes as ``policy``.

    Accepts ``app.engine.policy.Policy``, a dataclass, a plain object, a dict
    or ``None``; unknown shapes fall back to the built-in defaults instead of
    raising.

    Resolution order for "is this path excluded?":

    1.  ``policy.is_ignored(path)`` when the policy exposes that callable --
        this is the ``Policy`` object's own, unit-tested implementation and it
        wins outright.
    2.  Ignore globs read from the policy mapping (``ignore_paths``,
        ``exclude_globs``, ...), matched with :func:`glob_match`.
    3.  The built-in fallbacks, applied only when neither 1 nor 2 produced any
        rule, or as a generated-code guard for :data:`BUILTIN_IGNORE_GLOBS`.
    """

    def __init__(self, policy: Any = None) -> None:
        self.raw = policy

        fn = getattr(policy, "is_ignored", None)
        self.is_ignored_fn = fn if callable(fn) else None

        self.include = _as_list(_policy_get(policy, _INCLUDE_KEYS))
        self.exclude = _as_list(_policy_get(policy, _IGNORE_KEYS))
        self.exclude_dirs = {
            d.strip("/\\") for d in _as_list(_policy_get(policy, ("exclude_dirs", "ignore_dirs")))
        }

        #: True when the caller's policy actually contributed exclusion rules.
        self.policy_driven = bool(self.is_ignored_fn or self.exclude or self.exclude_dirs)

        use_defaults = _policy_get(policy, ("use_default_excludes", "use_builtin_excludes"), None)
        self.use_builtin_globs = True if use_defaults is None else bool(use_defaults)
        # Built-in *directories* are an opinion, so a real policy overrides
        # them; built-in *globs* are a generated-code guard and stay on unless
        # explicitly disabled.
        self.use_builtin_dirs = self.use_builtin_globs and not self.policy_driven

        try:
            self.max_file_bytes = int(
                _policy_get(
                    policy,
                    ("max_file_bytes", "max_file_size", "max_bytes", "max_size"),
                    DEFAULT_MAX_FILE_BYTES,
                )
            )
        except Exception:
            self.max_file_bytes = DEFAULT_MAX_FILE_BYTES
        if self.max_file_bytes <= 0:
            self.max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self.follow_symlinks = bool(_policy_get(policy, ("follow_symlinks",), False))

    # -- exclusion ------------------------------------------------------
    def _ignored_by_policy(self, rel_path: str) -> bool:
        if self.is_ignored_fn is not None:
            try:
                if bool(self.is_ignored_fn(rel_path)):
                    return True
            except Exception:
                pass  # a broken policy must not abort the scan
        for pattern in self.exclude:
            if glob_match(pattern, rel_path):
                return True
        return False

    def allows_dir(self, rel_dir: str, name: str) -> bool:
        """False when a whole directory subtree should be pruned."""
        rel_dir = rel_dir.replace(os.sep, "/").strip("/")
        if self._ignored_by_policy(rel_dir) or self._ignored_by_policy(rel_dir + "/"):
            return False
        if name in self.exclude_dirs:
            return False
        if self.use_builtin_dirs and (name in BUILTIN_IGNORE_DIRS or name.startswith(".git")):
            return False
        return True

    def allows(self, rel_path: str) -> bool:
        """True when a file at root-relative POSIX ``rel_path`` should be read."""
        rel_path = rel_path.replace(os.sep, "/").lstrip("./")
        if self._ignored_by_policy(rel_path):
            return False
        if self.use_builtin_globs:
            for pattern in BUILTIN_IGNORE_GLOBS:
                if glob_match(pattern, rel_path):
                    return False
        if self.include:
            for pattern in self.include:
                if glob_match(pattern, rel_path):
                    return True
            return False
        return True


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return data.decode("utf-32", "replace")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:4096]:
        raise ValueError("binary file")
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def iter_source_files(
    root: Path | str,
    exts: Sequence[str],
    pv: PolicyView,
    errors: list[str],
) -> Iterator[tuple[Path, str, str]]:
    """Yield ``(path, rel_posix_path, source_text)`` for every scannable file.

    ``rel_posix_path`` is the engine-wide occurrence path convention: POSIX
    separators, relative to the scan root, no leading ``./``.
    """
    root = Path(root)
    exts_l = tuple(e.lower() for e in exts)
    base = root if root.is_dir() else root.parent

    def _rel(path: Path) -> str:
        try:
            rel = os.path.relpath(str(path), str(base))
        except Exception:
            rel = str(path)
        return rel.replace(os.sep, "/").lstrip("./") or path.name

    def _emit(path: Path) -> Iterator[tuple[Path, str, str]]:
        rel = _rel(path)
        if not pv.allows(rel):
            return
        try:
            if path.is_symlink() and not pv.follow_symlinks:
                return
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"{rel}: stat failed: {exc}")
            return
        if size > pv.max_file_bytes:
            errors.append(f"{rel}: skipped (larger than {pv.max_file_bytes} bytes)")
            return
        try:
            src = _read_text(path)
        except Exception as exc:
            errors.append(f"{rel}: unreadable ({type(exc).__name__}: {exc})")
            return
        if src and max((len(line) for line in src.split("\n")), default=0) > MAX_LINE_LEN_BEFORE_MINIFIED:
            errors.append(f"{rel}: skipped (looks minified/generated)")
            return
        yield path, rel, src

    if root.is_file():
        if root.suffix.lower() in exts_l:
            yield from _emit(root)
        return
    if not root.exists():
        errors.append(f"{root}: target does not exist")
        return

    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=pv.follow_symlinks):
        kept: list[str] = []
        for d in dirnames:
            rel_dir = _rel(Path(dirpath) / d)
            if pv.allows_dir(rel_dir, d):
                kept.append(d)
        dirnames[:] = kept
        for filename in sorted(filenames):
            if not filename.lower().endswith(exts_l):
                continue
            yield from _emit(Path(dirpath) / filename)


# --------------------------------------------------------------------------
# comment / string masking
# --------------------------------------------------------------------------
@dataclass
class Masked:
    """Three parallel, equal-length views of one source file.

    ``code`` has comment bodies *and* string bodies blanked (quotes kept), so a
    regex over it can never match inside a literal.  ``text`` keeps string
    bodies (comments still blanked) so argument values can be read back.
    """

    src: str
    code: str
    text: str
    line_starts: list[int]

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def line_text(self, line: int) -> str:
        idx = line - 1
        if idx < 0 or idx >= len(self.line_starts):
            return ""
        start = self.line_starts[idx]
        end = self.line_starts[idx + 1] if idx + 1 < len(self.line_starts) else len(self.src)
        return self.src[start:end].rstrip("\n").rstrip("\r")

    def evidence(self, offset: int) -> str:
        return snippet(self.line_text(self.line_of(offset)))

    def is_code(self, start: int, end: int) -> bool:
        """True when the span survived masking (i.e. is real code)."""
        return self.code[start:end] == self.src[start:end]


def snippet(text: str) -> str:
    out = " ".join(text.split())
    if len(out) > MAX_EVIDENCE:
        out = out[: MAX_EVIDENCE - 1].rstrip() + "…"
    return out


_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%~^<>\n\t ")
_REGEX_KEYWORDS = (
    "return", "typeof", "case", "in", "of", "delete", "void", "instanceof",
    "new", "do", "else", "yield", "await",
)


def mask_source(src: str, lang: str = "js") -> Masked:
    """Blank out comments (and, in the ``code`` view, string bodies).

    Handles ``//`` and ``/* */`` comments, single/double quoted strings with
    backslash escapes, JS template literals, Go raw (backtick) strings, Java
    text blocks and -- heuristically -- JavaScript regular-expression literals.
    Never raises: an unterminated literal simply masks to end of line.
    """
    n = len(src)
    code = list(src)
    text = list(src)
    line_starts = [0]
    for i, ch in enumerate(src):
        if ch == "\n":
            line_starts.append(i + 1)

    def blank(i: int, both: bool) -> None:
        if i < 0 or i >= n or src[i] == "\n":
            return
        code[i] = " "
        if both:
            text[i] = " "

    is_js = lang == "js"
    is_go = lang == "go"
    is_java = lang == "java"

    i = 0
    last_significant = ""
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # ---- comments -------------------------------------------------
        if ch == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                blank(i, True)
                i += 1
            continue
        if ch == "/" and nxt == "*":
            blank(i, True)
            blank(i + 1, True)
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                blank(i, True)
                i += 1
            if i < n:
                blank(i, True)
                blank(i + 1, True)
                i += 2
            continue

        # ---- java text blocks ----------------------------------------
        if is_java and ch == '"' and src[i : i + 3] == '"""':
            i += 3
            while i < n and src[i : i + 3] != '"""':
                blank(i, False)
                i += 1
            i = min(n, i + 3)
            last_significant = '"'
            continue

        # ---- quoted strings ------------------------------------------
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                if src[i] == "\\":
                    blank(i, False)
                    blank(i + 1, False)
                    i += 2
                    continue
                if src[i] == quote:
                    break
                if src[i] == "\n":
                    break  # unterminated literal: never swallow the rest of the file
                blank(i, False)
                i += 1
            i += 1
            last_significant = quote
            continue

        # ---- backticks: JS template literal / Go raw string ----------
        if ch == "`" and (is_js or is_go):
            i += 1
            while i < n and src[i] != "`":
                if is_js and src[i] == "\\":
                    blank(i, False)
                    blank(i + 1, False)
                    i += 2
                    continue
                blank(i, False)
                i += 1
            i += 1
            last_significant = "`"
            continue

        # ---- JS regex literals ---------------------------------------
        if is_js and ch == "/":
            j = i - 1
            while j >= 0 and src[j] in " \t":
                j -= 1
            k = j
            while k >= 0 and (src[k].isalnum() or src[k] == "_"):
                k -= 1
            prev_word = src[k + 1 : j + 1]
            looks_regex = (
                last_significant == ""
                or last_significant in _REGEX_PRECEDERS
                or prev_word in _REGEX_KEYWORDS
            )
            if looks_regex:
                i += 1
                in_class = False
                while i < n and src[i] != "\n":
                    c = src[i]
                    if c == "\\":
                        blank(i, False)
                        blank(i + 1, False)
                        i += 2
                        continue
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        break
                    blank(i, False)
                    i += 1
                i += 1
                last_significant = "/"
                continue

        if not ch.isspace():
            last_significant = ch
        i += 1

    return Masked(src=src, code="".join(code), text="".join(text), line_starts=line_starts)


# --------------------------------------------------------------------------
# call-site extraction
# --------------------------------------------------------------------------
@dataclass
class CallSite:
    """One call expression, however it was found (tree-sitter or tokenizer)."""

    callee: str                     # e.g. "crypto.createHash"
    base: str                       # e.g. "createHash"
    receiver: str = ""              # e.g. "crypto" ("<call>" when chained)
    args: list[str] = field(default_factory=list)
    line: int = 0
    evidence: str = ""
    assigned_to: str | None = None
    receiver_call: str | None = None  # source text of the chained-onto call
    start: int = -1
    end: int = -1
    raw: str = ""

    def arg(self, index: int) -> str:
        return self.args[index] if 0 <= index < len(self.args) else ""

    @property
    def arg_text(self) -> str:
        return " , ".join(self.args)

    @property
    def dotted(self) -> str:
        return self.callee.lower()


def collapse_ws(text: str) -> str:
    return " ".join(text.split())


_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_$])((?:new\s+)?[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)\s*(?=\()"
)
_OPENERS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = {")": "(", "]": "[", "}": "{"}


def _match_balanced(code: str, open_index: int) -> int:
    """Return the index just past the ``)`` closing ``code[open_index] == '('``."""
    depth = 0
    i = open_index
    n = len(code)
    while i < n:
        c = code[i]
        if c in _OPENERS:
            depth += 1
        elif c in _CLOSERS:
            depth -= 1
            if depth == 0:
                return i + 1
            if depth < 0:
                return -1
        i += 1
    return -1


def _split_args(code: str, text: str, open_index: int, close_index: int) -> list[str]:
    """Split the argument list into top-level chunks, taking text from ``text``."""
    args: list[str] = []
    depth = 0
    start = open_index + 1
    for i in range(open_index, close_index):
        c = code[i]
        if c in _OPENERS:
            depth += 1
        elif c in _CLOSERS:
            depth -= 1
            if depth == 0:
                chunk = text[start:i].strip()
                if chunk:
                    args.append(chunk)
                break
        elif c == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
    return args


_ASSIGN_TAIL = re.compile(r"(?<![=!<>+\-*/%&|^])(:?=)\s*$")

#: words that, immediately before a name, mean "declaration", not "call".
_DECL_KEYWORDS = frozenset(
    {
        "function", "func", "class", "interface", "struct", "enum", "def", "type",
        "package", "void", "public", "private", "protected", "static", "final",
        "abstract", "synchronized", "native", "default", "record",
    }
)


def _preceding_word(code: str, start: int) -> str:
    i = start - 1
    while i >= 0 and code[i] in " \t":
        i -= 1
    end = i + 1
    while i >= 0 and (code[i].isalnum() or code[i] in "_$"):
        i -= 1
    return code[i + 1 : end]


def _assignment_target(code: str, start: int) -> str | None:
    head = code[max(0, start - 240) : start]
    stripped = head.rstrip()
    m = _ASSIGN_TAIL.search(stripped)
    if not m:
        return None
    lhs = stripped[: m.start()]
    for sep in (";", "{", "}", "\n", ")"):
        idx = lhs.rfind(sep)
        if idx >= 0:
            lhs = lhs[idx + 1 :]
    first = lhs.split(",")[0]
    ids = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", first)
    if not ids:
        return None
    name = ids[-1]
    if name in {"return", "new", "var", "let", "const", "final", "static", "public", "private"}:
        return None
    return name


def iter_calls(masked: Masked, max_calls: int = 20000) -> list[CallSite]:
    """Tokenizer-based call extraction over the masked source."""
    code, text = masked.code, masked.text
    calls: list[CallSite] = []
    # end offset -> start offset, so chained calls resolve in O(1) rather than
    # scanning every previously-seen call (which was quadratic on big files).
    by_end: dict[int, int] = {}
    for m in _CALL_RE.finditer(code):
        if len(calls) >= max_calls:
            break
        open_index = m.end()
        while open_index < len(code) and code[open_index] in " \t\r\n":
            open_index += 1
        if open_index >= len(code) or code[open_index] != "(":
            continue
        close_index = _match_balanced(code, open_index)
        if close_index < 0:
            continue
        if _preceding_word(code, m.start()) in _DECL_KEYWORDS:
            continue  # function/method declaration, not a call site
        callee = collapse_ws(m.group(1)).replace(" .", ".").replace(". ", ".")
        if callee.startswith("new "):
            callee_name = callee[4:].strip()
            is_new = True
        else:
            callee_name = callee
            is_new = False
        base = callee_name.rsplit(".", 1)[-1]
        receiver = callee_name.rsplit(".", 1)[0] if "." in callee_name else ""
        start = m.start()
        receiver_call = None
        if start > 0 and code[start - 1] == ".":
            receiver = "<call>"
            prev_start = by_end.get(start - 1)
            if prev_start is not None:
                receiver_call = collapse_ws(text[prev_start : start - 1])
        site = CallSite(
            callee=("new " + callee_name) if is_new else callee_name,
            base=base,
            receiver=receiver,
            args=_split_args(code, text, open_index, close_index),
            line=masked.line_of(start),
            evidence=masked.evidence(start),
            assigned_to=_assignment_target(code, start),
            receiver_call=receiver_call,
            start=start,
            end=close_index,
            raw=collapse_ws(text[start:close_index]),
        )
        by_end[close_index] = start
        calls.append(site)
    return calls


#: Characters that can legally precede a *value*.  A composite literal only
#: ever appears in value position; ``*tls.Config {`` in a function signature is
#: a pointer *type* and must not be mistaken for one (it would attribute the
#: whole function body to a phantom config literal).
_VALUE_POSITION_PREV = set("&(,[{=:!|?+-*/%<>;\n") | {""}


def iter_composites(masked: Masked, pattern: str) -> Iterator[tuple[str, int, str, int]]:
    """Yield ``(body, line, evidence, body_offset)`` for ``Name{ ... }`` literals.

    ``body_offset`` is the absolute offset of ``body[0]`` in the source, so the
    caller can turn matches inside the body back into real line numbers.

    A brace separated from the name by whitespace is only accepted when the
    name sits in value position.  gofmt writes composite literals as
    ``tls.Config{`` (no space) and pointer types as ``*tls.Config {`` (space),
    so ``func Cfg() *tls.Config {`` no longer yields a bogus literal whose
    "body" is the entire function.
    """
    try:
        regex = re.compile(pattern)
    except re.error:
        return
    code = masked.code
    n = len(code)
    for m in regex.finditer(code):
        brace = m.end()
        gap = 0
        while brace < n and code[brace] in " \t\r\n":
            brace += 1
            gap += 1
        if brace >= n or code[brace] != "{":
            continue
        if gap:
            j = m.start() - 1
            while j >= 0 and code[j] in " \t":
                j -= 1
            prev = code[j] if j >= 0 else ""
            if prev not in _VALUE_POSITION_PREV:
                continue  # type position (e.g. "func f() *tls.Config {")
            if prev == "*":
                continue  # pointer type, never a literal
        close = _match_balanced(code, brace)
        if close < 0:
            continue
        yield (
            masked.text[brace + 1 : close - 1],
            masked.line_of(m.start()),
            masked.evidence(m.start()),
            brace + 1,
        )


# --------------------------------------------------------------------------
# tree-sitter helpers
# --------------------------------------------------------------------------
def load_ts_parser(module_name: str, language_name: str):
    """Return a tree-sitter ``Parser`` or ``None`` if anything is missing.

    Supports the API differences between tree_sitter 0.20/0.21 (``Language(ptr,
    name)`` + ``parser.set_language``) and 0.22+ (``Language(ptr)`` +
    ``Parser(language)``).
    """
    try:
        import importlib

        from tree_sitter import Language, Parser  # type: ignore
    except Exception:
        return None
    try:
        grammar = importlib.import_module(module_name)
    except Exception:
        return None
    ptr = None
    for attr in ("language", "LANGUAGE"):
        obj = getattr(grammar, attr, None)
        if obj is None:
            continue
        try:
            ptr = obj() if callable(obj) else obj
        except Exception:
            ptr = None
        if ptr is not None:
            break
    if ptr is None:
        return None
    language = None
    for build in (lambda: Language(ptr), lambda: Language(ptr, language_name)):
        try:
            language = build()
            break
        except Exception:
            continue
    if language is None:
        return None
    try:
        return Parser(language)
    except Exception:
        pass
    try:
        parser = Parser()
        parser.set_language(language)
        return parser
    except Exception:
        return None


def node_text(src_bytes: bytes, node: Any) -> str:
    try:
        return src_bytes[node.start_byte : node.end_byte].decode("utf-8", "replace")
    except Exception:
        return ""


def walk_nodes(root: Any) -> Iterator[Any]:
    """Iterative pre-order walk (no recursion limits on huge files)."""
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        try:
            children = node.children
        except Exception:
            children = []
        for child in reversed(children):
            stack.append(child)


# --------------------------------------------------------------------------
# literal parsing
# --------------------------------------------------------------------------
_STR_RE = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1|`([^`]*)`""", re.S)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`"}


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def lit_str(arg: str) -> str | None:
    """Return the value of a (possibly concatenated) string literal argument."""
    if arg is None:
        return None
    arg = arg.strip()
    if not arg:
        return None
    pieces: list[str] = []
    pos = 0
    for m in _STR_RE.finditer(arg):
        between = arg[pos : m.start()].strip()
        if between and between not in {"+", ",", "(", ")"}:
            return None
        pieces.append(_unescape(m.group(2) if m.group(2) is not None else (m.group(3) or "")))
        pos = m.end()
    tail = arg[pos:].strip()
    if tail and tail not in {"+", ")", ","}:
        return None
    if not pieces:
        return None
    return "".join(pieces)


_INT_RE = re.compile(r"^[+-]?(0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)[lLuU]?$")


def lit_int(arg: str) -> int | None:
    if arg is None:
        return None
    token = arg.strip().rstrip(";,")
    if not token:
        return None
    quoted = lit_str(token)
    if quoted is not None:
        token = quoted.strip()
    m = _INT_RE.match(token)
    if not m:
        return None
    body = m.group(1).replace("_", "")
    try:
        return int(body, 16) if body[:2].lower() == "0x" else int(body)
    except Exception:
        return None


def lit_bool(arg: str) -> bool | None:
    token = (arg or "").strip().lower().rstrip(",;")
    if token in ("true", "yes"):
        return True
    if token in ("false", "no"):
        return False
    return None


def all_strings(text: str) -> list[str]:
    """Every string literal inside a chunk of source text."""
    out: list[str] = []
    for m in _STR_RE.finditer(text or ""):
        value = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        out.append(_unescape(value))
    return out


def obj_prop(text: str, key: str) -> str | None:
    """Value of ``key: value`` inside a JS object / Go composite literal.

    The value is cut at the first top-level ``,``/``}``/``]`` after the colon.
    """
    if not text:
        return None
    m = re.search(r"(?<![A-Za-z0-9_$.])['\"]?" + re.escape(key) + r"['\"]?\s*:", text)
    if not m:
        return None
    i = m.end()
    depth = 0
    start = i
    while i < len(text):
        c = text[i]
        if c in _OPENERS:
            depth += 1
        elif c in _CLOSERS:
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            break
        elif c == "\n" and depth == 0 and text[start:i].strip():
            break
        i += 1
    value = text[start:i].strip()
    return value or None


# --------------------------------------------------------------------------
# crypto vocabulary
# --------------------------------------------------------------------------
_CURVE_ALIASES = {
    "p192": "secp192r1", "p-192": "secp192r1", "prime192v1": "secp192r1",
    "secp192r1": "secp192r1", "nistp192": "secp192r1",
    "p224": "secp224r1", "p-224": "secp224r1", "secp224r1": "secp224r1", "nistp224": "secp224r1",
    "p256": "secp256r1", "p-256": "secp256r1", "prime256v1": "secp256r1",
    "secp256r1": "secp256r1", "nistp256": "secp256r1", "x962p256v1": "secp256r1",
    "p384": "secp384r1", "p-384": "secp384r1", "secp384r1": "secp384r1", "nistp384": "secp384r1",
    "p521": "secp521r1", "p-521": "secp521r1", "secp521r1": "secp521r1", "nistp521": "secp521r1",
    "secp256k1": "secp256k1", "p256k1": "secp256k1",
    "secp160r1": "secp160r1", "secp160k1": "secp160k1", "sect163k1": "sect163k1",
    "brainpoolp256r1": "brainpoolP256r1", "brainpoolp384r1": "brainpoolP384r1",
    "brainpoolp512r1": "brainpoolP512r1",
    "curve25519": "X25519", "x25519": "X25519", "ed25519": "Ed25519",
    "curve448": "X448", "x448": "X448", "ed448": "Ed448",
    "sm2p256v1": "sm2p256v1",
}


def normalize_curve(value: str | None) -> str | None:
    if not value:
        return None
    raw = str(value).strip().strip("\"'")
    key = raw.lower().replace("_", "").replace(" ", "")
    if key in _CURVE_ALIASES:
        return _CURVE_ALIASES[key]
    key2 = key.replace("-", "")
    if key2 in _CURVE_ALIASES:
        return _CURVE_ALIASES[key2]
    if re.fullmatch(r"(sec[pt]|brainpoolp)\d+[rkt]\d", key2):
        return raw
    return raw if re.fullmatch(r"[A-Za-z0-9_.\-]{3,32}", raw) else None


_HASH_TABLE: dict[str, tuple[str, str]] = {
    "md2": ("MD2", "MD2"),
    "md4": ("MD4", "MD4"),
    "md5": ("MD5", "MD5"),
    "md5sha1": ("MD5", "MD5-SHA-1"),
    "sha1": ("SHA-1", "SHA-1"),
    "sha0": ("SHA-1", "SHA-0"),
    "sha224": ("SHA-2", "SHA-224"),
    "sha256": ("SHA-2", "SHA-256"),
    "sha384": ("SHA-2", "SHA-384"),
    "sha512": ("SHA-2", "SHA-512"),
    "sha512224": ("SHA-2", "SHA-512/224"),
    "sha512256": ("SHA-2", "SHA-512/256"),
    "sha3224": ("SHA-3", "SHA3-224"),
    "sha3256": ("SHA-3", "SHA3-256"),
    "sha3384": ("SHA-3", "SHA3-384"),
    "sha3512": ("SHA-3", "SHA3-512"),
    "shake128": ("SHA-3", "SHAKE128"),
    "shake256": ("SHA-3", "SHAKE256"),
    "ripemd": ("RIPEMD", "RIPEMD-160"),
    "ripemd128": ("RIPEMD", "RIPEMD-128"),
    "ripemd160": ("RIPEMD", "RIPEMD-160"),
    "ripemd256": ("RIPEMD", "RIPEMD-256"),
    "blake2b": ("BLAKE2", "BLAKE2b"),
    "blake2b256": ("BLAKE2", "BLAKE2b-256"),
    "blake2b512": ("BLAKE2", "BLAKE2b-512"),
    "blake2s": ("BLAKE2", "BLAKE2s"),
    "blake2s256": ("BLAKE2", "BLAKE2s-256"),
    "blake3": ("BLAKE3", "BLAKE3"),
    "sm3": ("SM3", "SM3"),
    "whirlpool": ("Whirlpool", "Whirlpool"),
    "gost": ("GOST", "GOST R 34.11-94"),
}

#: Hash families whose *variant* (and therefore digest length) lives only in
#: the artefact ``name``.  ``Collector`` stamps the length into
#: ``params.extra`` so nothing downstream has to guess it from "SHA-2".
HASH_FAMILIES = frozenset(
    {
        "MD2", "MD4", "MD5", "SHA-1", "SHA-2", "SHA-3", "RIPEMD",
        "BLAKE2", "BLAKE3", "SM3", "Whirlpool", "GOST", "HMAC",
    }
)

_DIGEST_BITS: dict[str, int] = {
    "MD2": 128, "MD4": 128, "MD5": 128, "MD5-SHA-1": 288,
    "SHA-0": 160, "SHA-1": 160,
    "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
    "SHA-512/224": 224, "SHA-512/256": 256,
    "SHA3-224": 224, "SHA3-256": 256, "SHA3-384": 384, "SHA3-512": 512,
    "RIPEMD-128": 128, "RIPEMD-160": 160, "RIPEMD-256": 256,
    "BLAKE2b": 512, "BLAKE2b-256": 256, "BLAKE2b-512": 512,
    "BLAKE2s": 256, "BLAKE2s-256": 256, "BLAKE3": 256,
    "SM3": 256, "Whirlpool": 512, "GOST R 34.11-94": 256,
}

#: SHAKE is an XOF: the number in the name is a *security level*, not an output
#: length (FIPS 202 gives SHAKE128/SHAKE256 capacities of 256/512 bits).
_XOF_SECURITY_BITS = {"SHAKE128": 128, "SHAKE256": 256}


def hash_info(value: str | None) -> tuple[str, str] | None:
    """Map any spelling of a hash name to ``(family, canonical_name)``."""
    if not value:
        return None
    key = re.sub(r"[^a-z0-9]", "", str(value).lower())
    if key.startswith("hmac"):
        key = key[4:]
    if key.startswith("with"):
        key = key[4:]
    if key in _HASH_TABLE:
        return _HASH_TABLE[key]
    if key.startswith("sha3") and key[4:].isdigit():
        return ("SHA-3", f"SHA3-{key[4:]}")
    if key.startswith("sha") and key[3:].isdigit():
        return _HASH_TABLE.get("sha" + key[3:], ("SHA-2", f"SHA-{key[3:]}"))
    return None


def digest_bits(name: str | None) -> int | None:
    """Digest length in bits for a canonical hash name, or ``None``.

    ``digest_bits("SHA-256") == 256``.  Returns ``None`` for XOFs (SHAKE), whose
    output length is caller-chosen -- see :data:`_XOF_SECURITY_BITS`.
    """
    if not name:
        return None
    raw = str(name).strip()
    if raw in _DIGEST_BITS:
        return _DIGEST_BITS[raw]
    info = hash_info(raw)
    if info and info[1] in _DIGEST_BITS:
        return _DIGEST_BITS[info[1]]
    return None


_AES_RE = re.compile(
    r"^(?:id-)?aes[-_]?(128|192|256)?[-_]?"
    r"(gcm|gcmsiv|siv|ccm|cbc|ctr|ecb|ofb|cfb8|cfb1|cfb|xts|ocb|wrap|kw|kwp|cbchmacsha1|cbchmacsha256)?$"
)
_BLOCK_ALIASES = {
    "des3": ("3DES", 168, None),
    "3des": ("3DES", 168, None),
    "3des-ede": ("3DES", 168, None),
    "3des-ede3": ("3DES", 168, None),
    "des-ede3": ("3DES", 168, None),
    "des-ede": ("3DES", 112, None),
    "desede": ("3DES", 168, None),
    "tripledes": ("3DES", 168, None),
    "des": ("DES", 56, None),
    "rc4": ("RC4", None, None),
    "rc4-40": ("RC4", 40, None),
    "arcfour": ("RC4", None, None),
    "rc2": ("RC2", None, None),
    "bf": ("Blowfish", None, None),
    "blowfish": ("Blowfish", None, None),
    "cast5": ("CAST5", None, None),
    "cast": ("CAST5", None, None),
    "idea": ("IDEA", None, None),
    "seed": ("SEED", 128, None),
    "sm4": ("SM4", 128, None),
    "chacha20": ("ChaCha20", 256, None),
    "chacha20-poly1305": ("ChaCha20-Poly1305", 256, "AEAD"),
    "chacha": ("ChaCha20", 256, None),
    "rabbit": ("Rabbit", None, None),
}
_MODES = {
    "gcm": "GCM", "gcmsiv": "GCM-SIV", "siv": "SIV", "ccm": "CCM", "cbc": "CBC",
    "ctr": "CTR", "ecb": "ECB", "ofb": "OFB", "cfb": "CFB", "cfb8": "CFB8",
    "cfb1": "CFB1", "xts": "XTS", "ocb": "OCB", "wrap": "KW", "kw": "KW", "kwp": "KWP",
    "none": None, "poly1305": "AEAD",
}


def parse_openssl_cipher(value: str | None) -> dict | None:
    """Parse an OpenSSL/Node cipher name such as ``aes-256-gcm`` or ``des-ede3-cbc``."""
    if not value:
        return None
    raw = str(value).strip().strip("\"'")
    name = raw.lower().split("@")[0]
    m = _AES_RE.match(name.replace("_", "-").replace("--", "-"))
    if m:
        size = int(m.group(1)) if m.group(1) else None
        mode = _MODES.get((m.group(2) or "").replace("-", ""), None)
        return {"family": "AES", "key_size": size, "mode": mode, "raw": raw}
    for prefix in ("camellia", "aria"):
        cm = re.match(rf"^{prefix}[-_]?(128|192|256)?[-_]?([a-z0-9]+)?$", name)
        if cm:
            return {
                "family": prefix.upper() if prefix == "aria" else "Camellia",
                "key_size": int(cm.group(1)) if cm.group(1) else None,
                "mode": _MODES.get(cm.group(2) or "", None),
                "raw": raw,
            }
    parts = name.split("-")
    for cut in range(len(parts), 0, -1):
        head = "-".join(parts[:cut])
        if head in _BLOCK_ALIASES:
            family, size, mode = _BLOCK_ALIASES[head]
            tail = parts[cut:]
            if tail:
                if tail[0].isdigit():
                    size = int(tail[0])
                    tail = tail[1:]
                if tail:
                    mode = _MODES.get(tail[0], mode)
            return {"family": family, "key_size": size, "mode": mode, "raw": raw}
    return None


_JAVA_ALG_ALIASES = {
    "AES": ("AES", None),
    "AESWRAP": ("AES", None),
    "AES_128": ("AES", 128),
    "AES_192": ("AES", 192),
    "AES_256": ("AES", 256),
    "AESWRAP_128": ("AES", 128),
    "AESWRAP_256": ("AES", 256),
    "DESEDE": ("3DES", 168),
    "DESEDEWRAP": ("3DES", 168),
    "TRIPLEDES": ("3DES", 168),
    "DES": ("DES", 56),
    "RC2": ("RC2", None),
    "RC4": ("RC4", None),
    "ARCFOUR": ("RC4", None),
    "ARC4": ("RC4", None),
    "BLOWFISH": ("Blowfish", None),
    "RSA": ("RSA", None),
    "ECIES": ("ECIES", None),
    "CHACHA20": ("ChaCha20", 256),
    "CHACHA20-POLY1305": ("ChaCha20-Poly1305", 256),
    "SM4": ("SM4", 128),
    "SEED": ("SEED", 128),
    "CAMELLIA": ("Camellia", None),
    "IDEA": ("IDEA", None),
    "ELGAMAL": ("ElGamal", None),
}


def parse_java_transformation(value: str | None) -> dict | None:
    """Parse a JCE transformation such as ``AES/GCM/NoPadding``."""
    if not value:
        return None
    raw = str(value).strip().strip("\"'")
    if not raw:
        return None
    parts = [p.strip() for p in raw.split("/")]
    alg = parts[0].upper()
    mode = parts[1].upper() if len(parts) > 1 and parts[1] else None
    padding = parts[2] if len(parts) > 2 and parts[2] else None
    extra: dict[str, Any] = {}
    if alg.startswith("PBE"):
        inner = re.findall(r"(MD5|SHA-?\d+|DES|DESEDE|AES_?\d*|RC2|RC4)", alg)
        extra["pbe_transformation"] = raw
        family = "PBE"
        key_size = None
        for token in inner:
            mapped = _JAVA_ALG_ALIASES.get(token.replace("-", ""))
            if mapped and mapped[0] not in ("RSA",):
                family = "PBE-" + mapped[0]
                key_size = mapped[1]
                break
        # The inner digest of a PBE transformation is what SP 800-132 cares
        # about; keep it so the KB never has to re-parse the raw string.
        for token in inner:
            info = hash_info(token)
            if info:
                extra["hash"] = info[1]
                break
        return {
            "family": family, "key_size": key_size, "mode": mode,
            "padding": padding, "raw": raw, "extra": extra,
        }
    mapped = _JAVA_ALG_ALIASES.get(alg)
    if mapped is None:
        mapped = _JAVA_ALG_ALIASES.get(alg.replace("-", ""))
    if mapped is None:
        return None
    family, key_size = mapped
    if alg.endswith("WRAP") or alg.startswith("AESWRAP"):
        mode = mode or "KW"
    if mode == "NONE":
        mode = None
    return {
        "family": family, "key_size": key_size, "mode": mode,
        "padding": padding, "raw": raw, "extra": extra,
    }


_JWT_ALGS = {
    "hs256": {"family": "HMAC", "name": "HMAC-SHA-256", "hash": "SHA-256"},
    "hs384": {"family": "HMAC", "name": "HMAC-SHA-384", "hash": "SHA-384"},
    "hs512": {"family": "HMAC", "name": "HMAC-SHA-512", "hash": "SHA-512"},
    "rs256": {"family": "RSA", "name": "RSA-SHA-256", "padding": "PKCS1-v1_5", "hash": "SHA-256",
              "usage": "signature"},
    "rs384": {"family": "RSA", "name": "RSA-SHA-384", "padding": "PKCS1-v1_5", "hash": "SHA-384",
              "usage": "signature"},
    "rs512": {"family": "RSA", "name": "RSA-SHA-512", "padding": "PKCS1-v1_5", "hash": "SHA-512",
              "usage": "signature"},
    "ps256": {"family": "RSA", "name": "RSA-PSS-SHA-256", "padding": "PSS", "hash": "SHA-256",
              "usage": "signature"},
    "ps384": {"family": "RSA", "name": "RSA-PSS-SHA-384", "padding": "PSS", "hash": "SHA-384",
              "usage": "signature"},
    "ps512": {"family": "RSA", "name": "RSA-PSS-SHA-512", "padding": "PSS", "hash": "SHA-512",
              "usage": "signature"},
    "es256": {"family": "ECDSA", "name": "ECDSA-secp256r1", "curve": "secp256r1",
              "hash": "SHA-256", "usage": "signature"},
    "es256k": {"family": "ECDSA", "name": "ECDSA-secp256k1", "curve": "secp256k1",
               "hash": "SHA-256", "usage": "signature"},
    "es384": {"family": "ECDSA", "name": "ECDSA-secp384r1", "curve": "secp384r1",
              "hash": "SHA-384", "usage": "signature"},
    "es512": {"family": "ECDSA", "name": "ECDSA-secp521r1", "curve": "secp521r1",
              "hash": "SHA-512", "usage": "signature"},
    "eddsa": {"family": "Ed25519", "name": "Ed25519", "curve": "Ed25519", "usage": "signature"},
    "ed25519": {"family": "Ed25519", "name": "Ed25519", "curve": "Ed25519", "usage": "signature"},
    "none": {"family": "None", "name": "JWT-alg-none", "usage": "signature"},
    "rsa1_5": {"family": "RSA", "name": "RSA-PKCS1-v1_5", "padding": "PKCS1-v1_5",
               "usage": "key_encapsulation"},
    "rsa-oaep": {"family": "RSA", "name": "RSA-OAEP", "padding": "OAEP",
                 "usage": "key_encapsulation"},
    "rsa-oaep-256": {"family": "RSA", "name": "RSA-OAEP-256", "padding": "OAEP",
                     "hash": "SHA-256", "usage": "key_encapsulation"},
    "ecdh-es": {"family": "ECDH", "name": "ECDH-ES", "usage": "key_agreement"},
    "a128kw": {"family": "AES", "name": "AES-128-KW", "key_size": 128, "mode": "KW"},
    "a256kw": {"family": "AES", "name": "AES-256-KW", "key_size": 256, "mode": "KW"},
    "a128gcm": {"family": "AES", "name": "AES-128-GCM", "key_size": 128, "mode": "GCM"},
    "a256gcm": {"family": "AES", "name": "AES-256-GCM", "key_size": 256, "mode": "GCM"},
    "a128cbc-hs256": {"family": "AES", "name": "AES-128-CBC", "key_size": 128, "mode": "CBC"},
    "a256cbc-hs512": {"family": "AES", "name": "AES-256-CBC", "key_size": 256, "mode": "CBC"},
}


def parse_jwt_alg(value: str | None) -> dict | None:
    """Recognise a JOSE ``alg``/``enc`` value (RFC 7518).

    The returned dict carries a structured ``usage`` for the asymmetric
    entries, so the recommender can tell a signature key from a key-transport
    key without substring-matching file paths.
    """
    if not value:
        return None
    found = _JWT_ALGS.get(str(value).strip().strip("\"'").lower())
    return dict(found) if found is not None else None


def tls_version(value: str | None) -> str | None:
    """Normalise any spelling of a TLS/SSL version to ``TLSv1.2`` / ``SSLv3``."""
    if value is None:
        return None
    raw = str(value).strip().strip("\"'")
    key = raw.lower().replace("_", "").replace("-", "").replace(" ", "")
    key = key.replace("tlsversion", "").replace("versiontls", "tls")
    # "SSLv23"/"SSL23" is OpenSSL's *version-negotiating* method, not SSL 2.0.
    # Check it before the SSLv2 substring test, which would otherwise match.
    if "sslv23" in key or "ssl23" in key or "sslv2method" in key:
        return "TLS (unpinned)"
    if "ssl3" in key or "sslv3" in key or key.endswith("ssl30"):
        return "SSLv3"
    if "ssl2" in key or "sslv2" in key:
        return "SSLv2"
    m = re.search(r"tls\.?v?(1)\.?(\d)?", key)
    if m:
        minor = m.group(2) if m.group(2) is not None else "0"
        return f"TLSv1.{minor}"
    if key in ("tls", "tlsv1", "ssl", "tlsall", "tlsauto"):
        return "TLS (unpinned)"
    if re.fullmatch(r"1\.?[0-3]", key):
        return "TLSv" + (key if "." in key else key[0] + "." + key[1:])
    if key in ("tls13", "tlsv13"):
        return "TLSv1.3"
    return None


# (regex, family, display, standardised, superseded_by)
_PQC_PATTERNS: tuple[tuple[str, str, str, bool, str | None], ...] = (
    (r"ml[-_]?kem[-_]?(512|768|1024)?", "ML-KEM", "ML-KEM", True, None),
    (r"mlkem(512|768|1024)?", "ML-KEM", "ML-KEM", True, None),
    (r"kyber[-_]?(512|768|1024)?", "ML-KEM", "Kyber", False, "ML-KEM (FIPS 203)"),
    (r"ml[-_]?dsa[-_]?(44|65|87)?", "ML-DSA", "ML-DSA", True, None),
    (r"mldsa(44|65|87)?", "ML-DSA", "ML-DSA", True, None),
    (r"dilithium[-_]?(2|3|5)?", "ML-DSA", "Dilithium", False, "ML-DSA (FIPS 204)"),
    (r"slh[-_]?dsa[-_]?\w*", "SLH-DSA", "SLH-DSA", True, None),
    (r"sphincs\+?[-_]?\w*", "SLH-DSA", "SPHINCS+", False, "SLH-DSA (FIPS 205)"),
    (r"falcon[-_]?(512|1024)?", "FN-DSA", "Falcon", False, "FN-DSA (FIPS 206, draft)"),
    (r"fn[-_]?dsa[-_]?(512|1024)?", "FN-DSA", "FN-DSA", False, None),
    (r"frodokem[-_]?\w*", "FrodoKEM", "FrodoKEM", False, None),
    (r"classic[-_]?mceliece\w*", "Classic-McEliece", "Classic-McEliece", False, None),
    (r"bike[-_]?l\d", "BIKE", "BIKE", False, None),
    (r"hqc[-_]?\d+", "HQC", "HQC", False, None),
    (r"xmssmt|xmss", "XMSS", "XMSS", True, None),
    (r"lms[-_]?hss|hss[-_]?lms|lms", "LMS", "LMS", True, None),
    (r"sike[-_]?p?\d*|sidh[-_]?p?\d*", "SIKE", "SIKE", False, None),
    (r"rainbow[-_]?\w*", "Rainbow", "Rainbow", False, None),
)
_PQC_RE = re.compile(
    "|".join(f"(?P<g{i}>{pat})" for i, (pat, _f, _d, _s, _u) in enumerate(_PQC_PATTERNS)),
    re.IGNORECASE,
)

#: Schemes that are stateful hash-based signatures: reusing a one-time key
#: index yields practical forgery (SP 800-208), so "already quantum-safe" is
#: never the whole story for them.
_PQC_STATEFUL = {"XMSS", "LMS"}

#: Candidates broken by *classical* cryptanalysis (Castryck-Decru 2022 against
#: SIDH/SIKE; Beullens 2022 against Rainbow).  They must never be reported as
#: post-quantum protection.
_PQC_BROKEN = {"SIKE", "Rainbow"}


def pqc_info(token: str | None) -> dict | None:
    """Recognise a post-quantum algorithm name inside an identifier/package.

    The returned dict carries the caveats the recommender needs so it cannot
    contradict the knowledge base:

    ``standardised``    final FIPS parameter set (ML-KEM / ML-DSA / SLH-DSA)
    ``pre_standard``    round-3 spelling that is wire-incompatible with FIPS
    ``standardised_as`` what to migrate a pre-standard scheme to
    ``stateful``        XMSS/LMS: needs audited key-state management
    ``broken``          SIKE/SIDH/Rainbow: classically broken, remove
    """
    if not token:
        return None
    m = _PQC_RE.search(str(token))
    if not m:
        return None
    for i, (_pat, family, display, standardised, superseded) in enumerate(_PQC_PATTERNS):
        if m.group(f"g{i}"):
            matched = m.group(f"g{i}")
            level = re.search(r"(\d{2,4})", matched)
            name = display + (f"-{level.group(1)}" if level else "")
            return {
                "family": family,
                "name": name,
                "matched": matched,
                "standardised": bool(standardised),
                "pre_standard": bool(superseded),
                "standardised_as": superseded,
                "stateful": family in _PQC_STATEFUL,
                "broken": family in _PQC_BROKEN,
            }
    return None


_ASYM_SIZED = {"RSA", "DSA", "DH", "ElGamal", "RSA-PSS"}
_EC_FAMILIES = {"ECDSA", "ECDH", "EC", "ECIES", "ECMQV"}
_SYMMETRIC = {
    "AES", "Camellia", "ARIA", "SEED", "SM4", "Blowfish", "CAST5", "IDEA",
    "3DES", "DES", "RC2", "RC4", "ChaCha20", "ChaCha20-Poly1305", "Rabbit", "Salsa20",
}


def canon_name(
    family: str,
    key_size: int | None = None,
    curve: str | None = None,
    mode: str | None = None,
    variant: str | None = None,
) -> str:
    """Canonical display name, e.g. ``RSA-1024``/``ECDSA-secp256r1``/``AES-256-GCM``."""
    if family in _ASYM_SIZED:
        return f"{family}-{key_size}" if key_size else family
    if family in _EC_FAMILIES:
        return f"{family}-{curve}" if curve else family
    if family in _SYMMETRIC:
        parts = [family]
        if key_size and family not in ("ChaCha20", "ChaCha20-Poly1305"):
            parts.append(str(key_size))
        if mode:
            parts.append(mode)
        return "-".join(parts)
    if family == "HMAC":
        return f"HMAC-{variant}" if variant else "HMAC"
    if family == "TLS":
        return variant or (f"TLS-{mode}" if mode else "TLS")
    if variant:
        return variant
    return family


# --------------------------------------------------------------------------
# artefact collection
# --------------------------------------------------------------------------
_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


class Collector:
    """Accumulates artefacts, merging by (family, name, kind, key params).

    ``name`` is part of the merge identity on purpose: SHA-256 and SHA-512 are
    both ``family="SHA-2"`` with no other distinguishing parameter, and folding
    them together would attribute one algorithm's occurrences to the other.
    """

    def __init__(self, detector: str) -> None:
        self.detector = detector
        self._by_key: dict[tuple, Artefact] = {}
        self._seen: dict[tuple, Occurrence] = {}

    # -- internals ------------------------------------------------------
    @staticmethod
    def _merge_extra(target: dict, extra: dict | None) -> None:
        if not extra:
            return
        for key, value in extra.items():
            if key not in target or target[key] in (None, "", [], {}):
                target[key] = list(dict.fromkeys(value)) if isinstance(value, list) else value
            elif isinstance(target[key], list):
                if isinstance(value, list):
                    for item in value:
                        if item not in target[key]:
                            target[key].append(item)
                elif value not in target[key]:
                    target[key].append(value)

    @staticmethod
    def _enrich_hash_extra(family: str, name: str, extra: dict) -> None:
        """Record the digest length so nothing downstream has to guess it.

        ``family="SHA-2"`` carries no digest length, and the knowledge base
        cannot recover one from it -- which is exactly why every SHA-2 finding
        used to classify as UNKNOWN.  The variant is unambiguous in ``name``,
        so stamp it here, at the one place that knows both.
        """
        if family not in HASH_FAMILIES:
            return
        if family == "HMAC":
            inner = name[5:] if name.upper().startswith("HMAC-") else None
            info = hash_info(inner) if inner else None
            if info:
                extra.setdefault("hash", info[1])
                bits = digest_bits(info[1])
                if bits:
                    # NB: the digest size, never the HMAC *key* length --
                    # params.key_size stays the key length.
                    extra.setdefault("digest_size", bits)
            return
        extra.setdefault("variant", name)
        bits = digest_bits(name)
        if bits:
            extra.setdefault("digest_size", bits)
        elif name in _XOF_SECURITY_BITS:
            extra.setdefault("security_bits", _XOF_SECURITY_BITS[name])
            extra.setdefault("xof", True)

    def add(
        self,
        *,
        family: str,
        file: str,
        line: int | None,
        evidence: str,
        name: str | None = None,
        kind: str = "algorithm",
        key_size: int | None = None,
        curve: str | None = None,
        mode: str | None = None,
        padding: str | None = None,
        not_after: str | None = None,
        variant: str | None = None,
        extra: dict | None = None,
        confidence: str = "high",
    ) -> Artefact:
        curve = normalize_curve(curve) if curve else None
        if name is None:
            name = canon_name(
                family, key_size=key_size, curve=curve, mode=mode, variant=variant
            )
        # Occurrence paths are the engine-wide convention: POSIX, root-relative.
        file = str(file).replace(os.sep, "/").replace("\\", "/")

        merged_extra = dict(extra or {})
        self._enrich_hash_extra(family, name, merged_extra)

        key = (family, name, kind, key_size, curve, mode, padding)
        artefact = self._by_key.get(key)
        if artefact is None:
            params = Params(
                key_size=key_size,
                curve=curve,
                mode=mode,
                padding=padding,
                not_after=not_after,
                extra=merged_extra,
            )
            artefact = Artefact(
                name=name, family=family, kind=kind, params=params, occurrences=[]
            )
            self._by_key[key] = artefact
        else:
            self._merge_extra(artefact.params.extra, merged_extra)
            if not_after and not artefact.params.not_after:
                artefact.params.not_after = not_after

        occ_key = (key, file, line, snippet(evidence or ""))
        existing = self._seen.get(occ_key)
        if existing is None:
            occurrence = Occurrence(
                file=file,
                line=line,
                evidence=snippet(evidence or ""),
                detector=self.detector,
                confidence=confidence,
            )
            self._seen[occ_key] = occurrence
            artefact.occurrences.append(occurrence)
        elif _CONFIDENCE_RANK.get(confidence, 0) > _CONFIDENCE_RANK.get(existing.confidence, 0):
            existing.confidence = confidence
        return artefact

    def artefacts(self) -> list[Artefact]:
        out = list(self._by_key.values())
        for artefact in out:
            artefact.occurrences.sort(key=lambda o: (o.file, o.line or 0))
        out.sort(key=lambda a: (a.kind, a.family, a.name))
        return out

    def __len__(self) -> int:
        return len(self._by_key)


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------
def _self_test() -> int:
    """Assert the invariants this module promises.  ``python -m`` runnable."""
    failures: list[str] = []

    def check(label: str, got: Any, want: Any) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    # glob semantics -- the fnmatch bug the review found
    check("glob top-level node_modules",
          glob_match("**/node_modules/**", "node_modules/x.js"), True)
    check("glob nested node_modules",
          glob_match("**/node_modules/**", "src/node_modules/x.js"), True)
    check("glob no false positive on monkeys",
          glob_match("**/keys/**", "src/monkeys/a.py"), False)
    check("glob real keys dir", glob_match("**/keys/**", "src/keys/a.py"), True)
    check("glob dir itself", glob_match("vendor/**", "vendor"), True)
    check("glob star no cross slash", glob_match("src/*.js", "src/a/b.js"), False)
    check("glob basename pattern", glob_match("*.min.js", "dist/a.min.js"), True)

    # policy delegation
    class _P:
        def is_ignored(self, path: str) -> bool:
            return path.startswith("skipme")

    pv = PolicyView(_P())
    check("policy is_ignored honoured", pv.allows("skipme/a.js"), False)
    check("policy allows others", pv.allows("src/a.js"), True)
    check("policy_driven", pv.policy_driven, True)
    check("dict ignore_paths", PolicyView({"ignore_paths": ["**/gen/**"]}).allows("a/gen/b.js"), False)
    check("no policy -> builtin dirs", PolicyView().allows_dir("node_modules", "node_modules"), False)

    # masking
    m = mask_source('var a = "crypto.createHash"; // crypto.createHash\ncrypto.createHash("md5");', "js")
    check("mask hides string+comment", m.code.count("createHash"), 1)
    check("mask keeps string in text view", m.text.count("createHash"), 2)
    check("line count preserved", len(m.src), len(m.code))

    calls = iter_calls(m)
    check("one call site", [c.callee for c in calls], ["crypto.createHash"])
    check("arg captured", lit_str(calls[0].arg(0)), "md5")

    # hashes / digest provenance
    check("hash_info sha256", hash_info("SHA256"), ("SHA-2", "SHA-256"))
    check("digest bits", digest_bits("SHA-256"), 256)
    c = Collector("test")
    a = c.add(family="SHA-2", name="SHA-256", file="src\\a.js", line=1, evidence="x")
    check("digest stamped", a.params.extra.get("digest_size"), 256)
    check("variant stamped", a.params.extra.get("variant"), "SHA-256")
    check("posix path", a.occurrences[0].file, "src/a.js")
    c.add(family="SHA-2", name="SHA-512", file="src/a.js", line=2, evidence="y")
    check("name is part of identity", len(c), 2)
    h = c.add(family="HMAC", name="HMAC-SHA-256", key_size=128, file="a.js", line=3, evidence="z")
    check("hmac inner hash", h.params.extra.get("hash"), "SHA-256")
    check("hmac key size untouched", h.params.key_size, 128)

    # ciphers / versions / pqc
    check("aes parse", parse_openssl_cipher("aes-256-gcm"),
          {"family": "AES", "key_size": 256, "mode": "GCM", "raw": "aes-256-gcm"})
    check("jce parse mode", (parse_java_transformation("AES/GCM/NoPadding") or {}).get("mode"), "GCM")
    check("sslv23 is not sslv2", tls_version("PROTOCOL_SSLv23"), "TLS (unpinned)")
    check("sslv3", tls_version("PROTOCOL_SSLv3"), "SSLv3")
    check("tls12", tls_version("TLSv1_2"), "TLSv1.2")
    check("kyber pre-standard", (pqc_info("kyber768") or {}).get("pre_standard"), True)
    check("mlkem standard", (pqc_info("ML-KEM-768") or {}).get("standardised"), True)
    check("xmss stateful", (pqc_info("xmss") or {}).get("stateful"), True)
    check("sike broken", (pqc_info("sikep434") or {}).get("broken"), True)
    check("jwt usage", (parse_jwt_alg("RS256") or {}).get("usage"), "signature")

    for line in failures:
        print("FAIL", line)
    print(f"_srcutil self-test: {'OK' if not failures else str(len(failures)) + ' failure(s)'}")
    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())

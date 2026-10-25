"""Example tools, each hardened against its own class of abuse."""
from __future__ import annotations

import ast
import json
import operator
import re
import sqlite3
from pathlib import Path

from .errors import SandboxViolation, ToolError
from .memory import SecureMemory
from .tools import Tool, ToolContext, ToolRegistry


class Effects:
    """Records real-world side effects so tests can prove what did (not) happen."""

    def __init__(self):
        self.emails: list[dict] = []
        self.deleted: list[int] = []
        self.files_read: list[str] = []
        self.queries: list[str] = []
        self.memory: list[str] = []


# ---------------------------------------------------------------- calculator
_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.Mod: operator.mod, ast.Pow: operator.pow}
_UNARY = {ast.USub: operator.neg, ast.UAdd: operator.pos}


def safe_calculate(expr: str) -> str:
    """AST-walking calculator: never uses eval(); bounded exponent to prevent CPU DoS."""
    if len(expr) > 100:
        raise ToolError("expression too long")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ToolError("invalid expression") from exc

    def ev(node, depth=0):
        if depth > 20:
            raise ToolError("expression too deep")
        if isinstance(node, ast.Expression):
            return ev(node.body, depth + 1)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            return _UNARY[type(node.op)](ev(node.operand, depth + 1))
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            left, right = ev(node.left, depth + 1), ev(node.right, depth + 1)
            if isinstance(node.op, ast.Pow) and abs(right) > 100:
                raise ToolError("exponent too large")
            try:
                result = _OPS[type(node.op)](left, right)
            except ZeroDivisionError as exc:
                raise ToolError("division by zero") from exc
            if abs(result) > 1e100:
                raise ToolError("result too large")
            return result
        raise ToolError("unsupported expression")

    result = ev(tree)
    return str(int(result)) if float(result).is_integer() else str(round(result, 10))


# ------------------------------------------------------------- file sandbox
class FileSandbox:
    ALLOWED_SUFFIXES = {".txt", ".md", ".csv"}
    MAX_BYTES = 100_000

    def __init__(self, base_dir):
        self.base = Path(base_dir).resolve()

    def read(self, relative: str) -> str:
        if not relative or "\x00" in relative:
            raise SandboxViolation("invalid path")
        target = (self.base / relative).resolve()          # resolves .. and symlinks
        if not target.is_relative_to(self.base):
            raise SandboxViolation("path escapes the sandbox")
        if target.suffix.lower() not in self.ALLOWED_SUFFIXES:
            raise SandboxViolation("file type not allowed")
        if not target.is_file():
            raise ToolError("file not found")
        if target.stat().st_size > self.MAX_BYTES:
            raise ToolError("file too large")
        return target.read_text(encoding="utf-8", errors="replace")


# ------------------------------------------------------------ read-only SQL
_SQL_OK, _SQL_DENY, _SQL_READ, _SQL_SELECT, _SQL_FUNCTION = 0, 1, 20, 21, 31
ALLOWED_SQL_FUNCS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "round", "abs"}


def _authorizer(allowed_tables: set[str]):
    allowed = {t.lower() for t in allowed_tables}

    def cb(action, arg1, arg2, db_name, source):
        if action == _SQL_SELECT:
            return _SQL_OK
        if action == _SQL_READ:
            return _SQL_OK if (arg1 or "").lower() in allowed else _SQL_DENY
        if action == _SQL_FUNCTION:
            return _SQL_OK if (arg2 or "").lower() in ALLOWED_SQL_FUNCS else _SQL_DENY
        return _SQL_DENY                                   # everything else: deny

    return cb


def run_readonly_query(conn: sqlite3.Connection, sql: str,
                       allowed_tables: set[str], max_rows: int = 50) -> str:
    s = sql.strip()
    if not s or len(s) > 500:
        raise ToolError("query empty or too long")
    if s.endswith(";"):
        s = s[:-1].rstrip()
    if ";" in s:
        raise ToolError("multiple statements are not allowed")
    if "--" in s or "/*" in s:
        raise ToolError("comments are not allowed")
    if not re.match(r"(?is)^select\b", s):
        raise ToolError("only SELECT queries are allowed")
    conn.set_authorizer(_authorizer(allowed_tables))       # engine-level enforcement
    try:
        cur = conn.execute(s)
        cols = [c[0] for c in cur.description or []]
        rows = [dict(zip(cols, r)) for r in cur.fetchmany(max_rows)]
    except sqlite3.Error as exc:
        raise ToolError("query rejected by database policy") from exc
    finally:
        conn.set_authorizer(None)
    return json.dumps(rows, default=str)


# --------------------------------------------------------------------- email
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def make_email_validator(allowed_domains: set[str]):
    allowed = {d.lower() for d in allowed_domains}

    def validate(args: dict) -> None:
        if any(c in args["to"] + args["subject"] for c in "\r\n"):
            raise ToolError("header injection detected")
        m = _EMAIL_RE.fullmatch(args["to"])
        if not m or m.group(1).lower() not in allowed:
            raise ToolError("recipient domain is not on the allowlist")
        if len(args["subject"]) > 200 or len(args["body"]) > 2000:
            raise ToolError("subject/body too long")

    return validate


# ------------------------------------------------------------------ registry
def build_default_registry(effects: Effects, sandbox: FileSandbox, db: sqlite3.Connection,
                           memory: SecureMemory, *, allowed_tables: set[str],
                           email_domains: set[str], untrusted_threshold: int = 2) -> ToolRegistry:
    reg = ToolRegistry(untrusted_threshold)

    def read_file(args, ctx):
        effects.files_read.append(args["path"])
        return sandbox.read(args["path"])

    def query_db(args, ctx):
        effects.queries.append(args["sql"])
        return run_readonly_query(db, args["sql"], allowed_tables)

    def send_email(args, ctx):
        effects.emails.append(dict(args))
        return f"email queued to {args['to']}"

    def delete_record(args, ctx):
        effects.deleted.append(args["id"])
        return f"record {args['id']} deleted"

    def remember(args, ctx: ToolContext):
        memory.write(ctx.identity, args["text"],
                     source="user_confirmed" if ctx.approved else "model")
        effects.memory.append(args["text"])
        return "saved to memory"

    reg.register(Tool("calculator", "Evaluate arithmetic", lambda a, c: safe_calculate(a["expression"]),
                      "tool:calculator", "low", {"expression": str}))
    reg.register(Tool("read_file", "Read a text file from the sandbox", read_file,
                      "tool:read_file", "low", {"path": str}))
    reg.register(Tool("query_db", "Run a read-only SELECT", query_db,
                      "tool:query_db", "medium", {"sql": str}))
    reg.register(Tool("send_email", "Send an email", send_email, "tool:send_email", "high",
                      {"to": str, "subject": str, "body": str}, make_email_validator(email_domains)))
    reg.register(Tool("delete_record", "Delete a record", delete_record,
                      "tool:delete_record", "high", {"id": int}))
    reg.register(Tool("remember", "Store a user preference in memory", remember,
                      "tool:remember", "high", {"text": str}))
    return reg

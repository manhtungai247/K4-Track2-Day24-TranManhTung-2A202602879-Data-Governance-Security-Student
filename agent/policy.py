"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

_PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
_CLASSIFICATIONS = {"public", "internal", "restricted"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    if context.data_classification not in _CLASSIFICATIONS:
        return False, "Unknown data classification"
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data cannot be sent through an egress tool"

    try:
        principals = json.loads(_PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "Principal policy could not be loaded"
    principal = principals.get(context.principal_id)
    if principal is None:
        return False, "Unknown principal"
    if not context.agent_owner or not context.requested_tool:
        return False, "Agent identity or requested tool is missing"
    if context.requested_tool not in principal.get("allowed_tools", []):
        return False, f"Principal {context.principal_id} is not allowed to use {context.requested_tool}"
    if context.requested_tool not in context.agent_scopes:
        return False, "Requested tool is outside agent scopes"
    if context.delegation_depth < 0:
        return False, "Delegation depth is invalid"
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return False, "Requested tool is outside parent scopes"
    if context.request_purpose not in principal.get("purposes", []):
        return False, f"Purpose {context.request_purpose!r} is not allowed for {context.principal_id}"
    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("expiry must include a timezone")
        if expires_at.utcoffset() != timezone.utc.utcoffset(expires_at):
            return False, "Authorization expiry must be UTC"
        if expires_at.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return False, "Authorization has expired"
    except (AttributeError, TypeError, ValueError):
        return False, "Authorization expiry is missing or invalid"
    return True, f"{context.principal_id} may use {context.requested_tool} for {context.request_purpose}"

"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    run_id = str(uuid4())
    agent_id = "lab24-agent"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir is not None else DEFAULT_LEDGER_PATH
    principal_path = Path(__file__).resolve().parent.parent / "data" / "principals.json"
    try:
        principals = json.loads(principal_path.read_text(encoding="utf-8"))
        principal = principals.get(principal_id, {})
        agent_scopes = tuple(principal.get("allowed_tools", []))
        purposes = principal.get("purposes", [])
    except (OSError, json.JSONDecodeError):
        agent_scopes, purposes = (), []
    parent_scopes = agent_scopes

    def request_tool(tool_name: str, args: dict, classification: str,
                     purpose: str, operation, *, egress: bool = False,
                     delegation_depth: int = 0):
        context = PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=f"{agent_id}/{run_id}",
            delegation_depth=delegation_depth,
            egress_enabled=egress,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes if delegation_depth else (),
            expires_at=expires_at,
        )
        allowed, reason = policy.check(context)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool_name,
            "args_hash": hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason or "Policy returned no reason",
        }
        ledger.append(entry, ledger_path)
        return operation() if allowed else None

    # Run A reads untrusted tickets only. Ticket IDs cross the boundary solely
    # through filenames; free text is never used to select a customer.
    docs = request_tool(
        "search_docs", {"query": message}, "internal", "summarize-tickets",
        lambda: tools.search_docs(message),
    ) or []
    safe_docs = [{**doc, "text": pii.redact(doc["text"])} for doc in docs]
    ticket_ids = sorted({int(match.group(1)) for doc in docs
                         if (match := re.fullmatch(r"ticket-(\d+)\.md", doc["id"]))})

    # Trusted relationship data maps ticket IDs to customer IDs. The DPO may
    # read related records; denied principals still get an auditable decision.
    customers_path = Path(__file__).resolve().parent.parent / "data" / "customers.json"
    try:
        customers = json.loads(customers_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        customers = []
    related = [record for record in customers
               if set(ticket_ids).intersection(record.get("related_tickets", []))]
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in docs))
    if injected is not None:
        for customer in related:
            request_tool(
                "read_customer", {"customer_id": customer["customer_id"]},
                "restricted", "support-reply",
                lambda customer_id=customer["customer_id"]: tools.read_customer(customer_id),
                delegation_depth=1,
            )
        request_tool(
            "http_post", {"url": injected.target_url}, "restricted", "support-reply",
            lambda: tools.http_post(injected.target_url, {}), egress=True,
            delegation_depth=1,
        )
    return llm.summarize(safe_docs)

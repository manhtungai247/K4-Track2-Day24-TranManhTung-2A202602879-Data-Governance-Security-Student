"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_ZERO_HASH = "0" * 64


def _hash(entry: dict) -> str:
    encoded = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    previous_hash = _ZERO_HASH
    if path.exists() and path.stat().st_size:
        last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
        previous_hash = last["hash"]
    recorded = dict(entry)
    recorded.pop("hash", None)
    recorded["prev_hash"] = previous_hash
    recorded["hash"] = _hash(recorded)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(recorded, ensure_ascii=False, sort_keys=True) + "\n")
    return recorded


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False
    previous_hash = _ZERO_HASH
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    return False
                entry = json.loads(line)
                saved_hash = entry.pop("hash", None)
                if not str(entry.get("reason", "")).strip():
                    return False
                if entry.get("prev_hash") != previous_hash or saved_hash != _hash(entry):
                    return False
                previous_hash = saved_hash
        return True
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return False

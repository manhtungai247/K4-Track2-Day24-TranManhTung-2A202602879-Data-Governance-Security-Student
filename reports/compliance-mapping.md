# Compliance mapping — kiểm soát kỹ thuật và giới hạn

Đây là mapping kỹ thuật ở mức lab, không phải đánh giá tuân thủ hay ý kiến pháp lý. Đối chiếu tiêu đề/số hiệu/ngày hiệu lực trên cổng văn bản Chính phủ; không gán một điều khoản cụ thể cho kiểm soát dưới đây.

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 — Luật Bảo vệ dữ liệu cá nhân (hiệu lực 01-01-2026) | Phát hiện/redact mẫu PII và giới hạn đọc hồ sơ bằng principal/purpose/tool | `agent/pii.py:45-69`; `agent/policy.py:60-98`; `agent/runner.py:133-153` | Fixture giả; không xác định căn cứ xử lý, thông báo, đồng ý, quyền chủ thể hay nghĩa vụ tổ chức. [Văn bản chính thức](https://vanban.chinhphu.vn/?docid=214590&pageid=27160) |
| Nghị định 356/2025/NĐ-CP — hướng dẫn thi hành Luật Bảo vệ dữ liệu cá nhân (hiệu lực 01-01-2026) | Ghi quyết định allow/deny, principal, purpose và thời hạn; giữ bằng chứng hash-chain | `agent/policy.py:60-98`; `agent/runner.py:96-128`; `agent/ledger.py:52-91` | Không phải hồ sơ đánh giá tác động hoặc chứng minh đáp ứng thủ tục/biện pháp theo nghị định. [Văn bản chính thức](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160&typegroupid=4) |
| Luật 134/2025/QH15 — Luật Trí tuệ nhân tạo (hiệu lực 01-03-2026) | Giới hạn hành động tool tại policy boundary; tách dữ liệu không tin cậy khỏi việc lựa chọn hồ sơ riêng | `agent/policy.py:60-98`; `agent/runner.py:130-160` | Mock không đánh giá rủi ro/hạng hệ thống, nghĩa vụ nhà cung cấp/triển khai, giám sát hay các yêu cầu pháp lý cụ thể. [Văn bản chính thức](https://vanban.chinhphu.vn/?docid=216334&orggroupid=1&pageid=27160) |
| OWASP ASI01 — Agent Goal Hijack | Test bốn lure qua `find_injection`; không cho nội dung ticket tự quyết định khách | `agent/llm.py:35-60`; `agent/runner.py:134-153`; `tests/test_injection.py` | Deterministic mock và bốn fixture, không đại diện mọi prompt injection. |
| OWASP ASI03 — Identity & Privilege Abuse | Giao quyền principal/tool/scope/purpose/TTL; support_l1 bị chặn, dpo được đọc hồ sơ có quan hệ | `agent/policy.py:60-98`; `tests/test_obo.py` | `--as` chỉ chọn principal giả lập, không xác thực người dùng thật. |
| OWASP ASI04 — Agentic Supply Chain Vulnerabilities | Pin hook Gitleaks và hash dependency; ghi nhận token lab trong Git history | `.pre-commit-config.yaml`; `requirements.lock`; `reports/secrets-incident.md` | Chưa chứng minh an toàn toàn bộ dependency hoặc môi trường triển khai. [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) |

Tên và hiệu lực các văn bản Việt Nam được tra từ cổng văn bản Chính phủ. OWASP dùng taxonomy Agentic Security Initiative (ASI), không phải mã LLM01/LLM03/LLM05.

# Baseline — trước khi thêm policy/OBO/split/ledger

1. **Agent có identity mỗi run chưa?** Chưa. `_naive_loop()` ở `agent/loop.py:27` nhận message và LLM nhưng không tạo `agent_id`, `run_id` hay principal để kiểm quyền.
2. **Ai cho phép `http_post`?** Không có policy gate. Nếu `find_injection()` trả instruction, `_naive_loop()` tự đọc các customer ID rồi gọi `tools.http_post()` ở `agent/loop.py:34-44`; chỉ allowlist localhost trong `agent/tools.py:68-85` giới hạn đích, không quyết định quyền hay dữ liệu.
3. **Bằng chứng gửi sai PII ở đâu?** Baseline tạo body từ customer record tại `agent/loop.py:37-44`. Sink nhận POST và ghi `path`/`body` vào `reports/sink.log` tại `sink/sink.py:42-47`. Bản chụp bốn biến thể là `reports/attack-before.log` (4 dòng; dữ liệu KH-000999 là synthetic).

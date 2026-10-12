# Verification — 2026-10-12

- **OS / Python / Gitleaks:** Windows; Python 3.12.14; Gitleaks 8.30.1. Windows `python` app alias không có runtime cài đặt, nên dùng `.venv/Scripts/python.exe` từ Python runtime sẵn có.
- **PII (`tests/test_pii.py -v -s`):** `gold=118 pred=118 tp=118`, precision `1.000`, recall `1.000` (100%). Regex hoạt động trên bộ dữ liệu synthetic; account cần nhãn `STK`/`số tài khoản`, và không nhận diện mọi biến thể viết cách/che ký tự/ngữ nghĩa.
- **CP3a–CP3e:** `tests/test_policy.py` 4 passed; `tests/test_obo.py` 5 passed; `tests/test_split.py` 1 passed; `tests/test_ledger.py` 3 passed. OBO xác nhận support_l1 bị deny, dpo đọc được hồ sơ hợp lệ, scope con không vượt scope cha; mỗi tool decision của runner có reason và các trường audit.
- **Injection:** `tests/test_injection.py` 8 passed; không SKIP. `python -m agent.check_lure corpus/ticket-90*.md` báo `4/4 lure sẵn sàng`.
- **Toàn bộ suite:** `.venv/Scripts/python.exe -m pytest tests/ -q --basetemp=.pytest_tmp` → `33 passed in 3.69s`, 0 failed, 0 skipped.
- **Supply chain:** `tests/test_supply_chain.py` nằm trong full suite và pass. `pip install --require-hashes -r requirements.lock` thành công. `pre-commit run --all-files` → `Detect hardcoded secrets...Passed`.
- **Gitleaks:** `gitleaks git --config .gitleaks.toml --redact .` → exit 1, đúng 1 synthetic finding tại `lab-fake-secret.txt`, commit `1bdd849`, rule `lab24-synthetic-token`. `gitleaks dir --config .gitleaks.toml --redact .` → exit 0, no findings sau allowlist `.venv/` cho hai false positive trong README của scanner.
- **Bằng chứng chạy:** `reports/attack-before.log` có 4 POST synthetic; `reports/attack-after.log` 0 byte. Lượt `--mock --as dpo` tạo ledger 23 dòng (22 allow, 1 deny); deny `http_post` có reason và `on_behalf_of=dpo`. `verify(Path('reports/ledger.jsonl'))` → `True`.
- **Giới hạn:** fixture `--as` không xác thực người vận hành; regex chỉ bao phủ mẫu đã biết; hash chain một file không phát hiện xóa dòng cuối/viết lại toàn bộ; lab không chứng minh production safety hoặc tuân thủ pháp luật.

# Secret giả trong lịch sử Git — kết quả CP4

- **Scanner/phiên bản:** Gitleaks `8.30.1`, chạy bằng bản Windows chính thức.
- **Commit chứa token giả:** `1bdd849` (`lab-fake-secret.txt`).
- **Quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact .` quét 4 commits, exit 1 như dự kiến; JSON report đã redact cho thấy đúng 1 finding, rule `lab24-synthetic-token`, file `lab-fake-secret.txt`, commit `1bdd849`.
- **Quét working tree:** `gitleaks dir --config .gitleaks.toml --redact .` exit 0, không finding. Lần quét ban đầu thấy 2 finding false positive trong README của binary Gitleaks tải vào `.venv/Scripts/gitleaks/`; đã thêm allowlist chỉ cho `.venv/` trong `.gitleaks.toml` rồi quét lại sạch. Không tắt rule lab.
- **Hook:** `.pre-commit-config.yaml` dùng repo chính thức, pin `v8.30.1`, `gitleaks-system`, `pass_filenames: false`. `pre-commit run --all-files` pass. Hook chạy ở chế độ staged; quét working tree riêng ở trên cung cấp xác nhận file hiện tại.
- **Nếu là credential thật:** thu hồi/rotate tại dịch vụ cấp token; điều tra sử dụng trái phép; xử lý mọi bản sao và thông báo theo quy trình áp dụng. Xóa khỏi HEAD không vô hiệu hóa bản đã lộ trong lịch sử.
- **Giới hạn:** token trong bài là chuỗi synthetic, vô hiệu, gắn rule `lab24-synthetic-token`. Pin dependency/hook giúp tăng tính tái lập và phát hiện, nhưng không thể thu hồi credential hay bảo đảm scanner nhận mọi dạng secret.

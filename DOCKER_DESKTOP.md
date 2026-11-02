# Sentinel OS — Docker Desktop trên Windows 10/11

## 1. Phần mềm cần cài

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) với backend WSL2/Linux containers.
- Git for Windows để sao chép/cập nhật repository; hoặc tải ZIP từ GitHub và giải nén.
- **Chỉ khi quét LAN:** Node.js 22 LTS chạy **trên Windows host**, không chạy LAN Agent bên trong container vì container thường không nhìn thấy bảng ARP của host.

Không cần cài Coolify, VPS, npm hoặc Node.js trên Windows nếu chỉ dùng dashboard / web audit trong Docker Desktop.

## 2. Lấy mã nguồn lần đầu

Mở PowerShell hoặc Command Prompt:

```powershell
git clone https://github.com/mepwegroup-code/Sentinel.git
cd Sentinel
```

Nếu đã có repository, chạy `git pull --ff-only` trên nhánh `main` trước khi dùng.

## 3. Start / Stop một lần bấm

1. Khởi động Docker Desktop và đợi Docker Engine sẵn sàng.
2. Nhấp đúp **`START_SENTINEL.cmd`** ở thư mục Sentinel.
3. Ở lần chạy đầu, script tạo file `.env` với mật khẩu quản trị và token ngẫu nhiên. Lưu lại mật khẩu hiển thị; bạn cũng có thể xem trong file `.env` trên máy riêng của mình. **Không gửi file này cho ai hoặc commit lên GitHub.**
4. Docker sẽ build image ở lần đầu và khởi động `sentinel-os`; script tự mở [http://127.0.0.1:3000](http://127.0.0.1:3000).
5. Đăng nhập: **username `admin`**, password `SENTINEL_ADMIN_PASSWORD` trong `.env`.
6. Sau khi sử dụng, nhấp đúp **`STOP_SENTINEL.cmd`**. Cấu hình và dữ liệu lưu trong volume `sentinel_data` vẫn được giữ lại.
7. Muốn cập nhật từ GitHub, nhấp đúp **`UPDATE_SENTINEL.cmd`**. Lệnh cập nhật `main` rồi build lại container; không xóa volume hay `.env`.

Docker Desktop → Containers sẽ hiển thị Compose project **`sentinel-os`** và service **`sentinel`** để bạn Start/Stop từ giao diện nếu muốn.

### Chạy bằng lệnh thay vì nhấp đúp

```powershell
docker compose up -d --build     # Tạo và chạy, cần file .env (tạo bởi START_SENTINEL.cmd)
docker compose ps
docker compose logs -f sentinel
docker compose stop
docker compose up -d             # Chạy lại container, không build nếu image không đổi
```

Cổng được bind vào **`127.0.0.1:3000`**, không mở trực tiếp trên IP LAN hoặc Internet.

## 4. Quét LAN thực tế trên máy Windows

1. Cài Node.js 22 LTS và mở Sentinel bằng `START_SENTINEL.cmd`.
2. Nhấp đúp **`SCAN_LAN.cmd`**.
3. Script liệt kê các card IPv4 private (Wi-Fi, Ethernet,...). Nhập tên card chính xác nếu được hỏi. Khi có nhiều card vật lý, bắt buộc chỉ rõ card để tránh quét nhầm.
4. Xác nhận **`YES`** chỉ khi bạn sở hữu mạng hoặc đã được cấp quyền kiểm tra. Agent hiện giới hạn dải IPv4 **/24** và kiểm tra các cổng TCP đã chọn với cường độ nhẹ.
5. Agent gửi báo cáo về `http://127.0.0.1:3000/api/lan-agent-report`, có token riêng lấy từ `.env`. Mở tab LAN của Sentinel để xem dữ liệu mới.

**Chú ý:** LAN Agent chỉ đọc bảng ARP và một số phép thử TCP trên subnet đã chọn. Nó không thể khẳng định đã phát hiện toàn bộ thiết bị, không xác minh tất cả thiết bị còn online, và không phải hệ thống Nmap toàn diện.

## 5. Lưu dữ liệu, backup và khắc phục lỗi

- `.env` được lưu trên Windows, không nằm trong image, bị Git ignore.
- Báo cáo LAN mới nhất nằm trong Docker named volume `sentinel_data`. Không dùng `docker compose down -v` nếu muốn giữ dữ liệu.
- AI yêu cầu cấu hình `GEMINI_API_KEY` trong `.env` và khởi động lại container.
- Nếu `START_SENTINEL.cmd` báo Docker Engine not running, mở Docker Desktop rồi thử lại.
- Nếu báo lỗi cổng 3000, kiểm tra chương trình khác chiếm `127.0.0.1:3000`.
- Xem log: `docker compose logs --tail=100 sentinel`.
- Nếu Docker Desktop hiển thị image/container là **Linux/amd64**, đó là kiến trúc phù hợp Windows x64 thông thường; không cần chọn Windows container.
- Nếu cần thay mật khẩu, sửa `.env`, rồi chạy `docker compose up -d --force-recreate`. Tất cả phiên đăng nhập trước đó sẽ bị vô hiệu nếu thay `SENTINEL_SESSION_SECRET`.

**Bảo mật:** Các API pentest chỉ sử dụng trên domain/IP của bạn hoặc có văn bản ủy quyền, không kiểm thử gây nghẽn hoặc vượt phạm vi. Sentinel chưa phải sản phẩm pentest công khai hoàn chỉnh; giữ `localhost` và đừng cấu hình port forwarding/VPN chia sẻ dashboard trước khi hoàn thiện kiểm soát SSRF, DNS rebinding, chuyển hướng và quyền mục tiêu.

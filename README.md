# Sentinel OS

Ứng dụng giám sát, đánh giá bảo mật website và hỗ trợ kiểm tra các thiết bị trong mạng nội bộ **do bạn sở hữu hoặc được phép kiểm thử**.

## Chạy trên máy Windows bằng Docker Desktop

**Không cần Coolify hoặc VPS.**

1. Cài [Docker Desktop](https://www.docker.com/products/docker-desktop/), bật Linux containers/WSL2.
2. Lấy repository bằng `git clone https://github.com/mepwegroup-code/Sentinel.git` hoặc tải ZIP và giải nén.
3. Mở Docker Desktop, nhấp đúp **`START_SENTINEL.cmd`** trong thư mục dự án.
4. Lần đầu chạy, file `.env` được tạo với mật khẩu và token ngẫu nhiên. Lưu mật khẩu hiển thị.
5. Trình duyệt sẽ mở **http://127.0.0.1:3000**. Đăng nhập `admin`.
6. Khi kết thúc, nhấp đúp **`STOP_SENTINEL.cmd`**. Lần sau chỉ việc Start.

| File | Chức năng |
|---|---|
| `START_SENTINEL.cmd` | Khởi động Docker container và mở web |
| `STOP_SENTINEL.cmd` | Tắt container, không xóa dữ liệu |
| `SCAN_LAN.cmd` | Quét LAN được cấp quyền (yêu cầu Node.js 22 trên Windows) |
| `UPDATE_SENTINEL.cmd` | Kéo mã nguồn từ GitHub, rebuild và chạy lại |
| `compose.yaml` | Docker Compose local-only, volume dữ liệu, không tự chạy 24/7 |

**Hướng dẫn chi tiết:** [DOCKER_DESKTOP.md](DOCKER_DESKTOP.md)

Coolify vẫn là lựa chọn riêng nếu triển khai máy chủ dài hạn: [COOLIFY_DEPLOY.md](COOLIFY_DEPLOY.md).

## Trạng thái bảo mật

- Website lắng nghe tại **127.0.0.1:3000** trên máy người dùng. Không mở cổng ra Internet.
- Xác thực admin và LAN Agent bằng secret riêng ở server; file `.env` không được đưa lên GitHub.
- LAN Agent dùng ARP/TCP trên NIC nội bộ được chọn, chỉ hỗ trợ IPv4 /24.
- Các tính năng cô lập thiết bị, giới hạn băng thông, Wake-on-LAN và deep scan **chưa thực thi** khi không có tích hợp hạ tầng tương ứng.
- Một phần threat-map/dashboard có dữ liệu minh họa; không coi đó là bằng chứng đo thực tế.
- Chỉ thực hiện pentest trên tài sản thuộc quyền quản lý hoặc đã có sự cho phép, kiểm soát tốc độ và tránh kiểm thử gây gián đoạn. Hệ thống chưa đạt mức hardened để công khai dưới dạng dịch vụ quét cho mọi người.

## Developer

```bash
npm install
npm run check
npm run build
docker compose up -d --build
```

GitHub Actions kiểm tra TypeScript, image Docker, API health, xác thực và Docker Compose.

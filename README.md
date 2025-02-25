# CipherNest - Audio Steganography với Django

**CipherNest** là một ứng dụng web được phát triển bằng Django, cho phép người dùng ẩn thông tin bí mật trong các file âm thanh (Audio Steganography) và trích xuất thông tin từ các file âm thanh đã được mã hóa. Ứng dụng này cung cấp giao diện trực quan để người dùng dễ dàng thực hiện các thao tác mã hóa và giải mã.

## Tính năng chính

- **Mã hóa thông tin vào file âm thanh**: Người dùng có thể tải lên một file âm thanh và nhập thông tin bí mật để ẩn vào file đó.
- **Giải mã thông tin từ file âm thanh**: Người dùng có thể tải lên file âm thanh đã được mã hóa để trích xuất thông tin bí mật.
- **Hỗ trợ nhiều định dạng âm thanh**: Ứng dụng hỗ trợ các định dạng âm thanh phổ biến như WAV, MP3, v.v.
- **Bảo mật**: Sử dụng các thuật toán mã hóa để đảm bảo thông tin được ẩn một cách an toàn.
- **Giao diện trực quan**: Dễ dàng sử dụng với giao diện web thân thiện.

## Công nghệ sử dụng

- **Backend**: Django, Django REST Framework (DRF)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap (hoặc bất kỳ framework frontend nào bạn sử dụng)
- **Database**: SQLite (hoặc PostgreSQL/MySQL tùy cấu hình)
- **Audio Processing**: Thư viện xử lý âm thanh như `pydub`, `wave`, hoặc `librosa`
- **Deployment**: Docker, Nginx, Gunicorn (tùy chọn)

## Cài đặt và chạy dự án

### Yêu cầu hệ thống

- Python 3.8 trở lên
- pip (Python package manager)

### Các bước cài đặt

1. **Clone dự án**:
   ```bash
   git clone https://github.com/tranlequocthong313/CipherNest.git
   cd CipherNest
   ```

2. **Tạo và kích hoạt môi trường ảo (virtual environment)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Trên Windows: venv\Scripts\activate
   ```

3. **Cài đặt các dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Chạy migrations**:
   ```bash
   python manage.py migrate
   ```

5. **Tạo superuser (quản trị viên)**:
   ```bash
   python manage.py createsuperuser
   ```

6. **Chạy server**:
   ```bash
   python manage.py runserver
   ```

7. **Truy cập ứng dụng**:
   - Mở trình duyệt và truy cập vào địa chỉ: `http://localhost:8000`

### Cấu hình môi trường

Tạo file `.env` trong thư mục gốc của dự án và thêm các biến môi trường cần thiết:

```env
SECRET_KEY=your-secret-key
DEBUG=True
```

## Cấu trúc thư mục

```
CipherNest/
├── ciphernest/               # Thư mục chính của project Django
│   ├── settings/            # Cấu hình settings (base.py, dev.py, prod.py)
│   ├── urls.py              # Cấu hình URLs chính
│   ├── wsgi.py              # WSGI config
│   └── asgi.py              # ASGI config
├── apps/                    # Các ứng dụng Django
│   ├── steganography/       # Ứng dụng xử lý steganography
│   │   ├── models.py        # Các model Django
│   │   ├── views.py         # Các view xử lý logic
│   │   ├── utils.py         # Các hàm tiện ích (mã hóa, giải mã)
│   │   └── templates/       # Các file template HTML
├── manage.py                # Script quản lý Django
├── requirements.txt         # Danh sách các dependencies
├── .env                     # File cấu hình môi trường
└── README.md                # Tài liệu hướng dẫn
```

## API Endpoints

Dưới đây là một số API endpoints chính (nếu có sử dụng Django REST Framework):

- **Steganography**:
  - `POST /api/encode/` - Mã hóa thông tin vào file âm thanh.
  - `POST /api/decode/` - Giải mã thông tin từ file âm thanh.

## Đóng góp

Nếu bạn muốn đóng góp vào dự án, vui lòng làm theo các bước sau:

1. Fork dự án
2. Tạo branch mới (`git checkout -b feature/YourFeatureName`)
3. Commit các thay đổi (`git commit -m 'Add some feature'`)
4. Push lên branch (`git push origin feature/YourFeatureName`)
5. Mở một Pull Request

## Liên hệ

Nếu bạn có bất kỳ câu hỏi hoặc góp ý nào, vui lòng liên hệ:

- **Tên**: Trần Lê Quốc Thông
- **Email**: tranlequocthong313@gmail.com
- **GitHub**: [tranlequocthong313](https://github.com/tranlequocthong313)

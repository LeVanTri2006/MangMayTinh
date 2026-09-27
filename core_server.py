# =============================================================================
# TÊN DỰ ÁN : HỆ THỐNG PHÁT HIỆN XÂM NHẬP DỰA TRÊN TRÍ TUỆ NHÂN TẠO (AI-IDS)
# TÊN FILE  : core_server.py
# MÔ TẢ     : Bắt gói tin mạng theo thời gian thực bằng Scapy, phân tích bằng
#              mô hình AI (Random Forest), và cung cấp API Flask trả về cảnh báo.
# CÔNG NGHỆ : Python 3.x, scapy, joblib, pandas, flask, flask-cors, threading
# CHẠY FILE : python core_server.py  (Cần quyền Administrator trên Windows)
# =============================================================================

# --- NHẬP CÁC THƯ VIỆN CẦN THIẾT ---
import joblib                             # Nạp mô hình AI từ file .pkl
import pandas as pd                       # Định dạng dữ liệu đầu vào cho mô hình
import threading                          # Chạy Sniffer và Flask song song (đa luồng)
import sys                                # Thoát chương trình khi có lỗi nghiêm trọng
from datetime import datetime             # Lấy thời gian thực khi phát hiện tấn công

from flask import Flask, jsonify          # Framework tạo Web API
from flask_cors import CORS               # Cho phép trình duyệt gọi API (tránh lỗi CORS)

from scapy.all import sniff               # Hàm bắt gói tin mạng theo thời gian thực
from scapy.layers.inet import IP, TCP    # Lớp giao thức IP và TCP trong Scapy


# =============================================================================
# BƯỚC 1: KHỞI TẠO VÀ NẠP "BỘ NÃO AI"
# =============================================================================

# Tên file mô hình AI (phải chạy train_model.py trước để tạo file này)
TEN_FILE_MO_HINH = "ai_model.pkl"

# Danh sách toàn cục lưu trữ các cảnh báo tấn công do AI phát hiện
DANH_SACH_CANH_BAO = []

# Khóa luồng để tránh xung đột khi nhiều luồng cùng ghi vào danh sách
KHOA_LUONG = threading.Lock()

print("=" * 60)
print("  HỆ THỐNG PHÁT HIỆN XÂM NHẬP DỰA TRÊN AI (AI-IDS)")
print("  Module: Server Lõi (core_server.py)")
print("=" * 60)

# Nạp mô hình AI từ file .pkl
try:
    print(f"\n[->] Đang nạp bộ não AI từ file '{TEN_FILE_MO_HINH}'...")
    mo_hinh_ai = joblib.load(TEN_FILE_MO_HINH)
    print(f"[OK] Nạp mô hình thành công! Sẵn sàng phân tích gói tin.\n")
except FileNotFoundError:
    print(f"\n[!!!] LỖI NGHIÊM TRỌNG: Không tìm thấy file '{TEN_FILE_MO_HINH}'!")
    print(f"      Vui lòng chạy 'python train_model.py' trước để tạo file mô hình.")
    print(f"      Chương trình sẽ thoát.\n")
    sys.exit(1)
except Exception as loi:
    print(f"\n[!!!] LỖI khi nạp mô hình: {loi}")
    sys.exit(1)


# =============================================================================
# BƯỚC 2: HÀM BÓC TÁCH VÀ PHÂN TÍCH GÓI TIN (PACKET ANALYZER)
# =============================================================================

# Mã màu ANSI để in cảnh báo màu đỏ trên console
MAU_DO    = "\033[91m"
MAU_VANG  = "\033[93m"
MAU_XANH  = "\033[92m"
RESET_MAU = "\033[0m"

def phan_tich_goi_tin(goi_tin):
    """
    Hàm phân tích từng gói tin mạng được Scapy bắt được.

    Chỉ xử lý các gói tin có lớp IP và TCP.
    Trích xuất 5 đặc trưng, đưa vào mô hình AI để dự đoán.
    Nếu phát hiện tấn công → lưu vào DANH_SACH_CANH_BAO và in cảnh báo.

    Tham số:
        goi_tin: Gói tin mạng do Scapy bắt được
    """
    # Bỏ qua các gói tin không phải IP + TCP
    if not (goi_tin.haslayer(IP) and goi_tin.haslayer(TCP)):
        return

    try:
        # --- TRÍCH XUẤT 5 ĐẶC TRƯNG ĐẦU VÀO CHO MÔ HÌNH AI ---

        # 1. Độ dài toàn bộ gói tin (tính bằng bytes)
        do_dai_goi_tin = len(goi_tin)

        # 2. Cổng nguồn TCP
        cong_nguon = goi_tin[TCP].sport

        # 3. Cổng đích TCP
        cong_dich = goi_tin[TCP].dport

        # 4. Cờ SYN: bằng 1 nếu gói tin có cờ 'S', ngược lại = 0
        co_syn = 1 if 'S' in str(goi_tin[TCP].flags) else 0

        # 5. Cờ ACK: bằng 1 nếu gói tin có cờ 'A', ngược lại = 0
        co_ack = 1 if 'A' in str(goi_tin[TCP].flags) else 0

        # --- [BỘ LỌC CHỐNG NHIỄU (WHITELIST)] ---
        # Bỏ qua các gói tin xác nhận TCP rỗng (54 bytes) hoặc lưu lượng web HTTPS (cổng 443)
        # Đây là luồng truy cập bình thường nhưng AI hay bị nhầm lẫn (False Positive)
        if do_dai_goi_tin == 54 or cong_dich == 443:
            return

        # --- ĐỊNH DẠNG DỮ LIỆU ĐẦU VÀO CHO MÔ HÌNH AI ---
        # Tạo DataFrame với đúng tên cột như lúc huấn luyện
        du_lieu_dau_vao = pd.DataFrame([[
            do_dai_goi_tin,
            cong_nguon,
            cong_dich,
            co_syn,
            co_ack
        ]], columns=[
            'packet_length',
            'src_port',
            'dst_port',
            'tcp_syn_flag',
            'tcp_ack_flag'
        ])

        # --- DỰ ĐOÁN BẰNG MÔ HÌNH AI ---
        ket_qua_du_doan = mo_hinh_ai.predict(du_lieu_dau_vao)[0]

        # --- XỬ LÝ KẾT QUẢ DỰ ĐOÁN ---
        if ket_qua_du_doan == 1:
            # Mô hình phát hiện tấn công! → Thu thập thêm thông tin

            # Địa chỉ IP nguồn và đích
            ip_nguon = goi_tin[IP].src
            ip_dich  = goi_tin[IP].dst

            # Thời gian phát hiện (định dạng dễ đọc)
            thoi_gian = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Đóng gói thông tin cảnh báo thành Dictionary
            canh_bao = {
                "thoi_gian"     : thoi_gian,
                "ip_nguon"      : ip_nguon,
                "ip_dich"       : ip_dich,
                "cong_nguon"    : cong_nguon,
                "cong_dich"     : cong_dich,
                "do_dai_goi_tin": do_dai_goi_tin,
                "co_syn"        : co_syn,
                "co_ack"        : co_ack,
                "phan_loai"     : "TẤN CÔNG"
            }

            # Thêm cảnh báo vào danh sách toàn cục (dùng khóa để an toàn đa luồng)
            with KHOA_LUONG:
                DANH_SACH_CANH_BAO.append(canh_bao)

            # In cảnh báo màu đỏ ra console để dễ theo dõi
            print(f"{MAU_DO}[!!!] PHÁT HIỆN TẤN CÔNG!{RESET_MAU}")
            print(f"      Thời gian : {thoi_gian}")
            print(f"      IP Nguồn  : {ip_nguon}:{cong_nguon}")
            print(f"      IP Đích   : {ip_dich}:{cong_dich}")
            print(f"      Độ dài    : {do_dai_goi_tin} bytes | SYN={co_syn} | ACK={co_ack}")
            print("-" * 55)

    except Exception as loi:
        # Bỏ qua lỗi nhỏ để không làm dừng sniffer
        pass


# =============================================================================
# BƯỚC 3: HÀM CHẠY SNIFFER ĐA LUỒNG
# =============================================================================

def khoi_dong_sniffer():
    """
    Hàm khởi động Scapy Sniffer để bắt gói tin mạng theo thời gian thực.

    - prn=phan_tich_goi_tin : Gọi hàm phân tích cho từng gói tin bắt được
    - store=False           : Không lưu gói tin vào RAM (tránh tràn bộ nhớ)
    - filter='ip'           : Chỉ bắt các gói tin IP để giảm tải xử lý
    """
    print(f"{MAU_XANH}[OK] Sniffer đã khởi động! Đang lắng nghe gói tin mạng...{RESET_MAU}")
    print(f"     (Nhấn Ctrl+C để dừng chương trình)\n")
    try:
        sniff(
            prn=phan_tich_goi_tin,   # Hàm xử lý từng gói tin
            store=False               # Không lưu vào RAM (hàm phan_tich_goi_tin tự lọc IP+TCP)
        )
    except Exception as loi:
        print(f"{MAU_VANG}[!] Sniffer dừng lại: {loi}{RESET_MAU}")


# =============================================================================
# BƯỚC 4: KHỞI TẠO WEB API BẰNG FLASK
# =============================================================================

# Khởi tạo ứng dụng Flask
ung_dung_flask = Flask(__name__)

# Cấu hình CORS: cho phép mọi domain gọi API (cần thiết cho Web Client)
CORS(ung_dung_flask)


@ung_dung_flask.route('/api/canh-bao', methods=['GET'])
def lay_danh_sach_canh_bao():
    """
    Endpoint API: GET /api/canh-bao

    Trả về toàn bộ danh sách cảnh báo tấn công dưới dạng JSON.
    Web Client có thể gọi API này để hiển thị cảnh báo theo thời gian thực.

    Trả về:
        JSON: { "tong_so_canh_bao": int, "du_lieu": [ ... ] }
    """
    with KHOA_LUONG:
        # Tạo bản sao danh sách để tránh xung đột khi đọc
        danh_sach_hien_tai = list(DANH_SACH_CANH_BAO)

    ket_qua = {
        "tong_so_canh_bao": len(danh_sach_hien_tai),
        "du_lieu"          : danh_sach_hien_tai
    }
    return jsonify(ket_qua)


@ung_dung_flask.route('/api/trang-thai', methods=['GET'])
def kiem_tra_trang_thai():
    """
    Endpoint API: GET /api/trang-thai

    Kiểm tra trạng thái hoạt động của Core Server.
    Hữu ích để Web Client biết server có đang chạy không.
    """
    return jsonify({
        "trang_thai"       : "Đang hoạt động",
        "tong_so_canh_bao" : len(DANH_SACH_CANH_BAO),
        "thoi_gian_server" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# =============================================================================
# BƯỚC 5: THỰC THI CHƯƠNG TRÌNH CHÍNH
# =============================================================================

if __name__ == '__main__':
    print(f"\n{MAU_XANH}[->] Đang khởi động luồng Sniffer...{RESET_MAU}")

    # Tạo luồng riêng cho Sniffer (daemon=True: luồng tự tắt khi chương trình chính tắt)
    luong_sniffer = threading.Thread(target=khoi_dong_sniffer, daemon=True)
    luong_sniffer.start()

    print(f"{MAU_XANH}[->] Đang khởi động Flask API Server...{RESET_MAU}")
    print(f"     API Cảnh báo : http://localhost:5000/api/canh-bao")
    print(f"     API Trạng thái: http://localhost:5000/api/trang-thai")
    print("=" * 60)

    try:
        # Chạy Flask trên tất cả các giao diện mạng, cổng 5000
        # use_reloader=False để tránh khởi động lại Sniffer 2 lần
        ung_dung_flask.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print(f"\n{MAU_VANG}[!] Nhận lệnh dừng. Tắt chương trình...{RESET_MAU}")
    except OSError as loi:
        print(f"\n{MAU_DO}[!!!] Không thể khởi động server: {loi}{RESET_MAU}")
        print(f"      Có thể cổng 5000 đã bị chiếm. Hãy đóng ứng dụng đang dùng cổng đó.")

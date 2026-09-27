import socket
import json
import threading
import joblib
import pandas as pd
from datetime import datetime
import sys
from flask import Flask, jsonify
from flask_cors import CORS

# =====================================================================
# BƯỚC 1: KHỞI TẠO BIẾN VÀ NẠP AI
# =====================================================================
TEN_FILE_MO_HINH = "ai_model.pkl"
DANH_SACH_CANH_BAO = []
KHOA_LUONG = threading.Lock()

print("=" * 55)
print("  [MÁY 1] SERVER TRUNG TÂM PHÂN TÍCH AI (AI-SERVER)")
print("=" * 55)

try:
    mo_hinh_ai = joblib.load(TEN_FILE_MO_HINH)
    print(f"[+] Nạp thành công bộ não AI từ '{TEN_FILE_MO_HINH}'.")
except Exception as e:
    print(f"[-] Lỗi nạp mô hình: {e}")
    sys.exit(1)

# =====================================================================
# BƯỚC 2: HÀM HỖ TRỢ ĐỌC TCP STREAM (CHỐNG DÍNH GÓI TIN)
# =====================================================================
def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

# =====================================================================
# BƯỚC 3: XỬ LÝ DỮ LIỆU TỪ CLIENT (SENSOR) GỬI VỀ
# =====================================================================
def handle_client(client_conn, addr):
    print(f"[+] Sensor Client {addr} đã kết nối vào hệ thống.")
    try:
        while True:
            # 1. Đọc Header 4 bytes để lấy kích thước
            raw_msglen = recvall(client_conn, 4)
            if not raw_msglen:
                break
            msglen = int.from_bytes(raw_msglen, byteorder='big')
            
            # 2. Đọc chuỗi JSON payload
            raw_data = recvall(client_conn, msglen)
            if not raw_data:
                break
                
            # Giải mã JSON
            du_lieu_mang = json.loads(raw_data.decode('utf-8'))
            
            # 3. Định dạng dữ liệu cho AI
            du_lieu_dau_vao = pd.DataFrame([[
                du_lieu_mang['do_dai_goi_tin'],
                du_lieu_mang['cong_nguon'],
                du_lieu_mang['cong_dich'],
                du_lieu_mang['co_syn'],
                du_lieu_mang['co_ack']
            ]], columns=['packet_length', 'src_port', 'dst_port', 'tcp_syn_flag', 'tcp_ack_flag'])
            
            # 4. Dự đoán
            ket_qua = mo_hinh_ai.predict(du_lieu_dau_vao)[0]
            
            # 5. Nếu là Tấn công (1) -> Cảnh báo
            if ket_qua == 1:
                canh_bao = {
                    "thoi_gian": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip_nguon": du_lieu_mang['ip_nguon'],
                    "ip_dich": du_lieu_mang['ip_dich'],
                    "cong_nguon": du_lieu_mang['cong_nguon'],
                    "cong_dich": du_lieu_mang['cong_dich'],
                    "do_dai_goi_tin": du_lieu_mang['do_dai_goi_tin'],
                    "phan_loai": "TẤN CÔNG"
                }
                with KHOA_LUONG:
                    DANH_SACH_CANH_BAO.append(canh_bao)
                
                print(f"🚨 PHÁT HIỆN TẤN CÔNG từ {du_lieu_mang['ip_nguon']} (Sensor: {addr[0]})")
                
    except Exception as e:
        print(f"[-] Lỗi kết nối Sensor {addr}: {e}")
    finally:
        client_conn.close()
        print(f"[-] Sensor {addr} đã ngắt kết nối.")

# =====================================================================
# BƯỚC 4: CHẠY TCP SERVER ĐỂ ĐÓN CLIENT
# =====================================================================
def start_tcp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    print(f"[+] TCP Server đang chạy trên Port 9999. Sẵn sàng chờ các Sensor...")
    
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# =====================================================================
# BƯỚC 5: CHẠY FLASK API (Cho Dashboard)
# =====================================================================
app = Flask(__name__)
CORS(app)

@app.route('/api/canh-bao', methods=['GET'])
def lay_canh_bao():
    with KHOA_LUONG:
        danh_sach = list(DANH_SACH_CANH_BAO)
    return jsonify({"tong_so_canh_bao": len(danh_sach), "du_lieu": danh_sach})

if __name__ == '__main__':
    # Chạy TCP Server ở luồng ẩn
    threading.Thread(target=start_tcp_server, daemon=True).start()
    # Chạy Flask API ở luồng chính
    print("[+] Khởi động API Server cho Giao diện trên Port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

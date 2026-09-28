import socket
import json
import sys
from scapy.all import sniff
from scapy.layers.inet import IP, TCP

print("=" * 55)
print("  [MÁY 2] CLIENT CẢM BIẾN MẠNG (AGENT SENSOR)")
print("=" * 55)

# CẤU HÌNH ĐỊA CHỈ MÁY CHỦ
# Khi nào báo cáo trên 2 máy thật, bạn chỉ cần sửa '127.0.0.1' thành IP của Máy 1 (VD: '192.168.1.15')
SERVER_IP = '127.0.0.1'
SERVER_PORT = 9999

# Mở kết nối TCP
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print(f"[+] Đã kết nối thành công đến AI Server tại {SERVER_IP}:{SERVER_PORT}")
except Exception as e:
    print(f"[-] LỖI: Không thể kết nối đến Server. Hãy chắc chắn Máy 1 đã chạy ai_server.py!")
    sys.exit(1)

def phan_tich_goi_tin(goi_tin):
    """Hàm móc vào Scapy, bóc tách đặc trưng và gửi về Server"""
    if not (goi_tin.haslayer(IP) and goi_tin.haslayer(TCP)):
        return

    try:
        # 1. Trích xuất 5 đặc trưng
        do_dai_goi_tin = len(goi_tin)
        cong_nguon = goi_tin[TCP].sport
        cong_dich = goi_tin[TCP].dport
        co_syn = 1 if 'S' in str(goi_tin[TCP].flags) else 0
        co_ack = 1 if 'A' in str(goi_tin[TCP].flags) else 0

        # [BỘ LỌC CHỐNG NHIỄU NGAY TẠI CLIENT] 
        # Giúp tiết kiệm băng thông mạng, không gửi rác về Server
        if (do_dai_goi_tin <= 54 and co_syn == 0) or cong_dich == 443:
            return

        # 2. Đóng gói dữ liệu kèm theo IP để Server biết ai đang bị tấn công
        du_lieu_mang = {
            "ip_nguon": goi_tin[IP].src,
            "ip_dich": goi_tin[IP].dst,
            "cong_nguon": cong_nguon,
            "cong_dich": cong_dich,
            "do_dai_goi_tin": do_dai_goi_tin,
            "co_syn": co_syn,
            "co_ack": co_ack
        }
        
        # 3. Áp dụng TCP Message Framing và Gửi qua Socket
        json_str = json.dumps(du_lieu_mang)
        data_bytes = json_str.encode('utf-8')
        
        msg_length = len(data_bytes)
        header = msg_length.to_bytes(4, byteorder='big')
        
        client_socket.sendall(header + data_bytes)
        
    except Exception as e:
        pass # Bỏ qua lỗi vặt để sniffer không dừng

# Bắt đầu nghe lén card mạng
print(f"[*] Đang thu thập dữ liệu mạng nội bộ và truyền về Máy chủ...")
sniff(prn=phan_tich_goi_tin, store=False)

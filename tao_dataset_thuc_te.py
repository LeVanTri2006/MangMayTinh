# =============================================================================
# TÊN FILE  : tao_dataset_thuc_te.py
# MÔ TẢ     : Tạo dataset mô phỏng lưu lượng mạng thực tế (5000 mẫu).
#
# NGUYÊN TẮC THIẾT KẾ (đúng kỹ thuật mạng):
#   BÌNH THƯỜNG (label=0):
#     - Gói SYN hợp lệ : packet_length=60-74,  SYN=1, ACK=0, dst_port đa dạng
#     - Gói SYN-ACK    : packet_length=60-74,  SYN=1, ACK=1, (server trả lời)
#     - Gói dữ liệu    : packet_length=100-1500, SYN=0, ACK=1, dst_port đa dạng
#     - Gói ACK nhỏ    : packet_length=54-60,  SYN=0, ACK=1  (ACK thông thường)
#     - Gói FIN        : packet_length=54-60,  SYN=0, ACK=1  (đóng kết nối)
#
#   TẤN CÔNG SYN FLOOD (label=1):
#     - packet_length = 40-54 bytes  (cực nhỏ, chỉ có TCP header, không có data)
#     - SYN=1, ACK=0                 (chỉ bắn SYN, không bao giờ ACK lại)
#     - dst_port = 80/443/22/3389    (nhắm vào port nổi tiếng)
#     - src_port ngẫu nhiên          (giả mạo IP nguồn)
#
# LÝ DO KHÔNG DÙNG NSL-KDD TRỰC TIẾP:
#   NSL-KDD mô tả LUỒNG KẾT NỐI (connection flow), không phải gói tin đơn lẻ.
#   Ánh xạ sai → AI học nhầm → báo động giả liên tục với gói ACK bình thường.
# =============================================================================

import pandas as pd
import numpy as np
import os

# Cấu hình
TEN_FILE_OUTPUT = "dataset.csv"
SO_MAU_TONG     = 6000   # 3000 bình thường + 3000 tấn công
SEED            = 42

np.random.seed(SEED)

print("=" * 60)
print("  TẠO DATASET THỰC TẾ CHO AI-IDS")
print("  (Mô phỏng đúng đặc trưng gói tin TCP/IP)")
print("=" * 60)

# =============================================================================
# PHẦN 1: TẠO LƯU LƯỢNG BÌNH THƯỜNG (label = 0)
# =============================================================================
print("\n[->] Đang tạo lưu lượng BÌNH THƯỜNG...")

n_bt = SO_MAU_TONG // 2  # 3000 mẫu bình thường

# Các cổng đích hợp lệ khi người dùng duyệt web, SSH, DNS...
CONG_BINH_THUONG = [80, 443, 22, 53, 25, 110, 143, 8080, 3389, 21, 8443, 993]

# --- Loại 1: Gói SYN hợp lệ (bắt đầu kết nối TCP) ~15% ---
n_syn = int(n_bt * 0.15)
df_syn_hop_le = pd.DataFrame({
    "packet_length": np.random.randint(60, 75, size=n_syn),          # SYN: 60-74 bytes
    "src_port"     : np.random.randint(1024, 65535, size=n_syn),
    "dst_port"     : np.random.choice(CONG_BINH_THUONG, size=n_syn),
    "tcp_syn_flag" : np.ones(n_syn,  dtype=int),   # SYN = 1
    "tcp_ack_flag" : np.zeros(n_syn, dtype=int),   # ACK = 0
    "label"        : np.zeros(n_syn, dtype=int)
})

# --- Loại 2: Gói SYN-ACK (server trả lời bắt tay) ~10% ---
n_synack = int(n_bt * 0.10)
df_synack = pd.DataFrame({
    "packet_length": np.random.randint(60, 75, size=n_synack),
    "src_port"     : np.random.choice(CONG_BINH_THUONG, size=n_synack),  # Từ server
    "dst_port"     : np.random.randint(1024, 65535, size=n_synack),       # Về client
    "tcp_syn_flag" : np.ones(n_synack,  dtype=int),   # SYN = 1
    "tcp_ack_flag" : np.ones(n_synack,  dtype=int),   # ACK = 1
    "label"        : np.zeros(n_synack, dtype=int)
})

# --- Loại 3: Gói dữ liệu lớn (HTTP content, file transfer...) ~40% ---
n_data = int(n_bt * 0.40)
df_data = pd.DataFrame({
    "packet_length": np.random.randint(200, 1461, size=n_data),       # Có payload lớn
    "src_port"     : np.random.randint(1024, 65535, size=n_data),
    "dst_port"     : np.random.choice(CONG_BINH_THUONG, size=n_data),
    "tcp_syn_flag" : np.zeros(n_data, dtype=int),   # SYN = 0
    "tcp_ack_flag" : np.ones(n_data,  dtype=int),   # ACK = 1
    "label"        : np.zeros(n_data, dtype=int)
})

# --- Loại 4: Gói ACK nhỏ (acknowledgment, keepalive, FIN...) ~35% ---
n_ack = n_bt - n_syn - n_synack - n_data
df_ack = pd.DataFrame({
    "packet_length": np.random.randint(54, 100, size=n_ack),          # Không có payload
    "src_port"     : np.random.randint(1024, 65535, size=n_ack),
    "dst_port"     : np.random.choice(CONG_BINH_THUONG, size=n_ack),
    "tcp_syn_flag" : np.zeros(n_ack, dtype=int),   # SYN = 0
    "tcp_ack_flag" : np.ones(n_ack,  dtype=int),   # ACK = 1
    "label"        : np.zeros(n_ack, dtype=int)
})

df_binh_thuong = pd.concat([df_syn_hop_le, df_synack, df_data, df_ack], ignore_index=True)
print(f"     [OK] {len(df_binh_thuong):,} mẫu bình thường (SYN hợp lệ, SYN-ACK, Data, ACK)")


# =============================================================================
# PHẦN 2: TẠO LƯU LƯỢNG TẤN CÔNG SYN FLOOD (label = 1)
# =============================================================================
print("[->] Đang tạo lưu lượng TẤN CÔNG SYN FLOOD...")

n_tc = SO_MAU_TONG - n_bt  # 3000 mẫu tấn công

# Đặc điểm SYN Flood:
# - Gói cực nhỏ (chỉ IP+TCP header, không data): 40-54 bytes
# - Luôn SYN=1, ACK=0 (không hoàn thành bắt tay 3 bước)
# - Nhắm vào port phổ biến
# - Tốc độ cao, src_port thay đổi liên tục (giả mạo)
CONG_TAN_CONG = [80, 443, 22, 3389]

df_tan_cong = pd.DataFrame({
    "packet_length": np.random.randint(40, 65, size=n_tc),            # Bao gồm cả padding Ethernet (60-64 bytes)
    "src_port"     : np.random.randint(1024, 65535, size=n_tc),       # Port giả mạo ngẫu nhiên
    "dst_port"     : np.random.choice(CONG_TAN_CONG, size=n_tc,
                                      p=[0.45, 0.35, 0.12, 0.08]),    # Chủ yếu nhắm HTTP/HTTPS
    "tcp_syn_flag" : np.ones(n_tc,  dtype=int),   # SYN = 1 liên tục ← Đặc trưng SYN Flood
    "tcp_ack_flag" : np.zeros(n_tc, dtype=int),   # ACK = 0 ← Không bao giờ hoàn thành bắt tay
    "label"        : np.ones(n_tc, dtype=int)
})

print(f"     [OK] {len(df_tan_cong):,} mẫu SYN Flood (packet_length=40-54, SYN=1, ACK=0)")


# =============================================================================
# PHẦN 3: GHÉP, TRỘN VÀ LƯU FILE
# =============================================================================
df_cuoi = pd.concat([df_binh_thuong, df_tan_cong], ignore_index=True)
df_cuoi = df_cuoi.sample(frac=1, random_state=SEED).reset_index(drop=True)

# Đảm bảo kiểu dữ liệu đúng
df_cuoi = df_cuoi.astype({
    "packet_length": int,
    "src_port"     : int,
    "dst_port"     : int,
    "tcp_syn_flag" : int,
    "tcp_ack_flag" : int,
    "label"        : int
})

df_cuoi.to_csv(TEN_FILE_OUTPUT, index=False)

print(f"\n{'=' * 60}")
print(f"  KẾT QUẢ")
print(f"{'=' * 60}")
print(f"  File: {TEN_FILE_OUTPUT}")
print(f"  Tổng mẫu    : {len(df_cuoi):,}")
print(f"  Bình thường : {(df_cuoi['label']==0).sum():,}  (SYN/SYN-ACK/Data/ACK hợp lệ)")
print(f"  Tấn công    : {(df_cuoi['label']==1).sum():,}  (SYN Flood: 40-54 bytes, SYN=1, ACK=0)")
print(f"\n  Đặc điểm phân biệt rõ ràng:")
print(f"  - Bình thường: packet_length đa dạng (54-1500), mix SYN/ACK")
print(f"  - Tấn công   : packet_length NHỎ (40-54), SYN=1 + ACK=0 LIÊN TỤC")
print(f"\n[->] Chạy 'python train_model.py' để huấn luyện lại mô hình!")
print(f"{'=' * 60}\n")

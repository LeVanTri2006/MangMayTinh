import tkinter as tk
from tkinter import scrolledtext, ttk
import socket
import json
import threading
import sys
from scapy.all import sniff
from scapy.layers.inet import IP, TCP

class DesktopClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Trạm Cảm Biến Mạng (Agent Sensor)")
        self.root.geometry("650x450")
        self.root.configure(bg="#0d1b2a") # Màu xanh dương đậm (Dark Blue)

        # Biến hệ thống
        self.client_socket = None
        self.is_sniffing = False
        self.goi_tin_da_gui = 0

        # --- GIAO DIỆN ---
        lbl_title = tk.Label(root, text="📡 TRẠM CẢM BIẾN MẠNG (AGENT SENSOR)", font=("Helvetica", 14, "bold"), bg="#0d1b2a", fg="#00b4d8")
        lbl_title.pack(pady=10)

        # Khung Cấu hình Kết nối
        frame_config = tk.Frame(root, bg="#0d1b2a")
        frame_config.pack(pady=10)

        tk.Label(frame_config, text="IP Máy chủ (Server):", bg="#0d1b2a", fg="white", font=("Helvetica", 10)).grid(row=0, column=0, padx=5)
        self.entry_ip = tk.Entry(frame_config, width=15, font=("Helvetica", 10))
        self.entry_ip.insert(0, "127.0.0.1") # Mặc định là localhost
        self.entry_ip.grid(row=0, column=1, padx=5)

        tk.Label(frame_config, text="Port:", bg="#0d1b2a", fg="white", font=("Helvetica", 10)).grid(row=0, column=2, padx=5)
        self.entry_port = tk.Entry(frame_config, width=6, font=("Helvetica", 10))
        self.entry_port.insert(0, "9999")
        self.entry_port.grid(row=0, column=3, padx=5)

        # Nút điều khiển
        frame_btns = tk.Frame(root, bg="#0d1b2a")
        frame_btns.pack(pady=5)

        self.btn_start = tk.Button(frame_btns, text="▶ Bắt đầu Lắng nghe & Kết nối", bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold"), command=self.start_agent)
        self.btn_start.grid(row=0, column=0, padx=10)

        self.btn_stop = tk.Button(frame_btns, text="⏹ Dừng lại", bg="#f44336", fg="white", font=("Helvetica", 10, "bold"), state=tk.DISABLED, command=self.stop_agent)
        self.btn_stop.grid(row=0, column=1, padx=10)

        # Thống kê
        self.lbl_stats = tk.Label(root, text="Số gói tin đã bóc tách & gửi về Server: 0", bg="#0d1b2a", fg="yellow", font=("Helvetica", 10, "italic"))
        self.lbl_stats.pack(pady=5)

        # Khung Log
        self.txt_log = scrolledtext.ScrolledText(root, bg="#000000", fg="#00FFFF", font=("Consolas", 10), state=tk.DISABLED)
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, message):
        """Hàm in chữ ra màn hình log"""
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.insert(tk.END, message + "\n")
        self.txt_log.see(tk.END)
        self.txt_log.config(state=tk.DISABLED)

    def start_agent(self):
        server_ip = self.entry_ip.get()
        server_port = int(self.entry_port.get())

        # 1. Kết nối đến TCP Server
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, server_port))
            self.log(f"[+] KẾT NỐI THÀNH CÔNG TỚI SERVER {server_ip}:{server_port}")
        except Exception as e:
            self.log(f"[-] LỖI KẾT NỐI: Không tìm thấy Server ở IP {server_ip}. Hãy chắc chắn Server đã bật!")
            return

        # 2. Thay đổi trạng thái giao diện
        self.is_sniffing = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.entry_ip.config(state=tk.DISABLED)
        self.entry_port.config(state=tk.DISABLED)

        # 3. Khởi động Scapy bắt gói tin trên một luồng (Thread) riêng biệt
        threading.Thread(target=self.run_sniffer, daemon=True).start()

    def run_sniffer(self):
        self.log("[*] Đang móc vào Card mạng... Bắt đầu bóc tách dữ liệu!")
        # stop_filter sẽ tự động dừng Scapy khi self.is_sniffing = False
        sniff(prn=self.phan_tich_goi_tin, store=False, stop_filter=lambda x: not self.is_sniffing)
        self.log("[-] Đã dừng thu thập dữ liệu mạng.")

    def phan_tich_goi_tin(self, goi_tin):
        if not self.is_sniffing:
            return

        # Chỉ bóc tách các gói TCP
        if not (goi_tin.haslayer(IP) and goi_tin.haslayer(TCP)):
            return

        try:
            do_dai_goi_tin = len(goi_tin)
            cong_nguon = goi_tin[TCP].sport
            cong_dich = goi_tin[TCP].dport
            co_syn = 1 if 'S' in str(goi_tin[TCP].flags) else 0
            co_ack = 1 if 'A' in str(goi_tin[TCP].flags) else 0

            # DEBUG LOG: Báo cáo khi thấy gói SYN xuất hiện
            if co_syn == 1:
                print(f"[DEBUG - CLIENT] Bắt được gói SYN | Nguồn: {goi_tin[IP].src}:{cong_nguon} | Đích: {goi_tin[IP].dst}:{cong_dich} | Size: {do_dai_goi_tin} bytes")

            # BỘ LỌC CHỐNG NHIỄU (Tiết kiệm băng thông & Chống lặp vô hạn)
            # 1. Bỏ qua các gói tin của cổng 9999 (Đây là cổng 2 phần mềm đang dùng để chat với nhau)
            if cong_nguon == 9999 or cong_dich == 9999:
                return
                
            # 2. Chặn gói <= 54 byte NẾU KHÔNG CÓ CỜ SYN
            if (do_dai_goi_tin <= 54 and co_syn == 0) or cong_dich == 443:
                return

            if co_syn == 1:
                print("[DEBUG - CLIENT] --> Gói SYN hợp lệ, chuẩn bị đóng gói gửi lên Server!")

            du_lieu_mang = {
                "ip_nguon": goi_tin[IP].src,
                "ip_dich": goi_tin[IP].dst,
                "cong_nguon": cong_nguon,
                "cong_dich": cong_dich,
                "do_dai_goi_tin": do_dai_goi_tin,
                "co_syn": co_syn,
                "co_ack": co_ack
            }
            
            # Đóng gói và Gửi (TCP Framing)
            json_str = json.dumps(du_lieu_mang)
            data_bytes = json_str.encode('utf-8')
            msg_length = len(data_bytes)
            header = msg_length.to_bytes(4, byteorder='big')
            
            self.client_socket.sendall(header + data_bytes)
            
            # Cập nhật số lượng lên màn hình
            self.goi_tin_da_gui += 1
            self.lbl_stats.config(text=f"Số gói tin đã bóc tách & gửi về Server: {self.goi_tin_da_gui}")

        except Exception as e:
            pass # Lỗi vặt bỏ qua

    def stop_agent(self):
        self.is_sniffing = False
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
        
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.entry_ip.config(state=tk.NORMAL)
        self.entry_port.config(state=tk.NORMAL)
        self.log("[-] Đã ngắt kết nối khỏi Server.")

    def on_closing(self):
        self.stop_agent()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = DesktopClientApp(root)
    root.mainloop()

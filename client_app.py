import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
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
        # 1. Header
        lbl_title = tk.Label(root, text="📡 TRẠM CẢM BIẾN MẠNG (AGENT SENSOR)", font=("Helvetica", 16, "bold"), bg="#0d1b2a", fg="#00F0FF")
        lbl_title.pack(pady=(15, 5))
        
        self.lbl_status_main = tk.Label(root, text="🔴 TRẠNG THÁI: CHƯA KẾT NỐI", font=("Consolas", 12, "bold"), bg="#0d1b2a", fg="#ff4d4d")
        self.lbl_status_main.pack(pady=(0, 10))

        # Khung chứa Cấu hình & Nút bấm
        frame_top = tk.Frame(root, bg="#0d1b2a")
        frame_top.pack(fill=tk.X, padx=20)

        # 2. Cấu hình Kết nối (Bên trái)
        frame_config = tk.LabelFrame(frame_top, text="🔧 Cấu hình Kết nối", bg="#0d1b2a", fg="white", font=("Helvetica", 10, "bold"), bd=1)
        frame_config.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        tk.Label(frame_config, text="IP Máy chủ:", bg="#0d1b2a", fg="white", font=("Helvetica", 10)).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.entry_ip = tk.Entry(frame_config, width=15, font=("Consolas", 11), bg="#1b263b", fg="white", insertbackground="white", relief=tk.FLAT)
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(frame_config, text="Port:", bg="#0d1b2a", fg="white", font=("Helvetica", 10)).grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.entry_port = tk.Entry(frame_config, width=6, font=("Consolas", 11), bg="#1b263b", fg="white", insertbackground="white", relief=tk.FLAT)
        self.entry_port.insert(0, "9999")
        self.entry_port.grid(row=0, column=3, padx=10, pady=10)

        # 3. Bảng điều khiển (Bên phải)
        frame_btns = tk.LabelFrame(frame_top, text="⚡ Điều khiển", bg="#0d1b2a", fg="white", font=("Helvetica", 10, "bold"), bd=1)
        frame_btns.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.btn_start = tk.Button(frame_btns, text="▶ KHỞI ĐỘNG CẢM BIẾN", bg="#00e676", fg="black", font=("Helvetica", 10, "bold"), relief=tk.FLAT, command=self.start_agent)
        self.btn_start.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.btn_stop = tk.Button(frame_btns, text="⏹ DỪNG LẠI", bg="#ff1744", fg="white", font=("Helvetica", 10, "bold"), relief=tk.FLAT, state=tk.DISABLED, command=self.stop_agent)
        self.btn_stop.pack(fill=tk.X, padx=10, pady=(0, 10))

        # 4. Thống kê
        self.lbl_stats = tk.Label(root, text="📊 Số gói tin đã xử lý & gửi về Server: 0", bg="#0d1b2a", fg="#ffea00", font=("Consolas", 11, "bold"))
        self.lbl_stats.pack(pady=10)

        # 5. Khung Log Terminal
        frame_log = tk.LabelFrame(root, text="🖥️ Terminal Giám sát (Real-time)", bg="#0d1b2a", fg="white", font=("Helvetica", 10, "bold"), bd=1)
        frame_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        self.txt_log = scrolledtext.ScrolledText(frame_log, bg="#000000", fg="#00FF41", font=("Consolas", 10), state=tk.DISABLED, relief=tk.FLAT)
        self.txt_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log(self, message):
        """Hàm in chữ ra màn hình log"""
        self.txt_log.config(state=tk.NORMAL)
        self.txt_log.insert(tk.END, message + "\n")
        
        # CHỐNG GIẬT LAG: Chỉ giữ tối đa 500 dòng log gần nhất trên màn hình
        if int(self.txt_log.index('end-1c').split('.')[0]) > 500:
            self.txt_log.delete('1.0', '2.0')
            
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
            # Hiển thị thông báo dạng Pop-up trên giao diện
            messagebox.showerror("Lỗi Kết Nối", f"Không thể kết nối đến Server ở IP: {server_ip}\n\n1. Hãy kiểm tra lại xem đã gõ đúng IP chưa.\n2. Đảm bảo Trạm Chỉ Huy (Server) đã được bật!")
            self.log(f"[-] LỖI KẾT NỐI: Không tìm thấy Server ở IP {server_ip}.")
            return

        # 2. Thay đổi trạng thái giao diện
        self.is_sniffing = True
        self.lbl_status_main.config(text="🟢 TRẠNG THÁI: ĐANG LẮNG NGHE & KẾT NỐI", fg="#00e676")
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.entry_ip.config(state=tk.DISABLED)
        self.entry_port.config(state=tk.DISABLED)

        # 3. Khởi động Scapy bắt gói tin trên một luồng (Thread) riêng biệt
        threading.Thread(target=self.run_sniffer, daemon=True).start()

    def run_sniffer(self):
        self.log("[*] Đang móc vào Card mạng... Bắt đầu bóc tách dữ liệu!")
        # Đang test 1 máy nên dùng tạm iface="lo" (Loopback). Khi nào đem 2 máy đi báo cáo thì XÓA chữ iface="lo" đi.
        # sniff(iface="lo", prn=self.phan_tich_goi_tin, store=False, stop_filter=lambda x: not self.is_sniffing)
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

            # LOG TẤT CẢ GÓI TIN ĐI QUA CARD MẠNG
            loai_goi = "TẤN CÔNG SYN?" if co_syn == 1 else "TRAFFIC THƯỜNG"
            icon = "🚨" if co_syn == 1 else "🌐"
            msg = f"{icon} [{loai_goi}] | {goi_tin[IP].src}:{cong_nguon} --> {goi_tin[IP].dst}:{cong_dich} | {do_dai_goi_tin} bytes"
            self.root.after(0, lambda m=msg: self.log(m))

            # BỘ LỌC CHỐNG NHIỄU (Tiết kiệm băng thông & Chống lặp vô hạn)
            # 1. Bỏ qua các gói tin của cổng 9999 (Đây là cổng 2 phần mềm đang dùng để chat với nhau)
            if cong_nguon == 9999 or cong_dich == 9999:
                return
                
            # 2. Chặn gói <= 54 byte NẾU KHÔNG CÓ CỜ SYN
            if (do_dai_goi_tin <= 54 and co_syn == 0) or cong_dich == 443:
                return

            if co_syn == 1:
                self.root.after(0, lambda: self.log("    🚀 -> Đã lọt qua màng lọc, đang đóng gói gửi lên Server!"))


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
        
        self.lbl_status_main.config(text="🔴 TRẠNG THÁI: ĐÃ DỪNG", fg="#ff4d4d")
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

import tkinter as tk
from tkinter import ttk
import socket
import json
import threading
import joblib
import pandas as pd
from datetime import datetime
import sys

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-IDS Server (Trạm Chỉ Huy)")
        self.root.geometry("950x550")
        self.root.configure(bg="#121212")

        # Nạp AI
        try:
            self.mo_hinh_ai = joblib.load("ai_model.pkl")
        except Exception as e:
            tk.messagebox.showerror("Lỗi", f"Không tìm thấy ai_model.pkl: {e}")
            sys.exit(1)

        self.alerts = []
        self.connected_clients = {} # Dict lưu thông tin các Cảm biến (IP, Port, Time_in, Time_out)
        self.lock = threading.Lock()
        self.previous_count = 0

        # --- GIAO DIỆN ---
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1e1e1e", foreground="#00FF00", fieldbackground="#1e1e1e", rowheight=30, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=("Helvetica", 11, "bold"))
        style.map('Treeview', background=[('selected', '#d32f2f')])
        
        self.lbl_title = tk.Label(root, text="🛡️ TRẠM CHỈ HUY KIỂM SOÁT XÂM NHẬP (AI-SERVER)", font=("Helvetica", 16, "bold"), bg="#121212", fg="#00F0FF")
        self.lbl_title.pack(pady=10)

        self.lbl_status = tk.Label(root, text="🔌 Đang khởi động Server TCP...", font=("Helvetica", 11, "italic"), bg="#121212", fg="yellow")
        self.lbl_status.pack(pady=5)
        
        # --- KHUNG 1: DANH SÁCH CẢM BIẾN (AGENTS) ---
        frame_clients = tk.LabelFrame(root, text="📡 DANH SÁCH CẢM BIẾN (AGENTS)", bg="#121212", fg="white", font=("Helvetica", 11, "bold"))
        frame_clients.pack(fill=tk.BOTH, expand=False, padx=20, pady=5)
        
        cols_client = ("ip", "port", "time_in", "time_out", "status")
        self.tree_clients = ttk.Treeview(frame_clients, columns=cols_client, show='headings', height=4)
        
        self.tree_clients.heading("ip", text="IP Cảm biến")
        self.tree_clients.heading("port", text="Cổng")
        self.tree_clients.heading("time_in", text="Thời gian Đến (Connect)")
        self.tree_clients.heading("time_out", text="Thời gian Đi (Disconnect)")
        self.tree_clients.heading("status", text="Trạng thái")
        
        self.tree_clients.column("ip", width=150, anchor=tk.CENTER)
        self.tree_clients.column("port", width=80, anchor=tk.CENTER)
        self.tree_clients.column("time_in", width=180, anchor=tk.CENTER)
        self.tree_clients.column("time_out", width=180, anchor=tk.CENTER)
        self.tree_clients.column("status", width=120, anchor=tk.CENTER)
        self.tree_clients.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- KHUNG 2: NHẬT KÝ TẤN CÔNG ---
        frame_alerts = tk.LabelFrame(root, text="🚨 NHẬT KÝ TẤN CÔNG (THỜI GIAN THỰC)", bg="#121212", fg="#ff4d4d", font=("Helvetica", 11, "bold"))
        frame_alerts.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        columns = ("thoi_gian", "ip_nguon", "ip_dich", "do_dai", "phan_loai")
        self.tree = ttk.Treeview(frame_alerts, columns=columns, show='headings', height=10)
        
        self.tree.heading("thoi_gian", text="Thời gian Báo động")
        self.tree.heading("ip_nguon", text="IP Kẻ tấn công")
        self.tree.heading("ip_dich", text="IP Nạn nhân")
        self.tree.heading("do_dai", text="Kích thước")
        self.tree.heading("phan_loai", text="Mức độ")
        
        self.tree.column("thoi_gian", width=180, anchor=tk.CENTER)
        self.tree.column("ip_nguon", width=180, anchor=tk.CENTER)
        self.tree.column("ip_dich", width=180, anchor=tk.CENTER)
        self.tree.column("do_dai", width=120, anchor=tk.CENTER)
        self.tree.column("phan_loai", width=120, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Chạy TCP Server ngầm
        threading.Thread(target=self.start_tcp_server, daemon=True).start()

        # Chạy vòng lặp cập nhật giao diện
        self.update_gui_loop()
        
    def update_clients_gui(self):
        """Cập nhật dữ liệu vào bảng Danh sách Cảm biến (Gọi từ các Thread)"""
        for item in self.tree_clients.get_children():
            self.tree_clients.delete(item)
            
        with self.lock:
            for addr, info in self.connected_clients.items():
                self.tree_clients.insert('', 0, values=(
                    info["ip"], info["port"], 
                    info["time_in"], info["time_out"], info["status"]
                ))

    def start_tcp_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', 9999))
        server_socket.listen(10)
        self.lbl_status.config(text="🟢 Máy chủ đang mở (Cổng 9999) | Đang chờ các Cảm biến kết nối tới...", fg="#00FF00")
        
        while True:
            conn, addr = server_socket.accept()
            
            # Lưu Client vào danh sách
            with self.lock:
                self.connected_clients[addr] = {
                    "ip": addr[0],
                    "port": addr[1],
                    "time_in": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "time_out": "-",
                    "status": "🟢 ONLINE"
                }
            self.root.after(0, self.update_clients_gui)
            
            # Báo hiệu lên giao diện ngay khi có Cảm biến kết nối tới
            self.root.after(0, lambda a=addr: self.lbl_status.config(
                text=f"🟢 Đã kết nối với Cảm biến {a[0]}:{a[1]} | Đang giám sát an ninh...", fg="#00FF00"
            ))
            
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return data

    def handle_client(self, client_conn, addr):
        try:
            while True:
                # Message Framing: Đọc 4 byte header
                raw_msglen = self.recvall(client_conn, 4)
                if not raw_msglen: break
                msglen = int.from_bytes(raw_msglen, byteorder='big')
                
                # Đọc payload
                raw_data = self.recvall(client_conn, msglen)
                if not raw_data: break
                    
                du_lieu = json.loads(raw_data.decode('utf-8'))
                
                print(f"\n[DEBUG - SERVER] Vừa nhận JSON: {du_lieu}")
                
                # Biến đổi thành DataFrame 5 cột cho AI
                df_input = pd.DataFrame([[
                    du_lieu['do_dai_goi_tin'], du_lieu['cong_nguon'],
                    du_lieu['cong_dich'], du_lieu['co_syn'], du_lieu['co_ack']
                ]], columns=['packet_length', 'src_port', 'dst_port', 'tcp_syn_flag', 'tcp_ack_flag'])
                
                # AI DỰ ĐOÁN
                ket_qua = self.mo_hinh_ai.predict(df_input)[0]
                
                print(f"[DEBUG - SERVER] --> AI Phán quyết: {'TẤN CÔNG (1)' if ket_qua == 1 else 'BÌNH THƯỜNG (0)'}")
                
                if ket_qua == 1:
                    canh_bao = {
                        "thoi_gian": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip_nguon": du_lieu['ip_nguon'], "cong_nguon": du_lieu['cong_nguon'],
                        "ip_dich": du_lieu['ip_dich'], "cong_dich": du_lieu['cong_dich'],
                        "do_dai": du_lieu['do_dai_goi_tin']
                    }
                    with self.lock:
                        self.alerts.append(canh_bao)
        except:
            pass
        finally:
            with self.lock:
                if addr in self.connected_clients:
                    self.connected_clients[addr]["time_out"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.connected_clients[addr]["status"] = "🔴 OFFLINE"
            self.root.after(0, self.update_clients_gui)
            client_conn.close()

    def update_gui_loop(self):
        """Hàm tự động vẽ lại bảng nếu mảng alerts có thêm dữ liệu mới"""
        with self.lock:
            current_count = len(self.alerts)
            if current_count > self.previous_count:
                self.lbl_status.config(text=f"🟢 Hệ thống đang bảo vệ | Tổng số báo động: {current_count} 🚨", fg="#00FF00")
                
                # Xóa bảng cũ
                for item in self.tree.get_children(): 
                    self.tree.delete(item)
                
                # Vẽ lại mảng dữ liệu (mới nhất lên đầu)
                for alert in reversed(self.alerts):
                    self.tree.insert("", tk.END, values=(
                        alert["thoi_gian"],
                        f"{alert['ip_nguon']}:{alert['cong_nguon']}",
                        f"{alert['ip_dich']}:{alert['cong_dich']}",
                        f"{alert['do_dai']} bytes",
                        "🚨 TẤN CÔNG"
                    ))
                self.previous_count = current_count
                
        # Lặp lại sau 1000ms (1 giây)
        self.root.after(1000, self.update_gui_loop)

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import ttk
import urllib.request
import urllib.error
import json
import threading
import time

class IDSDashboardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-IDS Desktop Dashboard")
        self.root.geometry("950x550")
        self.root.configure(bg="#121212") # Dark mode theme

        # Tùy chỉnh giao diện Bảng (Treeview)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", 
                        background="#1e1e1e", 
                        foreground="#00FF00", 
                        fieldbackground="#1e1e1e", 
                        rowheight=30,
                        font=("Consolas", 10))
        style.configure("Treeview.Heading", 
                        background="#333333", 
                        foreground="white", 
                        font=("Helvetica", 11, "bold"))
        style.map('Treeview', background=[('selected', '#d32f2f')]) # Màu đỏ khi click chọn
        
        # Tiêu đề
        self.lbl_title = tk.Label(root, text="🛡️ HỆ THỐNG GIÁM SÁT XÂM NHẬP (AI-IDS)", font=("Helvetica", 18, "bold"), bg="#121212", fg="#00FF00")
        self.lbl_title.pack(pady=15)

        # Trạng thái kết nối
        self.lbl_status = tk.Label(root, text="🔌 Trạng thái: Đang chờ kết nối API Server...", font=("Helvetica", 11, "italic"), bg="#121212", fg="yellow")
        self.lbl_status.pack(pady=5)
        
        # Tạo bảng hiển thị (Treeview)
        columns = ("thoi_gian", "ip_nguon", "ip_dich", "do_dai", "phan_loai")
        self.tree = ttk.Treeview(root, columns=columns, show='headings', height=12)
        
        # Đặt tên cột
        self.tree.heading("thoi_gian", text="Thời gian")
        self.tree.heading("ip_nguon", text="IP Nguồn (Kẻ tấn công)")
        self.tree.heading("ip_dich", text="IP Đích (Mục tiêu)")
        self.tree.heading("do_dai", text="Chiều dài (TCP)")
        self.tree.heading("phan_loai", text="Trạng thái")
        
        # Chỉnh kích thước cột
        self.tree.column("thoi_gian", width=180, anchor=tk.CENTER)
        self.tree.column("ip_nguon", width=180, anchor=tk.CENTER)
        self.tree.column("ip_dich", width=180, anchor=tk.CENTER)
        self.tree.column("do_dai", width=120, anchor=tk.CENTER)
        self.tree.column("phan_loai", width=120, anchor=tk.CENTER)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Các biến quản lý việc tự động làm mới (Polling)
        self.is_running = True
        self.previous_count = 0
        
        # Khởi động luồng ngầm để gọi API 2 giây/lần
        self.poll_thread = threading.Thread(target=self.fetch_api_data, daemon=True)
        self.poll_thread.start()

    def fetch_api_data(self):
        """Hàm chạy ngầm liên tục để lấy dữ liệu từ Flask API"""
        api_url = "http://localhost:5000/api/canh-bao"
        while self.is_running:
            try:
                # Gọi API
                req = urllib.request.Request(api_url)
                with urllib.request.urlopen(req, timeout=2) as response:
                    if response.status == 200:
                        data = json.loads(response.read().decode('utf-8'))
                        alerts = data.get("du_lieu", [])
                        current_count = data.get("tong_so_canh_bao", 0)
                        
                        # Cập nhật dòng trạng thái xanh lá
                        self.lbl_status.config(text=f"🟢 Đã kết nối API Server | Tổng số báo động: {current_count} 🚨", fg="#00FF00")
                        
                        # Nếu có cảnh báo mới thì mới vẽ lại bảng
                        if current_count != self.previous_count:
                            self.update_table(alerts)
                            self.previous_count = current_count
            except (urllib.error.URLError, Exception):
                # Nếu API chết hoặc chưa bật core_server.py
                self.lbl_status.config(text="🔴 Mất kết nối! Hãy chắc chắn bạn đã chạy lệnh `sudo python3 core_server.py`", fg="#ff4444")
            
            # Đợi 2 giây rồi quét tiếp
            time.sleep(2)

    def update_table(self, alerts):
        """Hàm xóa bảng cũ và điền dữ liệu mới (Hiển thị tấn công mới nhất lên đầu)"""
        # Xóa các dòng cũ
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Điền các dòng mới (Duyệt ngược danh sách để cái mới nhất lên đầu)
        for alert in reversed(alerts):
            self.tree.insert("", tk.END, values=(
                alert.get("thoi_gian", "N/A"),
                f"{alert.get('ip_nguon')}:{alert.get('cong_nguon')}",
                f"{alert.get('ip_dich')}:{alert.get('cong_dich')}",
                f"{alert.get('do_dai_goi_tin', 0)} bytes",
                "🚨 TẤN CÔNG"
            ))

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSDashboardApp(root)
    root.mainloop()

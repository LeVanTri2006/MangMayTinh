# =============================================================================
# TÊN DỰ ÁN : HỆ THỐNG PHÁT HIỆN XÂM NHẬP DỰA TRÊN TRÍ TUỆ NHÂN TẠO (AI-IDS)
# TÊN FILE  : train_model.py
# MÔ TẢ     : Đọc dữ liệu mạng, huấn luyện mô hình Random Forest,
#              đánh giá kết quả và xuất file "bộ não" ai_model.pkl
# CÔNG NGHỆ : Python 3.x, pandas, numpy, scikit-learn, joblib
# =============================================================================

# --- NHẬP CÁC THƯ VIỆN CẦN THIẾT ---
import pandas as pd                          # Thư viện xử lý dữ liệu dạng bảng (CSV)
import numpy as np                           # Thư viện xử lý mảng số học
import joblib                                # Thư viện lưu/tải mô hình sang file .pkl

from sklearn.ensemble import RandomForestClassifier   # Thuật toán Rừng Ngẫu Nhiên (mô hình lõi)
from sklearn.model_selection import train_test_split  # Hàm chia tập dữ liệu Train/Test
from sklearn.metrics import (                         # Các hàm đánh giá mô hình
    accuracy_score,
    classification_report,
    confusion_matrix
)


# =============================================================================
# BƯỚC 1: KHỞI TẠO VÀ NẠP DỮ LIỆU (LOAD DATA)
# =============================================================================
def nap_du_lieu(ten_file: str) -> pd.DataFrame:
    """
    Hàm đọc file CSV chứa dữ liệu gói tin mạng.

    Tham số:
        ten_file (str): Đường dẫn đến file dataset.csv

    Trả về:
        du_lieu (DataFrame): Bảng dữ liệu pandas chứa toàn bộ thông tin gói tin
    """
    try:
        # Dùng pandas đọc file CSV vào một bảng dữ liệu (DataFrame)
        du_lieu = pd.read_csv(ten_file)

        # Thông báo đọc file thành công kèm số dòng và số cột
        print(f"[OK] Doc du lieu thanh cong tu '{ten_file}'.")
        print(f"    -> Tong so mau (dong): {du_lieu.shape[0]}")
        print(f"    -> Tong so dac trung (cot): {du_lieu.shape[1]}")
        print(f"    -> Phan phoi nhan (label):\n{du_lieu['label'].value_counts().to_string()}")
        print("-" * 55)

        return du_lieu

    except FileNotFoundError:
        # Bắt lỗi khi không tìm thấy file và in hướng dẫn cho người dùng
        print(f"[LOI] Khong tim thay file '{ten_file}'!")
        print("    -> Vui long kiem tra lai duong dan va dam bao file")
        print(f"       '{ten_file}' nam trong cung thu muc voi script nay.")
        # Dừng chương trình vì không có dữ liệu thì không thể tiếp tục
        raise SystemExit(1)


# =============================================================================
# BƯỚC 2: TIỀN XỬ LÝ DỮ LIỆU (DATA PREPROCESSING)
# =============================================================================
def tien_xu_ly_du_lieu(du_lieu: pd.DataFrame):
    """
    Hàm tách dữ liệu thành tập đặc trưng (X) và nhãn (y),
    sau đó chia thành tập Train (80%) và Test (20%).

    Tham số:
        du_lieu (DataFrame): Bảng dữ liệu đầy đủ từ Bước 1

    Trả về:
        X_huan_luyen, X_kiem_thu, y_huan_luyen, y_kiem_thu: 4 tập dữ liệu đã chia
    """
    print("[->] Buoc 2: Dang tien xu ly du lieu...")

    # Danh sách các cột đặc trưng (Features) - là "đầu vào" cho mô hình AI
    cac_cot_dac_trung = [
        'packet_length',   # Kích thước gói tin
        'src_port',        # Cổng nguồn
        'dst_port',        # Cổng đích
        'tcp_syn_flag',    # Cờ SYN (0 hoặc 1)
        'tcp_ack_flag'     # Cờ ACK (0 hoặc 1)
    ]

    # X: Ma trận đặc trưng - chứa dữ liệu thô của các gói tin (không có nhãn)
    X = du_lieu[cac_cot_dac_trung]

    # y: Vector nhãn - chứa kết quả phân loại (0=Bình thường, 1=Tấn công)
    y = du_lieu['label']

    # Chia tập dữ liệu:
    #   - test_size=0.2   -> 20% dùng để kiểm thử (Test set)
    #   - random_state=42 -> Cố định ngẫu nhiên để kết quả tái lập được
    X_huan_luyen, X_kiem_thu, y_huan_luyen, y_kiem_thu = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42
    )

    # In ra thông tin số lượng mẫu của từng tập
    print(f"    -> Tap Huan Luyen (Train): {X_huan_luyen.shape[0]} mau")
    print(f"    -> Tap Kiem Thu  (Test) : {X_kiem_thu.shape[0]} mau")
    print("-" * 55)

    return X_huan_luyen, X_kiem_thu, y_huan_luyen, y_kiem_thu


# =============================================================================
# BƯỚC 3: HUẤN LUYỆN MÔ HÌNH (MODEL TRAINING)
# =============================================================================
def huan_luyen_mo_hinh(X_huan_luyen, y_huan_luyen) -> RandomForestClassifier:
    """
    Hàm khởi tạo và huấn luyện mô hình Rừng Ngẫu Nhiên (Random Forest).

    Tham số:
        X_huan_luyen: Tập đặc trưng dùng để huấn luyện
        y_huan_luyen: Tập nhãn tương ứng dùng để huấn luyện

    Trả về:
        mo_hinh (RandomForestClassifier): Mô hình AI đã được huấn luyện
    """
    # Thông báo bắt đầu huấn luyện (đúng theo yêu cầu đề bài)
    print("Dang tien hanh huan luyen mo hinh...")

    # Khởi tạo mô hình Rừng Ngẫu Nhiên với các siêu tham số cơ bản:
    #   - n_estimators=100  -> Xây dựng 100 cây quyết định (Decision Tree)
    #   - random_state=42   -> Đảm bảo kết quả nhất quán mỗi lần chạy
    mo_hinh = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    # Gọi hàm fit() để mô hình "học" từ dữ liệu huấn luyện
    # Lúc này 100 cây quyết định sẽ được xây dựng đồng thời
    mo_hinh.fit(X_huan_luyen, y_huan_luyen)

    print("[OK] Huan luyen hoan tat!")
    print("-" * 55)

    return mo_hinh


# =============================================================================
# BƯỚC 4: ĐÁNH GIÁ MÔ HÌNH (MODEL EVALUATION)
# =============================================================================
def danh_gia_mo_hinh(mo_hinh: RandomForestClassifier, X_kiem_thu, y_kiem_thu):
    """
    Hàm sử dụng tập kiểm thử để đo lường chất lượng mô hình AI.
    In ra các chỉ số quan trọng phục vụ báo cáo đồ án.

    Tham số:
        mo_hinh       : Mô hình Random Forest đã được huấn luyện
        X_kiem_thu    : Tập đặc trưng kiểm thử (mô hình chưa thấy)
        y_kiem_thu    : Nhãn thực tế của tập kiểm thử (để so sánh)
    """
    print("[->] Buoc 4: Dang danh gia mo hinh tren tap kiem thu...")

    # Dùng mô hình dự đoán nhãn cho tập kiểm thử
    # Kết quả y_du_doan là mảng các giá trị 0 hoặc 1
    y_du_doan = mo_hinh.predict(X_kiem_thu)

    # --- CHỈ SỐ 1: ĐỘ CHÍNH XÁC TỔNG THỂ (ACCURACY SCORE) ---
    # Tỷ lệ số mẫu dự đoán đúng trên tổng số mẫu kiểm thử
    do_chinh_xac = accuracy_score(y_kiem_thu, y_du_doan)
    print("\n" + "=" * 55)
    print("  KET QUA DANH GIA MO HINH AI-IDS")
    print("=" * 55)
    print(f"  [1] Do Chinh Xac Tong The (Accuracy Score): {do_chinh_xac * 100:.2f}%")

    # --- CHỈ SỐ 2: MA TRẬN NHẦM LẪN (CONFUSION MATRIX) ---
    # Bảng 2x2 cho biết:
    #   - [TN] Du doan dung la Binh thuong   [FP] Nham Tan cong la Binh thuong
    #   - [FN] Nham Binh thuong la Tan cong  [TP] Du doan dung la Tan cong
    ma_tran_nham_lan = confusion_matrix(y_kiem_thu, y_du_doan)
    print("\n  [2] Ma Tran Nham Lan (Confusion Matrix):")
    print("      (Hang=Thuc te, Cot=Du doan | 0=Binh thuong, 1=Tan cong)")
    print(f"      {ma_tran_nham_lan}")

    # --- CHỈ SỐ 3: BÁO CÁO PHÂN LOẠI CHI TIẾT (CLASSIFICATION REPORT) ---
    # Gồm: Precision (Độ chính xác), Recall (Độ nhạy), F1-score cho từng lớp
    ten_lop = ['Binh thuong (0)', 'Tan cong (1)']
    bao_cao_phan_loai = classification_report(
        y_kiem_thu,
        y_du_doan,
        target_names=ten_lop
    )
    print("\n  [3] Bao Cao Phan Loai Chi Tiet (Classification Report):")
    print(bao_cao_phan_loai)
    print("=" * 55 + "\n")


# =============================================================================
# BƯỚC 5: XUẤT FILE MÔ HÌNH (EXPORT MODEL)
# =============================================================================
def xuat_mo_hinh(mo_hinh: RandomForestClassifier, ten_file_xuat: str):
    """
    Hàm lưu mô hình đã huấn luyện thành file .pkl để tái sử dụng
    ở Module Server mà không cần huấn luyện lại.

    Tham số:
        mo_hinh       : Mô hình Random Forest đã được huấn luyện
        ten_file_xuat : Tên file xuất ra (mặc định: 'ai_model.pkl')
    """
    # Dùng joblib.dump() để tuần tự hóa (serialize) toàn bộ mô hình thành file nhị phân
    joblib.dump(mo_hinh, ten_file_xuat)

    # In thông báo thành công đúng theo yêu cầu đề bài
    print(f"Da luu mo hinh thanh cong tai {ten_file_xuat}. San sang tich hop vao Core Server")


# =============================================================================
# ĐIỂM KHỞI CHẠY CHƯƠNG TRÌNH (ENTRY POINT)
# Toàn bộ logic chính được đặt trong khối này để đảm bảo script
# chỉ chạy khi được thực thi trực tiếp, không chạy khi bị import
# =============================================================================
if __name__ == '__main__':

    print("=" * 55)
    print("  HE THONG PHAT HIEN XAM NHAP DUA TREN AI (AI-IDS)")
    print("  Module: Huan luyen mo hinh (train_model.py)")
    print("=" * 55)
    print()

    # --- BƯỚC 1: NẠP DỮ LIỆU ---
    # Tên file dữ liệu đầu vào (phải nằm cùng thư mục với script)
    TEN_FILE_DU_LIEU = 'dataset.csv'
    du_lieu_mang = nap_du_lieu(TEN_FILE_DU_LIEU)

    # --- BƯỚC 2: TIỀN XỬ LÝ ---
    X_huan_luyen, X_kiem_thu, y_huan_luyen, y_kiem_thu = tien_xu_ly_du_lieu(du_lieu_mang)

    # --- BƯỚC 3: HUẤN LUYỆN ---
    mo_hinh_ids = huan_luyen_mo_hinh(X_huan_luyen, y_huan_luyen)

    # --- BƯỚC 4: ĐÁNH GIÁ ---
    danh_gia_mo_hinh(mo_hinh_ids, X_kiem_thu, y_kiem_thu)

    # --- BƯỚC 5: XUẤT FILE MÔ HÌNH ---
    # Tên file "bộ não" sẽ được lưu để tích hợp vào Core Server
    TEN_FILE_MO_HINH = 'ai_model.pkl'
    xuat_mo_hinh(mo_hinh_ids, TEN_FILE_MO_HINH)

# import pandas as pd

# df = pd.read_csv('data/2017/original/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

# print(df.info())


import matplotlib.pyplot as plt

# Dữ liệu từ Confusion Matrix
labels_attack = ['(D)DOS', 'Botnet', 'Brute Force', 'Port Scan', 'Web Attack', 'Unknown']
counts_attack = [584, 584, 584, 584, 584, 47]

count_benign = 56468
total_attack = sum(counts_attack)

# --- BIỂU ĐỒ 1: Tỉ lệ Bình thường vs Tấn công ---
plt.figure(figsize=(14, 6))

plt.subplot(1, 2, 1)
labels_overview = ['Benign (Bình thường)', 'Attack (Tấn công)']
sizes_overview = [count_benign, total_attack]
colors_overview = ['#66b3ff', '#ff9999']
explode_overview = (0, 0.1)  # Tách phần tấn công ra

plt.pie(sizes_overview, explode=explode_overview, labels=labels_overview, autopct='%1.1f%%',
        shadow=True, startangle=90, colors=colors_overview)
plt.title('Tỉ lệ lưu lượng Bình thường vs Tấn công')

# --- BIỂU ĐỒ 2: Phân bố chi tiết các loại tấn công ---
plt.subplot(1, 2, 2)
# Sử dụng biểu đồ cột (Bar chart) để so sánh số lượng
bars = plt.bar(labels_attack, counts_attack, color=['#ff9999', '#ffcc99', '#99ff99', '#ffb3e6', '#c2c2f0', '#ff6666'])

plt.title('Phân bố số lượng các loại tấn công (Loại bỏ Benign)')
plt.xlabel('Loại tấn công')
plt.ylabel('Số lượng mẫu')
plt.xticks(rotation=45)

# Hiển thị số liệu trên đầu cột
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 5, int(yval), ha='center', va='bottom')

plt.tight_layout()
plt.show()
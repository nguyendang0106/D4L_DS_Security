"""
Test script for Data Storage Manager
Demonstrates CRUD operations and relabeling functionality
"""

from data_storage_manager import get_storage_manager
import numpy as np

def print_section(title):
    """Print section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def main():
    # Khởi tạo storage manager
    storage = get_storage_manager()
    
    print_section("1. THỐNG KÊ BAN ĐẦU")
    stats = storage.get_statistics()
    print(f"Total records: {stats['total_records']}")
    print(f"Attack types: {stats['attack_types']}")
    
    # ==========================================
    # CREATE - Thêm dữ liệu mẫu
    # ==========================================
    print_section("2. CREATE - Thêm dữ liệu mẫu")
    
    # Tạo 84 features giả lập
    def generate_fake_features():
        return np.random.rand(84).tolist()
    
    # 2.1. Thêm Benign
    print("\n📝 Thêm 5 records Benign...")
    for i in range(5):
        storage.add_record('benign', generate_fake_features(), 'Benign', confidence=0.98)
    print("✅ Done!")
    
    # 2.2. Thêm Known Attacks
    print("\n📝 Thêm Known Attacks...")
    attack_types = ['DDoS', 'PortScan', 'Bot', 'Web Attack']
    for attack in attack_types:
        features_batch = [generate_fake_features() for _ in range(3)]
        labels_batch = [attack] * 3
        confidence_batch = [0.95, 0.92, 0.88]
        storage.add_batch('known_attacks', features_batch, labels_batch, confidence_batch)
    print(f"✅ Added {len(attack_types) * 3} known attack records!")
    
    # 2.3. Thêm Unknown (Dynamic & Static)
    print("\n📝 Thêm Unknown records...")
    unknown_features = [generate_fake_features() for _ in range(10)]
    unknown_labels = ['Unknown'] * 10
    unknown_conf = np.random.uniform(0.3, 0.6, 10).tolist()
    
    storage.add_batch('unknown_dynamic', unknown_features, unknown_labels, unknown_conf)
    storage.add_batch('unknown_static', unknown_features, unknown_labels, unknown_conf)
    print("✅ Added 10 Unknown records to both Dynamic and Static!")
    
    # ==========================================
    # READ - Đọc dữ liệu
    # ==========================================
    print_section("3. READ - Đọc dữ liệu")
    
    # 3.1. Đọc Benign
    print("\n📖 Benign records (first 3):")
    df_benign = storage.get_records('benign', limit=3)
    print(f"   Total: {len(df_benign)} records")
    print(f"   Columns: {list(df_benign.columns[:5])}... (showing first 5)")
    
    # 3.2. Đọc Known Attacks với filter
    print("\n📖 Known Attacks - DDoS only:")
    df_ddos = storage.get_records('known_attacks', filter_label='DDoS')
    print(f"   Found {len(df_ddos)} DDoS records")
    
    # 3.3. Đếm records
    print("\n📊 Record counts:")
    for category in ['benign', 'known_attacks', 'unknown_dynamic', 'unknown_static']:
        count = storage.get_record_count(category)
        print(f"   {category}: {count} records")
    
    # ==========================================
    # UPDATE - Cập nhật dữ liệu
    # ==========================================
    print_section("4. UPDATE - Cập nhật dữ liệu")
    
    print("\n✏️  Update record index 0 in Benign (change confidence)...")
    storage.update_record('benign', 0, new_confidence=0.99)
    print("✅ Updated!")
    
    # Verify
    df_verify = storage.get_records('benign', limit=1)
    print(f"   New confidence: {df_verify.iloc[0]['Confidence']}")
    
    # ==========================================
    # RELABEL - Chuyển Unknown → Known
    # ==========================================
    print_section("5. RELABEL - Chuyển Unknown Dynamic sang Known Attacks")
    
    print("\n🔄 Trước khi relabel:")
    print(f"   Unknown Dynamic: {storage.get_record_count('unknown_dynamic')} records")
    print(f"   Known Attacks: {storage.get_record_count('known_attacks')} records")
    
    # NOTE: Có thể relabel thành bất kỳ nhãn nào:
    # - Các nhãn chuẩn: 'Benign', '(D)DOS', 'Botnet', 'Brute Force', 'Port Scan', 'Web Attack'
    # - Hoặc nhãn tùy chỉnh cho loại tấn công mới phát hiện: 'New Attack Type', 'Zero-Day Attack', v.v.
    print("\n🏷️  Relabel index 0,1,2 → 'New Attack Type'...")
    count = storage.relabel_batch_unknown_to_known([0, 1, 2], 'New Attack Type')
    print(f"✅ Relabeled {count} records!")
    
    print("\n🔄 Sau khi relabel:")
    print(f"   Unknown Dynamic: {storage.get_record_count('unknown_dynamic')} records")
    print(f"   Known Attacks: {storage.get_record_count('known_attacks')} records")
    
    # Verify trong Known Attacks
    df_new_attack = storage.get_records('known_attacks', filter_label='New Attack Type')
    print(f"   Found {len(df_new_attack)} 'New Attack Type' records in Known Attacks")
    
    # ==========================================
    # DELETE - Xóa dữ liệu
    # ==========================================
    print_section("6. DELETE - Xóa dữ liệu")
    
    print("\n🗑️  Delete record index 0 from Benign...")
    storage.delete_record('benign', 0)
    print(f"✅ Deleted! New count: {storage.get_record_count('benign')}")
    
    print("\n🗑️  Delete all 'Bot' attacks...")
    deleted_count = storage.delete_by_label('known_attacks', 'Bot')
    print(f"✅ Deleted {deleted_count} Bot records!")
    
    # ==========================================
    # SEARCH - Tìm kiếm
    # ==========================================
    print_section("7. SEARCH - Tìm kiếm dữ liệu")
    
    print("\n🔍 Search Known Attacks with label='DDoS'...")
    df_search = storage.search_records('known_attacks', {' Label': 'DDoS'})
    print(f"   Found {len(df_search)} records")
    
    # ==========================================
    # EXPORT - Xuất dữ liệu
    # ==========================================
    print_section("8. EXPORT - Xuất dữ liệu")
    
    print("\n💾 Export Known Attacks to CSV...")
    storage.export_category('known_attacks', 'data/exports/known_attacks_export.csv', 'csv')
    print("✅ Exported!")
    
    print("\n💾 Export Unknown Dynamic to JSON...")
    storage.export_category('unknown_dynamic', 'data/exports/unknown_dynamic_export.json', 'json')
    print("✅ Exported!")
    
    # ==========================================
    # FINAL STATISTICS
    # ==========================================
    print_section("9. THỐNG KÊ CUỐI CÙNG")
    
    final_stats = storage.get_statistics()
    print(f"\n📊 Total records:")
    for category, count in final_stats['total_records'].items():
        print(f"   {category}: {count} records")
    
    print(f"\n🎯 Attack types distribution:")
    for attack_type, count in final_stats['attack_types'].items():
        print(f"   {attack_type}: {count} records")
    
    print(f"\n💾 Storage file sizes:")
    for category, size in final_stats['storage_files'].items():
        print(f"   {category}: {size/1024:.2f} KB")
    
    print(f"\n⏰ Last updated: {final_stats['last_updated']}")
    
    print("\n" + "="*60)
    print("  ✅ ALL TESTS COMPLETED!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()

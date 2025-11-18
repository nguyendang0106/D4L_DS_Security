"""
Data Storage Manager - Quản lý lưu trữ dữ liệu phân loại
=========================================================

Quản lý 4 nhóm dữ liệu:
1. Benign - Dữ liệu lành tính
2. Known Attacks - Các loại tấn công đã biết
3. Unknown (Dynamic) - Unknown có thể gán nhãn và chuyển sang Known
4. Unknown (Static) - Unknown lưu vĩnh viễn, không thay đổi

Author: NIDS System
"""

import pandas as pd
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import threading
import json
from pathlib import Path


class DataStorageManager:
    """Quản lý lưu trữ và thao tác CRUD cho 4 nhóm dữ liệu"""
    
    # Định nghĩa 4 file storage
    STORAGE_FILES = {
        'benign': 'data/storage/benign_data.csv',
        'known_attacks': 'data/storage/known_attacks_data.csv',
        'unknown_dynamic': 'data/storage/unknown_dynamic_data.csv',
        'unknown_static': 'data/storage/unknown_static_data.csv'
    }
    
    # Metadata file để track thống kê
    METADATA_FILE = 'data/storage/metadata.json'
    
    def __init__(self):
        """Khởi tạo Data Storage Manager"""
        self.lock = threading.Lock()
        self._initialize_storage()
        self.metadata = self._load_metadata()
        
    def _initialize_storage(self):
        """Tạo thư mục và file storage nếu chưa tồn tại"""
        # Tạo thư mục storage
        storage_dir = Path('data/storage')
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Khởi tạo các file CSV nếu chưa có
        for category, filepath in self.STORAGE_FILES.items():
            if not os.path.exists(filepath):
                # Tạo file với header (85 cột: 84 features + 1 label)
                header = self._get_csv_header()
                df = pd.DataFrame(columns=header)
                df.to_csv(filepath, index=False)
                print(f"✅ Created storage file: {filepath}")
    
    def _get_csv_header(self) -> List[str]:
        """Lấy header cho CSV (84 features + Label + Metadata)"""
        # 84 features từ RAW_FEATURE_NAMES (từ server.py)
        features = [
            " Flow ID", " Source IP", " Source Port", " Destination IP", 
            " Destination Port", " Protocol", " Timestamp", " Flow Duration",
            " Total Fwd Packets", " Total Backward Packets",
            "Total Length of Fwd Packets", " Total Length of Bwd Packets",
            " Fwd Packet Length Max", " Fwd Packet Length Min",
            " Fwd Packet Length Mean", " Fwd Packet Length Std",
            "Bwd Packet Length Max", " Bwd Packet Length Min",
            " Bwd Packet Length Mean", " Bwd Packet Length Std",
            "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
            " Flow IAT Std", " Flow IAT Max", " Flow IAT Min",
            "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std",
            " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total",
            " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max",
            " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags",
            " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length",
            " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s",
            " Min Packet Length", " Max Packet Length",
            " Packet Length Mean", " Packet Length Std",
            " Packet Length Variance", "FIN Flag Count",
            " SYN Flag Count", " RST Flag Count", " PSH Flag Count",
            " ACK Flag Count", " URG Flag Count", " CWE Flag Count",
            " ECE Flag Count", " Down/Up Ratio", " Average Packet Size",
            " Avg Fwd Segment Size", " Avg Bwd Segment Size",
            " Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
            " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate",
            " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
            " Subflow Fwd Bytes", " Subflow Bwd Packets",
            " Subflow Bwd Bytes", "Init_Win_bytes_forward",
            " Init_Win_bytes_backward", " act_data_pkt_fwd",
            " min_seg_size_forward", "Active Mean", " Active Std",
            " Active Max", " Active Min", "Idle Mean", " Idle Std",
            " Idle Max", " Idle Min"
        ]
        
        # Thêm cột Label, Timestamp, Confidence (nếu có)
        return features + [' Label', 'StoredAt', 'Confidence']
    
    def _load_metadata(self) -> Dict:
        """Load metadata từ file"""
        if os.path.exists(self.METADATA_FILE):
            with open(self.METADATA_FILE, 'r') as f:
                return json.load(f)
        else:
            # Metadata mặc định
            metadata = {
                'total_records': {
                    'benign': 0,
                    'known_attacks': 0,
                    'unknown_dynamic': 0,
                    'unknown_static': 0
                },
                'attack_types': {},
                'last_updated': datetime.now().isoformat(),
                'version': '1.0'
            }
            self._save_metadata(metadata)
            return metadata
    
    def _save_metadata(self, metadata: Dict):
        """Lưu metadata ra file"""
        with open(self.METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    # ==========================================
    # CREATE Operations
    # ==========================================
    
    def add_record(self, category: str, features: List[float], label: str, 
                   confidence: float = None) -> bool:
        """
        Thêm 1 record vào storage
        
        Args:
            category: 'benign', 'known_attacks', 'unknown_dynamic', 'unknown_static'
            features: List 84 features
            label: Nhãn phân loại
            confidence: Độ tin cậy (optional)
            
        Returns:
            True nếu thành công
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                
                # Tạo row mới
                row = features + [label, datetime.now().isoformat(), confidence]
                
                # Append vào CSV
                df = pd.DataFrame([row], columns=self._get_csv_header())
                df.to_csv(filepath, mode='a', header=False, index=False)
                
                # Update metadata
                self.metadata['total_records'][category] += 1
                if category in ['known_attacks', 'unknown_dynamic', 'unknown_static']:
                    if label not in self.metadata['attack_types']:
                        self.metadata['attack_types'][label] = 0
                    self.metadata['attack_types'][label] += 1
                
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                return True
                
            except Exception as e:
                print(f"❌ Error adding record: {e}")
                return False
    
    def add_batch(self, category: str, batch_features: List[List[float]], 
                  batch_labels: List[str], batch_confidence: List[float] = None) -> int:
        """
        Thêm nhiều records cùng lúc (batch)
        
        Returns:
            Số lượng records đã thêm thành công
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                
                # Tạo DataFrame
                data = []
                for i, (features, label) in enumerate(zip(batch_features, batch_labels)):
                    conf = batch_confidence[i] if batch_confidence else None
                    row = features + [label, datetime.now().isoformat(), conf]
                    data.append(row)
                
                df = pd.DataFrame(data, columns=self._get_csv_header())
                df.to_csv(filepath, mode='a', header=False, index=False)
                
                # Update metadata
                count = len(batch_labels)
                self.metadata['total_records'][category] += count
                
                for label in batch_labels:
                    if category in ['known_attacks', 'unknown_dynamic', 'unknown_static']:
                        if label not in self.metadata['attack_types']:
                            self.metadata['attack_types'][label] = 0
                        self.metadata['attack_types'][label] += 1
                
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                return count
                
            except Exception as e:
                print(f"❌ Error adding batch: {e}")
                return 0
    
    # ==========================================
    # READ Operations
    # ==========================================
    
    def get_records(self, category: str, limit: int = None, 
                    offset: int = 0, filter_label: str = None) -> pd.DataFrame:
        """
        Đọc records từ storage
        
        Args:
            category: Nhóm dữ liệu
            limit: Số lượng records tối đa
            offset: Bỏ qua N records đầu
            filter_label: Lọc theo label (optional)
            
        Returns:
            DataFrame chứa records
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        filepath = self.STORAGE_FILES[category]
        
        try:
            df = pd.read_csv(filepath)
            
            # Filter by label
            if filter_label:
                df = df[df[' Label'] == filter_label]
            
            # Pagination
            if offset > 0:
                df = df.iloc[offset:]
            if limit:
                df = df.head(limit)
            
            return df
            
        except Exception as e:
            print(f"❌ Error reading records: {e}")
            return pd.DataFrame()
    
    def get_record_count(self, category: str, filter_label: str = None) -> int:
        """Đếm số lượng records trong category"""
        if filter_label:
            df = self.get_records(category, filter_label=filter_label)
            return len(df)
        else:
            return self.metadata['total_records'].get(category, 0)
    
    def search_records(self, category: str, search_criteria: Dict) -> pd.DataFrame:
        """
        Tìm kiếm records theo criteria
        
        Args:
            category: Nhóm dữ liệu
            search_criteria: Dict với key là column name, value là giá trị cần tìm
            
        Example:
            search_records('known_attacks', {' Label': 'DDoS', 'Confidence': 0.95})
        """
        df = self.get_records(category)
        
        for column, value in search_criteria.items():
            if column in df.columns:
                df = df[df[column] == value]
        
        return df
    
    # ==========================================
    # UPDATE Operations
    # ==========================================
    
    def update_record(self, category: str, row_index: int, 
                      new_label: str = None, new_confidence: float = None) -> bool:
        """
        Cập nhật 1 record (chủ yếu dùng để sửa label)
        
        Args:
            category: Nhóm dữ liệu
            row_index: Index của row cần update
            new_label: Label mới (optional)
            new_confidence: Confidence mới (optional)
            
        Returns:
            True nếu thành công
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                df = pd.read_csv(filepath)
                
                if row_index >= len(df):
                    return False
                
                # Update fields
                if new_label:
                    old_label = df.at[row_index, ' Label']
                    df.at[row_index, ' Label'] = new_label
                    
                    # Update metadata
                    if old_label in self.metadata['attack_types']:
                        self.metadata['attack_types'][old_label] -= 1
                    if new_label not in self.metadata['attack_types']:
                        self.metadata['attack_types'][new_label] = 0
                    self.metadata['attack_types'][new_label] += 1
                
                if new_confidence is not None:
                    df.at[row_index, 'Confidence'] = new_confidence
                
                # Lưu lại
                df.to_csv(filepath, index=False)
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                return True
                
            except Exception as e:
                print(f"❌ Error updating record: {e}")
                return False
    
    # ==========================================
    # DELETE Operations
    # ==========================================
    
    def delete_record(self, category: str, row_index: int) -> bool:
        """
        Xóa 1 record
        
        Args:
            category: Nhóm dữ liệu
            row_index: Index của row cần xóa
            
        Returns:
            True nếu thành công
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                df = pd.read_csv(filepath)
                
                if row_index >= len(df):
                    return False
                
                # Get label before delete
                label = df.at[row_index, ' Label']
                
                # Delete row
                df = df.drop(row_index).reset_index(drop=True)
                df.to_csv(filepath, index=False)
                
                # Update metadata
                self.metadata['total_records'][category] -= 1
                if label in self.metadata['attack_types']:
                    self.metadata['attack_types'][label] -= 1
                
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                return True
                
            except Exception as e:
                print(f"❌ Error deleting record: {e}")
                return False
    
    def delete_by_label(self, category: str, label: str) -> int:
        """
        Xóa tất cả records có label cụ thể
        
        Returns:
            Số lượng records đã xóa
        """
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                df = pd.read_csv(filepath)
                
                # Count records to delete
                count = len(df[df[' Label'] == label])
                
                # Delete
                df = df[df[' Label'] != label]
                df.to_csv(filepath, index=False)
                
                # Update metadata
                self.metadata['total_records'][category] -= count
                if label in self.metadata['attack_types']:
                    self.metadata['attack_types'][label] = 0
                
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                return count
                
            except Exception as e:
                print(f"❌ Error deleting by label: {e}")
                return 0
    
    # ==========================================
    # SPECIAL: Chuyển Unknown Dynamic sang Known Attacks
    # ==========================================
    
    def relabel_unknown_to_known(self, row_index: int, new_attack_label: str) -> bool:
        """
        Chuyển 1 record từ Unknown (Dynamic) sang Known Attacks với nhãn mới
        
        Args:
            row_index: Index trong unknown_dynamic
            new_attack_label: Tên loại tấn công mới
            
        Returns:
            True nếu thành công
        """
        with self.lock:
            try:
                # 1. Đọc record từ unknown_dynamic
                dynamic_file = self.STORAGE_FILES['unknown_dynamic']
                df_dynamic = pd.read_csv(dynamic_file)
                
                if row_index >= len(df_dynamic):
                    return False
                
                # Lấy record
                record = df_dynamic.iloc[row_index]
                
                # 2. Update label
                record[' Label'] = new_attack_label
                record['StoredAt'] = datetime.now().isoformat()
                
                # 3. Thêm vào known_attacks
                known_file = self.STORAGE_FILES['known_attacks']
                pd.DataFrame([record]).to_csv(known_file, mode='a', header=False, index=False)
                
                # 4. Xóa khỏi unknown_dynamic
                df_dynamic = df_dynamic.drop(row_index).reset_index(drop=True)
                df_dynamic.to_csv(dynamic_file, index=False)
                
                # 5. Update metadata
                self.metadata['total_records']['unknown_dynamic'] -= 1
                self.metadata['total_records']['known_attacks'] += 1
                
                if 'Unknown' in self.metadata['attack_types']:
                    self.metadata['attack_types']['Unknown'] -= 1
                if new_attack_label not in self.metadata['attack_types']:
                    self.metadata['attack_types'][new_attack_label] = 0
                self.metadata['attack_types'][new_attack_label] += 1
                
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                print(f"✅ Relabeled Unknown → {new_attack_label} (moved to Known Attacks)")
                return True
                
            except Exception as e:
                print(f"❌ Error relabeling: {e}")
                return False
    
    def find_row_by_flow_id(self, category: str, flow_id: str) -> int:
        """
        Tìm row index trong CSV file từ Flow ID
        
        Args:
            category: Category name
            flow_id: Flow ID to search for
            
        Returns:
            Row index nếu tìm thấy, None nếu không tìm thấy
        """
        try:
            if category not in self.STORAGE_FILES:
                return None
            
            filepath = self.STORAGE_FILES[category]
            df = pd.read_csv(filepath)
            
            # Search for Flow ID (column name has leading space)
            matches = df[df[' Flow ID'] == flow_id]
            
            if len(matches) > 0:
                return matches.index[0]
            
            return None
            
        except Exception as e:
            print(f"❌ Error finding row by Flow ID: {e}")
            return None
    
    def relabel_batch_unknown_to_known(self, row_indices: List[int], 
                                       new_attack_label: str) -> int:
        """
        Chuyển nhiều records từ Unknown Dynamic sang Known Attacks
        
        Returns:
            Số lượng records đã chuyển thành công
        """
        count = 0
        # Sort descending để xóa từ index cao xuống thấp (tránh lỗi index)
        for idx in sorted(row_indices, reverse=True):
            if self.relabel_unknown_to_known(idx, new_attack_label):
                count += 1
        return count
    
    # ==========================================
    # STATISTICS & UTILITIES
    # ==========================================
    
    def get_statistics(self) -> Dict:
        """Lấy thống kê tổng quan"""
        return {
            'total_records': self.metadata['total_records'],
            'attack_types': self.metadata['attack_types'],
            'last_updated': self.metadata['last_updated'],
            'storage_files': {
                category: os.path.getsize(filepath) if os.path.exists(filepath) else 0
                for category, filepath in self.STORAGE_FILES.items()
            }
        }
    
    def export_category(self, category: str, output_path: str, 
                       file_format: str = 'csv') -> bool:
        """
        Export dữ liệu ra file
        
        Args:
            category: Nhóm dữ liệu
            output_path: Đường dẫn file output
            file_format: 'csv', 'json', 'parquet'
            
        Returns:
            True nếu thành công
        """
        try:
            df = self.get_records(category)
            
            if file_format == 'csv':
                df.to_csv(output_path, index=False)
            elif file_format == 'json':
                df.to_json(output_path, orient='records', indent=2)
            elif file_format == 'parquet':
                df.to_parquet(output_path, index=False)
            else:
                return False
            
            print(f"✅ Exported {len(df)} records to {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error exporting: {e}")
            return False
    
    def clear_category(self, category: str) -> bool:
        """Xóa toàn bộ dữ liệu trong 1 category (CẨNH THẬN!)"""
        if category not in self.STORAGE_FILES:
            raise ValueError(f"Invalid category: {category}")
        
        with self.lock:
            try:
                filepath = self.STORAGE_FILES[category]
                
                # Tạo file mới với header
                df = pd.DataFrame(columns=self._get_csv_header())
                df.to_csv(filepath, index=False)
                
                # Reset metadata
                self.metadata['total_records'][category] = 0
                self.metadata['last_updated'] = datetime.now().isoformat()
                self._save_metadata(self.metadata)
                
                print(f"⚠️  Cleared all data in {category}")
                return True
                
            except Exception as e:
                print(f"❌ Error clearing category: {e}")
                return False


# Singleton instance
_storage_manager = None
_storage_lock = threading.Lock()

def get_storage_manager() -> DataStorageManager:
    """Get global storage manager instance (singleton)"""
    global _storage_manager
    with _storage_lock:
        if _storage_manager is None:
            _storage_manager = DataStorageManager()
        return _storage_manager

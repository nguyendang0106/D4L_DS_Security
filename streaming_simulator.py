"""
Streaming Data Simulator - Continuous data feed from rotating CSV files
Simulates real-time network traffic monitoring
"""
import glob
import csv
import time
import threading
from collections import deque
from typing import List, Dict, Any
import os

class StreamingDataSimulator:
    """
    Simulates continuous data stream by rotating through multiple CSV files.
    Reads batches and provides infinite data feed.
    """
    
    def __init__(self, data_folder: str = "data/2017/original", batch_size: int = 3000):
        """
        Initialize the streaming simulator
        
        Args:
            data_folder: Path to folder containing CSV files
            batch_size: Number of rows per batch
        """
        self.data_folder = data_folder
        self.batch_size = batch_size
        
        # Find all CSV files
        self.csv_files = sorted(glob.glob(os.path.join(data_folder, "*.csv")))
        if not self.csv_files:
            raise ValueError(f"No CSV files found in {data_folder}")
        
        print(f"📁 Found {len(self.csv_files)} CSV files:")
        for i, f in enumerate(self.csv_files, 1):
            print(f"   {i}. {os.path.basename(f)}")
        
        # State
        self.current_file_index = 0
        self.current_file_handle = None
        self.current_reader = None
        self.is_streaming = False
        self.total_rows_read = 0
        self.total_batches_served = 0
        
        # Buffer for batches (thread-safe queue)
        self.batch_buffer = deque(maxlen=10)  # Buffer up to 10 batches
        self.lock = threading.Lock()
        
    def _open_next_file(self):
        """Open the next CSV file in rotation"""
        # Close current file if open
        if self.current_file_handle:
            self.current_file_handle.close()
        
        # Get next file (circular)
        file_path = self.csv_files[self.current_file_index]
        print(f"📂 Opening file [{self.current_file_index + 1}/{len(self.csv_files)}]: {os.path.basename(file_path)}")
        
        # Open file
        self.current_file_handle = open(file_path, 'r', encoding='latin-1')
        self.current_reader = csv.reader(self.current_file_handle, skipinitialspace=True)
        
        # Skip header
        header = next(self.current_reader, None)
        if header:
            # Detect if has Label column
            self.has_label = len(header) == 85
        
        # Move to next file for next time (circular)
        self.current_file_index = (self.current_file_index + 1) % len(self.csv_files)
        
    def _read_batch(self) -> List[List[str]]:
        """
        Read one batch of rows from current file.
        Automatically rotates to next file when current one is exhausted.
        
        Returns:
            List of row strings (batch_size rows)
        """
        batch = []
        max_retries = 3
        retry_count = 0
        
        while len(batch) < self.batch_size:
            try:
                # Try to read from current file
                if self.current_reader is None or self.current_file_handle is None or self.current_file_handle.closed:
                    self._open_next_file()
                    retry_count = 0  # Reset retry count on new file
                
                row = next(self.current_reader)
                
                # Skip empty rows
                if not row or not any(field.strip() for field in row):
                    continue
                
                # Remove Label if present
                if self.has_label and len(row) == 85:
                    row = row[:-1]
                elif len(row) > 85:
                    row = row[:84]
                
                # Validate row
                if len(row) >= 84:
                    batch.append(row)
                    self.total_rows_read += 1
                    retry_count = 0  # Reset retry count on successful read
                    
            except StopIteration:
                # Current file exhausted, rotate to next
                print(f"✅ Finished reading file. Total rows read: {self.total_rows_read}")
                self._open_next_file()
                retry_count = 0
                continue
            except (OSError, IOError) as e:
                # File I/O error - reopen file
                print(f"⚠️  File I/O error: {e}. Reopening file...")
                retry_count += 1
                if retry_count >= max_retries:
                    print(f"❌ Max retries reached. Moving to next file.")
                    self._open_next_file()
                    retry_count = 0
                else:
                    # Try to reopen current file
                    try:
                        if self.current_file_handle and not self.current_file_handle.closed:
                            self.current_file_handle.close()
                    except:
                        pass
                    self.current_file_handle = None
                    self.current_reader = None
                continue
            except Exception as e:
                # Other errors - skip row and continue
                print(f"⚠️  Error reading row: {e}")
                retry_count += 1
                if retry_count >= max_retries:
                    print(f"❌ Max retries reached. Moving to next file.")
                    self._open_next_file()
                    retry_count = 0
                continue
        
        return batch
    
    def get_next_batch(self) -> Dict[str, Any]:
        """
        Get next batch of data (public API)
        
        Returns:
            Dictionary with batch data and metadata
        """
        with self.lock:
            batch = self._read_batch()
            self.total_batches_served += 1
            
            return {
                "batch_id": self.total_batches_served,
                "rows": batch,
                "batch_size": len(batch),
                "total_rows_read": self.total_rows_read,
                "current_file": os.path.basename(self.csv_files[(self.current_file_index - 1) % len(self.csv_files)]),
                "timestamp": time.time()
            }
    
    def start_streaming(self):
        """Start streaming (mark as active)"""
        self.is_streaming = True
        print(f"🚀 Streaming started with batch_size={self.batch_size}")
        print(f"♾️  Infinite loop: Will rotate through {len(self.csv_files)} files continuously")
    
    def stop_streaming(self):
        """Stop streaming"""
        self.is_streaming = False
        with self.lock:
            if self.current_file_handle:
                try:
                    self.current_file_handle.close()
                except:
                    pass
                self.current_file_handle = None
                self.current_reader = None
        print(f"⏸️  Streaming stopped. Total batches served: {self.total_batches_served}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get streaming statistics"""
        return {
            "is_streaming": self.is_streaming,
            "total_files": len(self.csv_files),
            "current_file_index": self.current_file_index,
            "total_rows_read": self.total_rows_read,
            "total_batches_served": self.total_batches_served,
            "batch_size": self.batch_size,
            "files": [os.path.basename(f) for f in self.csv_files]
        }


# Global simulator instance
_simulator_instance = None
_simulator_lock = threading.Lock()

def get_simulator(batch_size: int = 3000) -> StreamingDataSimulator:
    """Get or create global simulator instance (singleton)"""
    global _simulator_instance
    with _simulator_lock:
        if _simulator_instance is None or _simulator_instance.batch_size != batch_size:
            _simulator_instance = StreamingDataSimulator(batch_size=batch_size)
        return _simulator_instance

#!/usr/bin/env python3
"""
Test script to measure batch processing speed improvement
"""
import requests
import time
import sys

BASE_URL = "http://0.0.0.0:8000"

def test_batch_processing(batch_size=3000):
    """Test batch processing with specified batch size"""
    
    # Use a real CSV file
    csv_file_path = "data/2017/original/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    
    print(f"🧪 Testing batch processing with batch_size={batch_size}")
    print(f"📁 File: {csv_file_path}")
    
    # Check server config
    try:
        response = requests.get(f"{BASE_URL}/")
        config = response.json()
        print(f"⚙️  Server Config:")
        print(f"   - CPU cores: {config.get('parallel_processing', {}).get('cpu_count', 'N/A')}")
        print(f"   - Worker processes: {config.get('parallel_processing', {}).get('num_workers', 'N/A')}")
        print(f"   - Parallel processing: {'✅ Enabled' if config.get('parallel_processing', {}).get('enabled') else '❌ Disabled'}")
    except:
        print("⚠️  Could not fetch server config")
    
    print("=" * 70)
    
    # Step 1: Upload CSV
    print("\n1️⃣ Uploading CSV file...")
    with open(csv_file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(f"{BASE_URL}/upload_monitoring_csv", files=files)
    
    if response.status_code != 200:
        print(f"❌ Upload failed: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    total_lines = result['csv_rows_count']
    print(f"✅ Upload successful: {total_lines} rows")
    
    # Step 2: Start monitoring
    print("\n2️⃣ Starting monitoring session...")
    response = requests.post(f"{BASE_URL}/start_monitoring")
    if response.status_code != 200:
        print(f"❌ Start failed: {response.status_code}")
        return
    print("✅ Monitoring started")
    
    # Step 3: Process batches and measure time
    print(f"\n3️⃣ Processing batches (batch_size={batch_size})...")
    print("-" * 70)
    
    start_time = time.time()
    processed_count = 0
    batch_times = []
    
    while processed_count < total_lines:
        batch_start = time.time()
        
        response = requests.get(f"{BASE_URL}/get_monitoring_update?batch_size={batch_size}")
        
        if response.status_code != 200:
            print(f"❌ Processing failed: {response.status_code}")
            break
        
        result = response.json()
        batch_end = time.time()
        batch_time = batch_end - batch_start
        batch_times.append(batch_time)
        
        processed_count = result['processed_lines']
        progress = result.get('progress_percent', 0)
        batch_actual_size = result['batch_size']
        
        # Calculate throughput
        rows_per_sec = batch_actual_size / batch_time if batch_time > 0 else 0
        
        print(f"📊 Batch: {batch_actual_size:5d} rows | "
              f"Time: {batch_time:6.2f}s | "
              f"Speed: {rows_per_sec:7.1f} rows/s | "
              f"Progress: {progress:5.1f}%")
        
        if result['status'] == 'finished':
            break
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Summary
    print("=" * 70)
    print("\n📈 PERFORMANCE SUMMARY")
    print("-" * 70)
    print(f"Total rows processed:     {processed_count:,}")
    print(f"Total time:               {total_time:.2f} seconds")
    print(f"Average throughput:       {processed_count / total_time:.1f} rows/second")
    print(f"Average batch time:       {sum(batch_times) / len(batch_times):.2f} seconds")
    print(f"Fastest batch:            {min(batch_times):.2f} seconds")
    print(f"Slowest batch:            {max(batch_times):.2f} seconds")
    print("=" * 70)
    
    # Check for errors
    response = requests.get(f"{BASE_URL}/get_monitoring_update?batch_size=1")
    result = response.json()
    all_predictions = result.get('all_predictions', [])
    
    error_count = sum(1 for p in all_predictions if p.get('is_error', False))
    if error_count > 0:
        print(f"\n⚠️  {error_count} predictions had errors")
    else:
        print(f"\n✅ All {processed_count} predictions completed successfully!")
    
    # Show prediction distribution
    prediction_counts = {}
    for pred in all_predictions:
        label = pred.get('prediction', 'Unknown')
        prediction_counts[label] = prediction_counts.get(label, 0) + 1
    
    print("\n📊 PREDICTION DISTRIBUTION:")
    print("-" * 70)
    for label, count in sorted(prediction_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / processed_count) * 100
        print(f"{label:30s}: {count:7,} ({percentage:5.2f}%)")
    print("=" * 70)


if __name__ == "__main__":
    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    test_batch_processing(batch_size)

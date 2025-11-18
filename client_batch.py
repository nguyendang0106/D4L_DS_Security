import requests
import time
import json

# Configuration
API_URL = "http://127.0.0.1:8000"
BATCH_SIZE = 4000  # Process 4000 rows per request

# CSV file path (with 85 columns including Label)
CSV_FILE = "data/2017/original/Monday-WorkingHours.pcap_ISCX.csv"

print("="*60)
print(" NIDS Batch Processing Client")
print("="*60)

# Method 1: Complete batch processing (process all at once)
def test_complete_batch():
    print("\n Method 1: Complete Batch Processing")
    print("-" * 60)
    
    with open(CSV_FILE, 'rb') as f:
        files = {'file': (CSV_FILE.split('/')[-1], f, 'text/csv')}
        params = {'batch_size': BATCH_SIZE}
        
        print(f" Uploading and processing: {CSV_FILE}")
        print(f"   Batch size: {BATCH_SIZE} rows per batch")
        
        start_time = time.time()
        response = requests.post(
            f"{API_URL}/predict_batch",
            files=files,
            params=params,
            timeout=300
        )
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n Processing completed in {elapsed:.2f}s")
            print(f"   Total rows: {result['total_rows']}")
            print(f"   Processed: {result['summary']['total_processed']}")
            print(f"   Errors: {result['summary']['errors']}")
            print(f"\n Prediction Distribution:")
            for label, count in result['summary']['prediction_distribution'].items():
                percentage = (count / result['total_rows']) * 100
                print(f"   {label:20s}: {count:6d} ({percentage:5.2f}%)")
            
            # Show sample predictions
            print(f"\n📋 Sample Predictions (first 10):")
            for pred in result['predictions'][:10]:
                status = "❌" if pred['is_error'] else "✅"
                print(f"   {status} Row {pred['line_index']:5d}: {pred['prediction']}")
            
            return result
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"   {response.text}")
            return None


# Method 2: Streaming batch processing (real-time updates)
def test_streaming_batch():
    print("\n🔄 Method 2: Streaming Batch Processing (Real-time)")
    print("-" * 60)
    
    # Step 1: Upload CSV
    with open(CSV_FILE, 'rb') as f:
        files = {'file': (CSV_FILE.split('/')[-1], f, 'text/csv')}
        print(f"📤 Uploading: {CSV_FILE}")
        response = requests.post(f"{API_URL}/upload_monitoring_csv", files=files)
        
        if response.status_code != 200:
            print(f"❌ Upload failed: {response.text}")
            return
        
        upload_result = response.json()
        print(f"✅ Upload successful!")
        print(f"   File: {upload_result['fileName']}")
        print(f"   Total rows: {upload_result['rowCount']}")
        print(f"   Has Label: {upload_result['hasLabel']}")
    
    # Step 2: Start monitoring
    print(f"\n▶️  Starting batch processing...")
    response = requests.post(f"{API_URL}/start_monitoring")
    if response.status_code != 200:
        print(f"❌ Start failed: {response.text}")
        return
    
    # Step 3: Process in batches with real-time updates
    start_time = time.time()
    prediction_counts = {}
    total_processed = 0
    
    while True:
        response = requests.get(
            f"{API_URL}/get_monitoring_update",
            params={'batch_size': BATCH_SIZE}
        )
        
        if response.status_code != 200:
            print(f"❌ Error: {response.text}")
            break
        
        result = response.json()
        
        if result['status'] == 'idle':
            print("⏸️  System is idle")
            break
        elif result['status'] == 'finished':
            print(f"\n✅ Processing completed!")
            break
        
        # Update statistics
        batch = result['latest_predictions']
        for pred in batch:
            if not pred['is_error']:
                label = pred['prediction']
                prediction_counts[label] = prediction_counts.get(label, 0) + 1
        
        total_processed = result['processed_lines']
        progress = result['progress_percent']
        
        # Real-time progress update
        print(f"⏳ Progress: {progress:6.2f}% ({total_processed}/{result['total_lines']}) - "
              f"Batch: {result['batch_size']} rows", end='\r')
        
        time.sleep(0.1)  # Small delay to avoid overwhelming the server
    
    elapsed = time.time() - start_time
    
    print(f"\n\n⏱️  Total time: {elapsed:.2f}s")
    print(f"   Throughput: {total_processed/elapsed:.0f} rows/second")
    print(f"\n📊 Prediction Distribution:")
    for label, count in prediction_counts.items():
        percentage = (count / total_processed) * 100 if total_processed > 0 else 0
        print(f"   {label:20s}: {count:6d} ({percentage:5.2f}%)")


# Main
if __name__ == "__main__":
    try:
        print(f"\n🎯 Select processing method:")
        print("   1. Complete Batch (process all at once)")
        print("   2. Streaming Batch (real-time updates)")
        
        choice = input("\nEnter choice (1 or 2, default=2): ").strip() or "2"
        
        if choice == "1":
            test_complete_batch()
        else:
            test_streaming_batch()
            
    except KeyboardInterrupt:
        print("\n\n⏹️  Processing interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*60)
    print("✨ Done!")
    print("="*60)

#!/usr/bin/env python3
"""
Test Streaming Mode - Continuous data feed simulation
Simulates real-time network traffic monitoring dashboard
"""
import requests
import time
import sys
from collections import defaultdict

BASE_URL = "http://0.0.0.0:8000"

def test_streaming_mode(batch_size=3000, num_batches=20, delay=0.5):
    """
    Test continuous streaming mode
    
    Args:
        batch_size: Rows per batch
        num_batches: Number of batches to fetch
        delay: Delay between batches (seconds) to simulate real-time
    """
    print("=" * 80)
    print("🌊 CONTINUOUS STREAMING MODE TEST")
    print("=" * 80)
    print(f"\n⚙️  Configuration:")
    print(f"   Batch size:        {batch_size:,} rows")
    print(f"   Batches to fetch:  {num_batches}")
    print(f"   Delay per batch:   {delay}s")
    print(f"   Total rows:        ~{batch_size * num_batches:,}")
    
    # Step 1: Start streaming
    print(f"\n1️⃣ Starting streaming...")
    response = requests.post(f"{BASE_URL}/streaming/start?batch_size={batch_size}")
    
    if response.status_code != 200:
        print(f"❌ Failed to start streaming: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    print(f"✅ Streaming started")
    print(f"   Mode: {result['mode']}")
    print(f"   Files in rotation: {result['total_files']}")
    for i, file in enumerate(result['files'], 1):
        print(f"      {i}. {file}")
    
    # Step 2: Fetch batches continuously
    print(f"\n2️⃣ Fetching batches (simulating real-time dashboard)...")
    print("-" * 80)
    
    total_predictions = defaultdict(int)
    total_rows = 0
    batch_times = []
    files_seen = set()
    
    start_time = time.time()
    
    for batch_num in range(num_batches):
        batch_start = time.time()
        
        response = requests.get(f"{BASE_URL}/streaming/next_batch")
        
        if response.status_code != 200:
            print(f"❌ Batch {batch_num + 1} failed: {response.status_code}")
            break
        
        result = response.json()
        batch_end = time.time()
        batch_time = batch_end - batch_start
        batch_times.append(batch_time)
        
        # Update statistics
        batch_id = result['batch_id']
        current_file = result['current_file']
        files_seen.add(current_file)
        
        summary = result['summary']
        total_rows += summary['total_predicted']
        
        for label, count in summary['prediction_distribution'].items():
            total_predictions[label] += count
        
        # Display progress
        rows_per_sec = summary['total_predicted'] / batch_time if batch_time > 0 else 0
        
        print(f"Batch {batch_id:3d} | "
              f"File: {current_file:50s} | "
              f"{summary['total_predicted']:5,} rows | "
              f"{batch_time:5.2f}s | "
              f"{rows_per_sec:7.1f} rows/s")
        
        # Show prediction distribution for this batch
        if batch_num % 5 == 0:  # Every 5 batches
            print(f"   Current distribution: {dict(summary['prediction_distribution'])}")
        
        # Simulate real-time delay
        time.sleep(delay)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Step 3: Stop streaming
    print(f"\n3️⃣ Stopping streaming...")
    response = requests.post(f"{BASE_URL}/streaming/stop")
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Streaming stopped")
    
    # Display summary
    print("\n" + "=" * 80)
    print("📊 STREAMING SESSION SUMMARY")
    print("=" * 80)
    
    print(f"\n⏱️  PERFORMANCE:")
    print(f"   Total time:            {total_time:.2f} seconds")
    print(f"   Total rows processed:  {total_rows:,}")
    print(f"   Average throughput:    {total_rows / total_time:,.1f} rows/second")
    print(f"   Average batch time:    {sum(batch_times) / len(batch_times):.3f} seconds")
    print(f"   Fastest batch:         {min(batch_times):.3f} seconds")
    print(f"   Slowest batch:         {max(batch_times):.3f} seconds")
    
    print(f"\n🔄 FILE ROTATION:")
    print(f"   Unique files accessed: {len(files_seen)}")
    for file in sorted(files_seen):
        print(f"      • {file}")
    
    print(f"\n🎯 PREDICTION DISTRIBUTION:")
    print("-" * 80)
    sorted_predictions = sorted(total_predictions.items(), key=lambda x: x[1], reverse=True)
    for label, count in sorted_predictions:
        percentage = (count / total_rows) * 100 if total_rows > 0 else 0
        bar = "█" * int(percentage / 2)
        print(f"{label:30s}: {count:7,} ({percentage:5.2f}%) {bar}")
    
    print("=" * 80)
    
    # Step 4: Get final stats
    response = requests.get(f"{BASE_URL}/streaming/stats")
    if response.status_code == 200:
        stats = response.json()
        print(f"\n📈 FINAL STATISTICS:")
        print(f"   Total batches served:  {stats['total_batches_served']}")
        print(f"   Total rows read:       {stats['total_rows_read']:,}")
        print(f"   Files in rotation:     {stats['total_files']}")
    
    print("\n✅ Streaming test completed!")
    print("=" * 80)


def test_continuous_mode(duration_seconds=30, batch_size=3000):
    """
    Test truly continuous mode for a specific duration
    Simulates live dashboard that runs indefinitely
    
    Args:
        duration_seconds: How long to run
        batch_size: Rows per batch
    """
    print("=" * 80)
    print("♾️  INFINITE STREAMING MODE (Time-limited test)")
    print("=" * 80)
    print(f"\n⚙️  Configuration:")
    print(f"   Duration:     {duration_seconds} seconds")
    print(f"   Batch size:   {batch_size:,} rows")
    print(f"   Mode:         Continuous (will stop after {duration_seconds}s)")
    
    # Start streaming
    print(f"\n🚀 Starting infinite stream...")
    response = requests.post(f"{BASE_URL}/streaming/start?batch_size={batch_size}")
    if response.status_code != 200:
        print(f"❌ Failed to start")
        return
    
    print("✅ Stream active - fetching batches continuously...")
    print("-" * 80)
    
    start_time = time.time()
    batch_count = 0
    total_rows = 0
    
    try:
        while time.time() - start_time < duration_seconds:
            response = requests.get(f"{BASE_URL}/streaming/next_batch")
            
            if response.status_code == 200:
                result = response.json()
                batch_count += 1
                total_rows += result['summary']['total_predicted']
                
                elapsed = time.time() - start_time
                throughput = total_rows / elapsed
                
                print(f"[{elapsed:5.1f}s] Batch {batch_count:3d} | "
                      f"{result['current_file']:50s} | "
                      f"Avg: {throughput:7.1f} rows/s", 
                      end='\r', flush=True)
            
            time.sleep(0.1)  # Small delay to avoid hammering
    
    except KeyboardInterrupt:
        print("\n\n⏸️  Interrupted by user")
    
    # Stop
    print(f"\n\n⏹️  Stopping after {duration_seconds}s...")
    requests.post(f"{BASE_URL}/streaming/stop")
    
    actual_time = time.time() - start_time
    print(f"\n📊 RESULTS:")
    print(f"   Duration:       {actual_time:.1f} seconds")
    print(f"   Batches:        {batch_count}")
    print(f"   Total rows:     {total_rows:,}")
    print(f"   Avg throughput: {total_rows / actual_time:,.1f} rows/second")
    print("=" * 80)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "continuous":
        # Continuous mode
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        batch_size = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
        test_continuous_mode(duration, batch_size)
    else:
        # Batch mode
        batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
        num_batches = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
        test_streaming_mode(batch_size, num_batches, delay)

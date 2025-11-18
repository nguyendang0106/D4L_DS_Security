import requests
import json

# Configuration
API_URL = "http://127.0.0.1:8000/predict"
N_RAW_FEATURES = 84  # Expected by server (84 features, excluding Label)

# Sample data: 84 features from CICIDS 2017 dataset (Monday-WorkingHours.pcap_ISCX.csv)
# Real benign network flow data
sample_features = [
    0.0, 0.0, 80.0, 0.0, 49188.0, 6.0, 0.0, 4.0, 2.0, 0.0,
    12.0, 0.0, 6.0, 6.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    3000000.0, 500000.0, 4.0, 0.0, 4.0, 4.0, 4.0, 4.0, 0.0, 4.0,
    4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    40.0, 0.0, 500000.0, 0.0, 6.0, 6.0, 6.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 9.0, 6.0,
    0.0, 40.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 12.0,
    0.0, 0.0, 329.0, -1.0, 1.0, 20.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0
]

# Verify feature count
if len(sample_features) != N_RAW_FEATURES:
    print(f"⚠️  Warning: Sample data has {len(sample_features)} features, expected {N_RAW_FEATURES}")
    print("   Adjusting to match expected count...")
    
    if len(sample_features) < N_RAW_FEATURES:
        # Pad with zeros
        sample_features.extend([0.0] * (N_RAW_FEATURES - len(sample_features)))
    else:
        # Truncate
        sample_features = sample_features[:N_RAW_FEATURES]

print(f"📊 Sending {len(sample_features)} features to API...")

# Prepare request
data_to_send = {"features": sample_features}

try:
    # Send request
    response = requests.post(API_URL, json=data_to_send, timeout=10)
    response.raise_for_status()
    
    # Parse response
    result = response.json()
    
    # Display results
    print("\n✅ Prediction successful!")
    print("=" * 50)
    print(f"🎯 Prediction: {result['prediction']}")
    print(f"📥 Raw features: {result.get('raw_features_count', 'N/A')}")
    print(f"🔧 Processed features: {result.get('processed_features_count', 'N/A')}")
    print("=" * 50)

except requests.exceptions.HTTPError as http_err:
    print(f"\n❌ HTTP error occurred: {http_err}")
    print(f"   Response: {response.text}")
except requests.exceptions.ConnectionError as conn_err:
    print(f"\n❌ Connection error: {conn_err}")
    print("   Is the server running? Start with: uvicorn server:app --host 0.0.0.0 --port 8000")
except requests.exceptions.Timeout as timeout_err:
    print(f"\n❌ Timeout error: {timeout_err}")
except requests.exceptions.RequestException as req_err:
    print(f"\n❌ Request error: {req_err}")
except json.JSONDecodeError:
    print("\n❌ Error decoding JSON response")
    print(f"   Raw response: {response.text}")

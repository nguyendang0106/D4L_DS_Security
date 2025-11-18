import asyncio
import csv
import io
import os
import pickle
from typing import List, Dict, Any
from datetime import datetime
import warnings
import numpy as np
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from functools import partial
import multiprocessing
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Import streaming simulator
from streaming_simulator import get_simulator

# Import data storage manager
from data_storage_manager import get_storage_manager

# Suppress sklearn warnings
warnings.filterwarnings('ignore')

# --- Configuration & Model Paths ---
MODEL_DIR = "model/"
STAGE1_SCALER_PATH = os.path.join(MODEL_DIR, "scaler_ae_normal_stage1.p")
STAGE1_MODEL_PATH = os.path.join(MODEL_DIR, "ocsvm_model_100k_stage1.p")
STAGE2_SCALER_PATH = os.path.join(MODEL_DIR, "scaler_stage2_normal_stage2.p")
STAGE2_MODEL_PATH = os.path.join(MODEL_DIR, "sota_stage2.p")

# Expected features: raw data has 85 columns (84 features + 1 Label)
# After cleaning: drop 24 columns (IPs, ports, Flow ID, zero-variance, bulk features, duplicate) → ~70 features
# Before training: drop Label, Timestamp, Destination Port → 67 features
N_RAW_FEATURES = 84  # Input from user (85 columns - Label column)
N_PROCESSED_FEATURES = 67  # Features for model

# Raw feature names (84 features, excluding Label)
RAW_FEATURE_NAMES = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min"
]

# Columns to drop during preprocessing (17 columns based on d4l-ds-security-data-kaggle.ipynb + training drops)
DROP_COLUMN_NAMES = {
    # Dataset Specific Information
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    # Features Without Observed Variance
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count",
    # Bulk features (6 columns)
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    # Duplicate Column
    "Fwd Header Length.1",
    # Training drops
    "Timestamp"
}

# Thresholds from training notebook
TAU_B = -0.0045741559351979745  # Stage 1: Benign threshold (F9 100k)
TAU_M = 0.93  # Stage 2: Multi-class confidence threshold
TAU_U = 0.0029087824072017237  # Stage 3: Unknown threshold (0.99 100k)

# CPU configuration for parallel processing
NUM_WORKERS = max(1, multiprocessing.cpu_count() - 1)  # Leave 1 core for system
print(f" Parallel processing enabled: {NUM_WORKERS} worker processes")

app = FastAPI()

# --- Global In-Memory Store for Monitoring ---
monitoring_data_store: Dict[str, Any] = {
    "csv_rows": [],
    "predictions": [],
    "current_index": 0,
    "is_active": False,
    "file_name": None,
    "total_lines": 0
}

# --- Model Loading ---
stage1_scaler_g = None
stage1_model_g = None
stage2_scaler_g = None
stage2_model_g = None

def load_all_models():
    """Load all required models and scalers"""
    global stage1_scaler_g, stage1_model_g, stage2_scaler_g, stage2_model_g
    try:
        with open(STAGE1_SCALER_PATH, "rb") as f:
            stage1_scaler_g = pickle.load(f)
        with open(STAGE1_MODEL_PATH, "rb") as f:
            stage1_model_g = pickle.load(f)
        with open(STAGE2_SCALER_PATH, "rb") as f:
            stage2_scaler_g = pickle.load(f)
        with open(STAGE2_MODEL_PATH, "rb") as f:
            stage2_model_g = pickle.load(f)
        print("[OK] All models loaded successfully!")
        print(f"   - Stage 1 OCSVM: {STAGE1_MODEL_PATH}")
        print(f"   - Stage 1 Scaler: {STAGE1_SCALER_PATH}")
        print(f"   - Stage 2 RF: {STAGE2_MODEL_PATH}")
        print(f"   - Stage 2 Scaler: {STAGE2_SCALER_PATH}")
    except Exception as e:
        print(f"[FAIL] Error loading models: {e}")
        raise RuntimeError(f"Could not load models: {e}")

@app.on_event("startup")
async def startup_event():
    load_all_models()

# --- Enable CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "null"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Preprocessing Function ---
def preprocess_raw_features(raw_features: List[float]) -> List[float]:
    """
    Convert 84 raw features to 67 processed features by dropping columns
    
    Process:
    1. Drop dataset-specific columns (Flow ID, IPs, Ports)
    2. Drop zero-variance features (PSH/URG flags, CWE flag)
    3. Drop bulk features (6 columns)
    4. Drop duplicate column (Fwd Header Length.1)
    5. Drop Timestamp
    
    Input: 84 raw features (excluding Label)
    Output: 67 processed features
    """
    if len(raw_features) != N_RAW_FEATURES:
        raise ValueError(f"Expected {N_RAW_FEATURES} features, got {len(raw_features)}")
    
    # Handle inf and nan values
    raw_features = [0.0 if not np.isfinite(x) else x for x in raw_features]
    
    # Create mapping from feature name to value
    feature_dict = dict(zip(RAW_FEATURE_NAMES, raw_features))
    
    # Remove columns that should be dropped
    processed_features = [
        value for name, value in feature_dict.items()
        if name not in DROP_COLUMN_NAMES
    ]
    
    if len(processed_features) != N_PROCESSED_FEATURES:
        raise ValueError(
            f"After preprocessing, expected {N_PROCESSED_FEATURES} features, "
            f"got {len(processed_features)}"
        )
    
    return processed_features


def preprocess_raw_features_batch(raw_features_batch: np.ndarray) -> np.ndarray:
    """
    Vectorized batch preprocessing - converts multiple rows at once.
    Much faster than looping through preprocess_raw_features().
    
    Input: numpy array of shape (n_samples, 84)
    Output: numpy array of shape (n_samples, 67)
    """
    if raw_features_batch.shape[1] != N_RAW_FEATURES:
        raise ValueError(f"Expected {N_RAW_FEATURES} features, got {raw_features_batch.shape[1]}")
    
    # Handle inf and nan values (replace with 0)
    raw_features_batch = np.nan_to_num(raw_features_batch, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Get indices of columns to keep (not in DROP_COLUMN_NAMES)
    keep_indices = [
        i for i, name in enumerate(RAW_FEATURE_NAMES)
        if name not in DROP_COLUMN_NAMES
    ]
    
    # Select only the columns we want to keep
    processed_batch = raw_features_batch[:, keep_indices]
    
    if processed_batch.shape[1] != N_PROCESSED_FEATURES:
        raise ValueError(
            f"After preprocessing, expected {N_PROCESSED_FEATURES} features, "
            f"got {processed_batch.shape[1]}"
        )
    
    return processed_batch

# --- Core Prediction Logic ---
def run_prediction_pipeline(features: List[float]) -> str:
    """
    Processes a single feature vector through the 3-stage pipeline.
    
    Stage 1 (OCSVM): Anomaly Detection
        - Input: 67 features
        - Output: anomaly_score
        - If score < TAU_B → "Benign" (END)
        - Else → "Attack", proceed to Stage 2
    
    Stage 2 (Random Forest): Multi-class Classification
        - Input: 68 features (67 + anomaly_score)
        - Output: attack_type with confidence
        - If confidence > TAU_M → Return attack_type (END)
        - Else → "Unknown", proceed to Stage 3
    
    Stage 3 (Zero-day Detection): Re-evaluate Unknown
        - Input: anomaly_score from Stage 1
        - If score < TAU_U → "Benign" (END)
        - Else → "Unknown" (END)
    """
    if not all([stage1_scaler_g, stage1_model_g, stage2_scaler_g, stage2_model_g]):
        raise RuntimeError("Models not loaded. Cannot perform prediction.")

    x_input_np = np.array([features])  # Model expects 2D array

    try:
        # --- Stage 1: Anomaly Detection (OCSVM) ---
        x_scaled_for_stage1 = stage1_scaler_g.transform(x_input_np)
        # decision_function returns scores; negative of score gives anomaly score
        proba_1_score_array = -stage1_model_g.decision_function(x_scaled_for_stage1)
        proba_1_score_single = proba_1_score_array[0]

        # Check if benign
        if proba_1_score_single < TAU_B:
            return "Benign"
        
        # If not benign, it's an attack → proceed to Stage 2
        # --- Stage 2: Multi-class Classification (RandomForest) ---
        x_attack_scaled_for_stage2 = stage2_scaler_g.transform(x_input_np)
        
        # Add anomaly score as extra feature
        input_for_stage2 = np.column_stack((
            x_attack_scaled_for_stage2,
            proba_1_score_array.reshape(-1, 1)
        ))
        
        # Get probabilities for all classes
        proba_2_raw_all_classes = stage2_model_g.predict_proba(input_for_stage2)[0]
        max_proba_stage2 = np.max(proba_2_raw_all_classes)
        argmax_idx_stage2 = np.argmax(proba_2_raw_all_classes)
        
        # Check confidence
        if max_proba_stage2 > TAU_M:
            # High confidence → return attack type
            return stage2_model_g.classes_[argmax_idx_stage2]
        
        # Low confidence → Unknown, proceed to Stage 3
        # --- Stage 3: Zero-Day Detection ---
        if proba_1_score_single < TAU_U:
            return "Benign"
        else:
            return "Unknown"

    except Exception as e:
        print(f"Error during prediction pipeline: {e}")
        import traceback
        traceback.print_exc()
        return f"Error: Prediction failed ({str(e)})"


def run_prediction_pipeline_batch(features_batch: np.ndarray) -> List[str]:
    """
    VECTORIZED batch prediction - processes multiple samples at once.
    Much faster than looping through run_prediction_pipeline().
    
    Input: numpy array of shape (n_samples, 67)
    Output: list of prediction labels (length n_samples)
    
    Pipeline:
    Stage 1: OCSVM for all samples → anomaly scores
    Stage 2: RF for "Attack" samples → attack types
    Stage 3: Zero-day for "Unknown" samples → final labels
    """
    if not all([stage1_scaler_g, stage1_model_g, stage2_scaler_g, stage2_model_g]):
        raise RuntimeError("Models not loaded. Cannot perform prediction.")
    
    n_samples = features_batch.shape[0]
    predictions = [""] * n_samples  # Initialize results
    
    try:
        # --- Stage 1: OCSVM Anomaly Detection (ALL samples) ---
        x_scaled_stage1 = stage1_scaler_g.transform(features_batch)
        anomaly_scores = -stage1_model_g.decision_function(x_scaled_stage1)  # Shape: (n_samples,)
        
        # Classify: score < TAU_B → Benign, else → Attack (go to Stage 2)
        benign_mask = anomaly_scores < TAU_B
        attack_mask = ~benign_mask
        
        # Set Benign predictions
        for idx in np.where(benign_mask)[0]:
            predictions[idx] = "Benign"
        
        # --- Stage 2: Random Forest (Attack samples only) ---
        attack_indices = np.where(attack_mask)[0]
        if len(attack_indices) > 0:
            attack_features = features_batch[attack_indices]
            attack_anomaly_scores = anomaly_scores[attack_indices].reshape(-1, 1)
            
            # Scale and add anomaly score
            x_scaled_stage2 = stage2_scaler_g.transform(attack_features)
            input_stage2 = np.column_stack((x_scaled_stage2, attack_anomaly_scores))
            
            # Get predictions and probabilities
            proba_stage2 = stage2_model_g.predict_proba(input_stage2)  # Shape: (n_attack, n_classes)
            max_proba = np.max(proba_stage2, axis=1)  # Max probability per sample
            predicted_classes = stage2_model_g.classes_[np.argmax(proba_stage2, axis=1)]
            
            # High confidence → attack type, Low confidence → Unknown (go to Stage 3)
            confident_mask = max_proba > TAU_M
            unknown_mask = ~confident_mask
            
            # Set confident attack predictions
            for i, idx in enumerate(attack_indices):
                if confident_mask[i]:
                    predictions[idx] = predicted_classes[i]
            
            # --- Stage 3: Zero-day Detection (Unknown samples only) ---
            unknown_indices = attack_indices[unknown_mask]
            if len(unknown_indices) > 0:
                unknown_anomaly_scores = anomaly_scores[unknown_indices]
                
                # Re-classify: score < TAU_U → Benign, else → Unknown
                for i, idx in enumerate(unknown_indices):
                    if unknown_anomaly_scores[i] < TAU_U:
                        predictions[idx] = "Benign"
                    else:
                        predictions[idx] = "Unknown"
        
        return predictions
        
    except Exception as e:
        print(f"Error during batch prediction: {e}")
        import traceback
        traceback.print_exc()
        # Return error for all samples
        return [f"Error: Prediction failed ({str(e)})"] * n_samples


# --- Parallel Processing Helper ---
def _predict_chunk_worker(chunk_data: tuple) -> List[str]:
    """
    Worker function for parallel processing.
    Processes a chunk of features through the prediction pipeline.
    
    Args:
        chunk_data: tuple of (features_array, model_paths_dict)
        
    Returns:
        List of prediction labels for the chunk
    """
    features_chunk, model_paths = chunk_data
    
    # Load models in worker process (each worker needs its own copy)
    try:
        with open(model_paths['stage1_scaler'], 'rb') as f:
            stage1_scaler = pickle.load(f)
        with open(model_paths['stage1_model'], 'rb') as f:
            stage1_model = pickle.load(f)
        with open(model_paths['stage2_scaler'], 'rb') as f:
            stage2_scaler = pickle.load(f)
        with open(model_paths['stage2_model'], 'rb') as f:
            stage2_model = pickle.load(f)
    except Exception as e:
        return [f"Error: Model loading failed ({str(e)})"] * len(features_chunk)
    
    # Run prediction pipeline for this chunk
    n_samples = features_chunk.shape[0]
    predictions = [""] * n_samples
    
    try:
        # Stage 1: OCSVM
        x_scaled_stage1 = stage1_scaler.transform(features_chunk)
        anomaly_scores = -stage1_model.decision_function(x_scaled_stage1)
        
        benign_mask = anomaly_scores < TAU_B
        attack_mask = ~benign_mask
        
        for idx in np.where(benign_mask)[0]:
            predictions[idx] = "Benign"
        
        # Stage 2: Random Forest (Attack samples)
        attack_indices = np.where(attack_mask)[0]
        if len(attack_indices) > 0:
            attack_features = features_chunk[attack_indices]
            attack_anomaly_scores = anomaly_scores[attack_indices].reshape(-1, 1)
            
            x_scaled_stage2 = stage2_scaler.transform(attack_features)
            input_stage2 = np.column_stack((x_scaled_stage2, attack_anomaly_scores))
            
            proba_stage2 = stage2_model.predict_proba(input_stage2)
            max_proba = np.max(proba_stage2, axis=1)
            predicted_classes = stage2_model.classes_[np.argmax(proba_stage2, axis=1)]
            
            confident_mask = max_proba > TAU_M
            unknown_mask = ~confident_mask
            
            for i, idx in enumerate(attack_indices):
                if confident_mask[i]:
                    predictions[idx] = predicted_classes[i]
            
            # Stage 3: Zero-day detection
            unknown_indices = attack_indices[unknown_mask]
            if len(unknown_indices) > 0:
                unknown_anomaly_scores = anomaly_scores[unknown_indices]
                for i, idx in enumerate(unknown_indices):
                    if unknown_anomaly_scores[i] < TAU_U:
                        predictions[idx] = "Benign"
                    else:
                        predictions[idx] = "Unknown"
        
        return predictions
        
    except Exception as e:
        return [f"Error: Prediction failed ({str(e)})"] * n_samples


def run_prediction_pipeline_batch_parallel(features_batch: np.ndarray, num_workers: int = None) -> List[str]:
    """
    PARALLEL batch prediction - splits batch across multiple CPU cores.
    Much faster than sequential batch processing for large batches.
    
    Args:
        features_batch: numpy array of shape (n_samples, 67)
        num_workers: number of parallel workers (default: NUM_WORKERS)
        
    Returns:
        list of prediction labels (length n_samples)
    """
    if num_workers is None:
        num_workers = NUM_WORKERS
    
    n_samples = features_batch.shape[0]
    
    # If batch is too small, use sequential processing
    if n_samples < num_workers * 100:  # Less than 100 samples per worker
        return run_prediction_pipeline_batch(features_batch)
    
    # Split batch into chunks for parallel processing
    chunk_size = max(1, n_samples // num_workers)
    chunks = []
    for i in range(0, n_samples, chunk_size):
        chunk = features_batch[i:i + chunk_size]
        chunks.append(chunk)
    
    # Prepare model paths for workers
    model_paths = {
        'stage1_scaler': STAGE1_SCALER_PATH,
        'stage1_model': STAGE1_MODEL_PATH,
        'stage2_scaler': STAGE2_SCALER_PATH,
        'stage2_model': STAGE2_MODEL_PATH
    }
    
    # Create worker data (chunk, model_paths)
    worker_data = [(chunk, model_paths) for chunk in chunks]
    
    # Process chunks in parallel
    try:
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            chunk_results = list(executor.map(_predict_chunk_worker, worker_data))
        
        # Combine results from all chunks
        all_predictions = []
        for chunk_result in chunk_results:
            all_predictions.extend(chunk_result)
        
        return all_predictions
        
    except Exception as e:
        print(f"Parallel processing failed, falling back to sequential: {e}")
        return run_prediction_pipeline_batch(features_batch)

# --- API Endpoints ---
@app.get("/")
async def root():
    """Health check endpoint"""
    model_status = "loaded" if all([stage1_scaler_g, stage1_model_g, stage2_scaler_g, stage2_model_g]) else "not loaded"
    return {
        "message": "Network Intrusion Detection System API",
        "model_status": model_status,
        "parallel_processing": {
            "enabled": True,
            "num_workers": NUM_WORKERS,
            "cpu_count": multiprocessing.cpu_count()
        },
        "expected_raw_features": N_RAW_FEATURES,
        "processed_features": N_PROCESSED_FEATURES,
        "stages": {
            "stage1": "OCSVM Anomaly Detection (Benign vs Attack)",
            "stage2": "Random Forest Multi-class Classification",
            "stage3": "Zero-day Detection (Unknown vs Benign)"
        }
    }

class InputData(BaseModel):
    features: List[float] = Field(
        ..., 
        example=[0.1] * N_RAW_FEATURES,
        description=f"List of {N_RAW_FEATURES} raw feature values (84 features, excluding Label)"
    )

@app.post("/predict")
async def predict_manual_input(item: InputData):
    """
    Single prediction endpoint
    
    Input: 84 raw features (from original CSV, excluding Label column)
    Output: Cyber attack classification
    """
    if len(item.features) != N_RAW_FEATURES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid input. Expected {N_RAW_FEATURES} features, got {len(item.features)}"
        )
    try:
        # Preprocess: 84 → 67 features
        processed_features = preprocess_raw_features(item.features)
        
        # Run 3-stage pipeline
        prediction = run_prediction_pipeline(processed_features)
        
        return {
            "prediction": prediction,
            "raw_features_count": len(item.features),
            "processed_features_count": len(processed_features)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload_monitoring_csv")
async def upload_csv_for_monitoring(file: UploadFile = File(...)):
    """
    Upload CSV file for batch monitoring
    
    Supports:
    - CSV with 84 features (no Label)
    - CSV with 85 features (84 + Label) - Label will be removed automatically
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a CSV file.")

    contents = await file.read()
    
    # Reset monitoring state
    monitoring_data_store["csv_rows"] = []
    monitoring_data_store["predictions"] = []
    monitoring_data_store["current_index"] = 0
    monitoring_data_store["is_active"] = False
    monitoring_data_store["file_name"] = file.filename
    monitoring_data_store["total_lines"] = 0

    try:
        buffer = io.StringIO(contents.decode())
        reader = csv.reader(buffer, skipinitialspace=True)
        header = next(reader, None)  # Skip header
        
        # Detect if CSV has Label column (85 columns) or not (84 columns)
        has_label = len(header) == 85 if header else False
        print(f"📊 CSV uploaded: {file.filename}")
        print(f"   Columns detected: {len(header) if header else 'unknown'}")
        print(f"   Has Label column: {has_label}")

        row_count = 0
        for row_strings in reader:
            if not row_strings or not any(field.strip() for field in row_strings):
                continue
                
            # Remove Label column if present (last column)
            if has_label and len(row_strings) == 85:
                row_strings = row_strings[:-1]  # Remove last column (Label)
            elif len(row_strings) > 85:
                # CSV might have extra columns, truncate to 84
                row_strings = row_strings[:84]
            
            # Make sure we have 84 columns
            if len(row_strings) < 84:
                continue
                
            monitoring_data_store["csv_rows"].append(row_strings)
            row_count += 1
        
        monitoring_data_store["total_lines"] = len(monitoring_data_store["csv_rows"])
        if monitoring_data_store["total_lines"] == 0:
            raise HTTPException(status_code=400, detail="CSV file is empty or contains no valid data rows.")

        print(f"✅ Upload complete: {monitoring_data_store['total_lines']} valid data rows")
        
        return {
            "message": f"CSV '{file.filename}' uploaded. Contains {monitoring_data_store['total_lines']} data rows.",
            "fileName": file.filename,
            "rowCount": monitoring_data_store["total_lines"],
            "hasLabel": has_label
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV file: {str(e)}")

@app.post("/start_monitoring")
async def start_monitoring_session():
    """Start monitoring session"""
    if not monitoring_data_store["csv_rows"]:
        raise HTTPException(status_code=400, detail="No CSV file uploaded for monitoring.")
    
    monitoring_data_store["predictions"] = []
    monitoring_data_store["current_index"] = 0
    monitoring_data_store["is_active"] = True
    print(f"Monitoring started for {monitoring_data_store['file_name']}. Total lines: {monitoring_data_store['total_lines']}")
    return {"message": "System monitoring started."}

@app.post("/stop_monitoring")
async def stop_monitoring_session():
    """Stop monitoring session"""
    monitoring_data_store["is_active"] = False
    print("Monitoring stopped by request.")
    return {"message": "System monitoring stopped."}

@app.get("/get_monitoring_update")
async def get_monitoring_update(batch_size: int = 1):
    """
    Get next prediction result(s) from monitoring session
    
    Args:
        batch_size: Number of rows to process in this request (default: 1, max: 4000)
    """
    if batch_size < 1:
        batch_size = 1
    if batch_size > 4000:
        batch_size = 4000
    
    if not monitoring_data_store["is_active"]:
        return {
            "status": "idle",
            "all_predictions": monitoring_data_store["predictions"],
            "latest_predictions": [],
            "processed_lines": monitoring_data_store["current_index"],
            "total_lines": monitoring_data_store["total_lines"]
        }

    if monitoring_data_store["current_index"] >= monitoring_data_store["total_lines"]:
        monitoring_data_store["is_active"] = False
        return {
            "status": "finished",
            "all_predictions": monitoring_data_store["predictions"],
            "latest_predictions": [],
            "message": "All lines processed.",
            "processed_lines": monitoring_data_store["current_index"],
            "total_lines": monitoring_data_store["total_lines"]
        }

    # Process batch
    batch_predictions = []
    end_index = min(
        monitoring_data_store["current_index"] + batch_size,
        monitoring_data_store["total_lines"]
    )
    
    batch_rows = monitoring_data_store["csv_rows"][monitoring_data_store["current_index"]:end_index]
    
    # --- VECTORIZED BATCH PROCESSING ---
    try:
        # Step 1: Convert all rows to float arrays (handle string columns)
        raw_features_list = []
        valid_indices = []  # Track which rows are valid
        
        for idx, current_row_str_list in enumerate(batch_rows):
            try:
                if len(current_row_str_list) != N_RAW_FEATURES:
                    continue
                
                # Convert to float, handling string columns
                features_float = []
                for col_name, val_str in zip(RAW_FEATURE_NAMES, current_row_str_list):
                    if col_name in ["Flow ID", "Source IP", "Destination IP", "Timestamp"]:
                        features_float.append(0.0)
                    else:
                        features_float.append(float(val_str.strip()))
                
                raw_features_list.append(features_float)
                valid_indices.append(idx)
                
            except (ValueError, IndexError):
                continue
        
        if len(raw_features_list) == 0:
            # No valid rows in batch
            monitoring_data_store["current_index"] = end_index
            return {
                "status": "processing",
                "latest_predictions": [],
                "batch_size": 0,
                "processed_lines": monitoring_data_store["current_index"],
                "total_lines": monitoring_data_store["total_lines"],
                "progress_percent": round((monitoring_data_store["current_index"] / monitoring_data_store["total_lines"]) * 100, 2)
            }
        
        # Step 2: Batch preprocessing (84 → 67 features)
        raw_features_array = np.array(raw_features_list)  # Shape: (n_valid, 84)
        processed_features_array = preprocess_raw_features_batch(raw_features_array)  # Shape: (n_valid, 67)
        
        # Step 3: PARALLEL batch prediction (multi-core processing)
        prediction_labels = run_prediction_pipeline_batch_parallel(processed_features_array)  # List of n_valid predictions
        
        # Step 4: Create response objects
        for i, valid_idx in enumerate(valid_indices):
            global_idx = monitoring_data_store["current_index"] + valid_idx
            current_row_str_list = batch_rows[valid_idx]
            
            prediction_obj = {
                "line_index": global_idx,
                "input_row_str": ", ".join(current_row_str_list[:5]) + "...",
                "prediction": prediction_labels[i],
                "is_error": prediction_labels[i].startswith("Error:")
            }
            
            batch_predictions.append(prediction_obj)
            monitoring_data_store["predictions"].append(prediction_obj)
        
    except Exception as e:
        # Fallback: create error predictions for entire batch
        print(f"Batch processing error: {e}")
        import traceback
        traceback.print_exc()
        
        for idx in range(len(batch_rows)):
            global_idx = monitoring_data_store["current_index"] + idx
            current_row_str_list = batch_rows[idx]
            
            prediction_obj = {
                "line_index": global_idx,
                "input_row_str": ", ".join(current_row_str_list[:5]) + "...",
                "prediction": f"Error: Batch processing failed ({str(e)})",
                "is_error": True
            }
            
            batch_predictions.append(prediction_obj)
            monitoring_data_store["predictions"].append(prediction_obj)
    
    monitoring_data_store["current_index"] = end_index

    return {
        "status": "processing",
        "latest_predictions": batch_predictions,
        "batch_size": len(batch_predictions),
        "processed_lines": monitoring_data_store["current_index"],
        "total_lines": monitoring_data_store["total_lines"],
        "progress_percent": round((monitoring_data_store["current_index"] / monitoring_data_store["total_lines"]) * 100, 2)
    }


@app.post("/predict_batch")
async def predict_batch(file: UploadFile = File(...), batch_size: int = 4000):
    """
    Process entire CSV file in batches and return all predictions
    
    Args:
        file: CSV file with 84 or 85 columns (85 = includes Label which will be removed)
        batch_size: Size of each processing batch (default: 4000)
        
    Returns:
        All predictions with summary statistics
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a CSV file.")

    contents = await file.read()
    
    try:
        buffer = io.StringIO(contents.decode())
        reader = csv.reader(buffer, skipinitialspace=True)
        header = next(reader, None)
        
        # Detect if CSV has Label column
        has_label = len(header) == 85 if header else False
        
        all_predictions = []
        row_count = 0
        
        # Read and process all rows
        csv_rows = []
        for row_strings in reader:
            if not row_strings or not any(field.strip() for field in row_strings):
                continue
                
            # Remove Label if present
            if has_label and len(row_strings) == 85:
                row_strings = row_strings[:-1]
            elif len(row_strings) > 85:
                row_strings = row_strings[:84]
            
            # Make sure we have 84 columns
            if len(row_strings) < 84:
                continue
                
            csv_rows.append(row_strings)
        
        total_rows = len(csv_rows)
        
        # --- VECTORIZED BATCH PROCESSING ---
        for batch_start in range(0, total_rows, batch_size):
            batch_end = min(batch_start + batch_size, total_rows)
            batch = csv_rows[batch_start:batch_end]
            
            # Step 1: Convert batch to float arrays (handle string columns)
            raw_features_list = []
            valid_indices = []
            
            for idx, row_strings in enumerate(batch):
                try:
                    if len(row_strings) != N_RAW_FEATURES:
                        all_predictions.append({
                            "line_index": batch_start + idx,
                            "prediction": f"Error: Expected {N_RAW_FEATURES} features, got {len(row_strings)}",
                            "is_error": True
                        })
                        continue
                    
                    # Convert to float, handling string columns (Flow ID, IPs, Timestamp)
                    # Source Port and Destination Port are int64, not string
                    features_float = []
                    for col_name, val_str in zip(RAW_FEATURE_NAMES, row_strings):
                        if col_name in ["Flow ID", "Source IP", "Destination IP", "Timestamp"]:
                            # Placeholder for string columns (will be dropped in preprocessing)
                            features_float.append(0.0)
                        else:
                            features_float.append(float(val_str.strip()))
                    
                    raw_features_list.append(features_float)
                    valid_indices.append(idx)
                    
                except Exception as e:
                    all_predictions.append({
                        "line_index": batch_start + idx,
                        "prediction": f"Error: {str(e)}",
                        "is_error": True
                    })
            
            # Step 2: Batch preprocessing and prediction for valid rows
            if len(raw_features_list) > 0:
                try:
                    raw_features_array = np.array(raw_features_list)
                    processed_features_array = preprocess_raw_features_batch(raw_features_array)
                    prediction_labels = run_prediction_pipeline_batch_parallel(processed_features_array)
                    
                    # Add predictions
                    for i, valid_idx in enumerate(valid_indices):
                        all_predictions.append({
                            "line_index": batch_start + valid_idx,
                            "prediction": prediction_labels[i],
                            "is_error": False
                        })
                        
                except Exception as e:
                    # Batch processing failed - mark all as errors
                    for valid_idx in valid_indices:
                        all_predictions.append({
                            "line_index": batch_start + valid_idx,
                            "prediction": f"Error: Batch processing failed ({str(e)})",
                            "is_error": True
                        })
        
        # Calculate statistics
        prediction_counts = {}
        error_count = 0
        for pred in all_predictions:
            if pred["is_error"]:
                error_count += 1
            else:
                label = pred["prediction"]
                prediction_counts[label] = prediction_counts.get(label, 0) + 1
        
        return {
            "status": "completed",
            "fileName": file.filename,
            "total_rows": total_rows,
            "predictions": all_predictions,
            "summary": {
                "total_processed": len(all_predictions),
                "errors": error_count,
                "prediction_distribution": prediction_counts
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process CSV file: {str(e)}")


# ============================================================================
# STREAMING ENDPOINTS - Continuous data feed simulation
# ============================================================================

@app.post("/streaming/start")
async def start_streaming(batch_size: int = 3000):
    """
    Start continuous streaming from rotating CSV files.
    Simulates infinite data feed for real-time monitoring.
    
    Args:
        batch_size: Number of rows per batch (default: 3000)
        
    Returns:
        Streaming configuration and status
    """
    simulator = get_simulator(batch_size=batch_size)
    simulator.start_streaming()
    stats = simulator.get_stats()
    
    return {
        "message": "Streaming started",
        "mode": "infinite_loop",
        "batch_size": batch_size,
        "files": stats["files"],
        "total_files": stats["total_files"],
        "description": f"Will continuously rotate through {stats['total_files']} files"
    }


@app.get("/streaming/next_batch")
async def get_streaming_batch():
    """
    Get next batch from continuous stream and process predictions.
    Automatically rotates through files infinitely.
    
    Returns:
        Batch predictions with metadata
    """
    simulator = get_simulator()
    
    if not simulator.is_streaming:
        raise HTTPException(
            status_code=400, 
            detail="Streaming not started. Call POST /streaming/start first"
        )
    
    try:
        # Get next batch from simulator
        batch_data = simulator.get_next_batch()
        batch_rows = batch_data["rows"]
        
        # Process batch (vectorized + parallel)
        raw_features_list = []
        valid_indices = []
        
        for idx, row_strings in enumerate(batch_rows):
            try:
                if len(row_strings) != N_RAW_FEATURES:
                    continue
                
                # Convert to float, handling string columns
                features_float = []
                for col_name, val_str in zip(RAW_FEATURE_NAMES, row_strings):
                    if col_name in ["Flow ID", "Source IP", "Destination IP", "Timestamp"]:
                        features_float.append(0.0)
                    else:
                        features_float.append(float(val_str.strip()))
                
                raw_features_list.append(features_float)
                valid_indices.append(idx)
                
            except (ValueError, IndexError):
                continue
        
        if len(raw_features_list) == 0:
            return {
                "status": "no_valid_data",
                "batch_id": batch_data["batch_id"],
                "message": "No valid rows in batch"
            }
        
        # Batch preprocessing and prediction
        raw_features_array = np.array(raw_features_list)
        processed_features_array = preprocess_raw_features_batch(raw_features_array)
        prediction_labels = run_prediction_pipeline_batch_parallel(processed_features_array)
        
        # Save predictions to storage automatically
        try:
            storage = get_storage_manager()
            # Use RAW features (84 cols) for storage, not processed
            batch_features = raw_features_array.tolist()
            batch_labels = prediction_labels  # Already a list
            # Generate confidence scores (mock for now, can be from model probabilities)
            batch_confidence = [0.85] * len(prediction_labels)  # Default confidence
            
            # Auto-categorize and save
            saved_counts = {'benign': 0, 'known_attacks': 0, 'unknown': 0}
            for features, label, confidence in zip(batch_features, batch_labels, batch_confidence):
                if label == "Benign":
                    storage.add_record('benign', features, label, confidence)
                    saved_counts['benign'] += 1
                elif label == "Unknown":
                    # Save to both Dynamic and Static
                    storage.add_record('unknown_dynamic', features, label, confidence)
                    storage.add_record('unknown_static', features, label, confidence)
                    saved_counts['unknown'] += 1
                elif not label.startswith("Error:"):
                    # Known attack (skip errors)
                    storage.add_record('known_attacks', features, label, confidence)
                    saved_counts['known_attacks'] += 1
            
            print(f"✅ Saved to storage: Benign={saved_counts['benign']}, Attacks={saved_counts['known_attacks']}, Unknown={saved_counts['unknown']}")
        except Exception as storage_error:
            # Don't fail the request if storage fails, just log it
            import traceback
            print(f"⚠️ Storage save failed: {storage_error}")
            traceback.print_exc()
        
        # Create predictions with metadata
        predictions = []
        for i, valid_idx in enumerate(valid_indices):
            predictions.append({
                "index": valid_idx,
                "prediction": prediction_labels[i],
                "is_error": prediction_labels[i].startswith("Error:")
            })
        
        # Calculate statistics
        prediction_counts = {}
        error_count = 0
        for pred in predictions:
            if pred["is_error"]:
                error_count += 1
            else:
                label = pred["prediction"]
                prediction_counts[label] = prediction_counts.get(label, 0) + 1
        
        return {
            "status": "success",
            "batch_id": batch_data["batch_id"],
            "batch_size": batch_data["batch_size"],
            "current_file": batch_data["current_file"],
            "total_rows_read": batch_data["total_rows_read"],
            "predictions": predictions,
            "summary": {
                "total_predicted": len(predictions),
                "errors": error_count,
                "prediction_distribution": prediction_counts
            },
            "timestamp": batch_data["timestamp"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Streaming batch processing failed: {str(e)}")


@app.post("/streaming/stop")
async def stop_streaming():
    """Stop continuous streaming"""
    simulator = get_simulator()
    stats = simulator.get_stats()
    simulator.stop_streaming()
    
    return {
        "message": "Streaming stopped",
        "statistics": {
            "total_batches_served": stats["total_batches_served"],
            "total_rows_read": stats["total_rows_read"],
            "files_used": stats["files"]
        }
    }


@app.get("/streaming/stats")
async def get_streaming_stats():
    """Get current streaming statistics"""
    simulator = get_simulator()
    return simulator.get_stats()


# ==========================================
# DATA STORAGE API ENDPOINTS
# ==========================================

@app.post("/storage/save_predictions")
async def save_predictions_to_storage(
    features_batch: List[List[float]],
    labels_batch: List[str],
    confidence_batch: List[float] = None
):
    """
    Lưu batch predictions vào storage theo category
    
    Tự động phân loại:
    - Benign → benign
    - Known attacks → known_attacks
    - Unknown → unknown_dynamic + unknown_static (cả 2)
    """
    try:
        storage = get_storage_manager()
        
        # Phân loại theo label
        benign_idx = []
        known_idx = []
        unknown_idx = []
        
        for i, label in enumerate(labels_batch):
            if label == "Benign":
                benign_idx.append(i)
            elif label == "Unknown":
                unknown_idx.append(i)
            else:
                known_idx.append(i)
        
        # Lưu từng category
        saved_counts = {
            "benign": 0,
            "known_attacks": 0,
            "unknown_dynamic": 0,
            "unknown_static": 0
        }
        
        # Benign
        if benign_idx:
            benign_features = [features_batch[i] for i in benign_idx]
            benign_labels = [labels_batch[i] for i in benign_idx]
            benign_conf = [confidence_batch[i] for i in benign_idx] if confidence_batch else None
            saved_counts["benign"] = storage.add_batch("benign", benign_features, benign_labels, benign_conf)
        
        # Known Attacks
        if known_idx:
            known_features = [features_batch[i] for i in known_idx]
            known_labels = [labels_batch[i] for i in known_idx]
            known_conf = [confidence_batch[i] for i in known_idx] if confidence_batch else None
            saved_counts["known_attacks"] = storage.add_batch("known_attacks", known_features, known_labels, known_conf)
        
        # Unknown - lưu vào cả 2 files
        if unknown_idx:
            unknown_features = [features_batch[i] for i in unknown_idx]
            unknown_labels = [labels_batch[i] for i in unknown_idx]
            unknown_conf = [confidence_batch[i] for i in unknown_idx] if confidence_batch else None
            
            saved_counts["unknown_dynamic"] = storage.add_batch("unknown_dynamic", unknown_features, unknown_labels, unknown_conf)
            saved_counts["unknown_static"] = storage.add_batch("unknown_static", unknown_features, unknown_labels, unknown_conf)
        
        return {
            "status": "success",
            "message": "Predictions saved to storage",
            "saved_counts": saved_counts,
            "total_saved": sum(saved_counts.values())
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save predictions: {str(e)}")


@app.get("/storage/records/{category}")
async def get_storage_records(
    category: str,
    limit: int = 100,
    offset: int = 0,
    filter_label: str = None
):
    """
    Lấy danh sách records từ storage
    
    Args:
        category: benign, known_attacks, unknown_dynamic, unknown_static
        limit: Số lượng records tối đa
        offset: Bỏ qua N records đầu (pagination)
        filter_label: Lọc theo label (optional)
    """
    try:
        storage = get_storage_manager()
        df = storage.get_records(category, limit=limit, offset=offset, filter_label=filter_label)
        
        # Replace inf/nan values to make JSON compliant
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Add row_index to each record (actual index in CSV file)
        records = df.to_dict(orient='records')
        for i, record in enumerate(records):
            record['_row_index'] = offset + i
        
        return {
            "status": "success",
            "category": category,
            "total_records": len(df),
            "records": records
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get records: {str(e)}")


@app.get("/storage/statistics")
async def get_storage_statistics():
    """Lấy thống kê tổng quan về storage"""
    try:
        storage = get_storage_manager()
        stats = storage.get_statistics()
        
        return {
            "status": "success",
            "statistics": stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@app.put("/storage/relabel/{row_index}")
async def relabel_unknown_to_known(
    row_index: int,
    new_attack_label: str
):
    """
    Gán nhãn cho Unknown (Dynamic) và chuyển sang Known Attacks
    
    Args:
        row_index: Index của row trong unknown_dynamic
        new_attack_label: Tên loại tấn công mới (VD: "DDoS", "PortScan", ...)
    """
    try:
        storage = get_storage_manager()
        success = storage.relabel_unknown_to_known(row_index, new_attack_label)
        
        if success:
            return {
                "status": "success",
                "message": f"Record {row_index} relabeled to {new_attack_label} and moved to Known Attacks",
                "row_index": row_index,
                "new_label": new_attack_label
            }
        else:
            raise HTTPException(status_code=404, detail=f"Record {row_index} not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to relabel: {str(e)}")


@app.put("/storage/relabel_batch")
async def relabel_batch_unknown(
    row_indices: List[int],
    new_attack_label: str
):
    """
    Gán nhãn cho nhiều Unknown (Dynamic) cùng lúc
    
    Args:
        row_indices: List các index cần gán nhãn
        new_attack_label: Tên loại tấn công mới
    """
    try:
        storage = get_storage_manager()
        count = storage.relabel_batch_unknown_to_known(row_indices, new_attack_label)
        
        return {
            "status": "success",
            "message": f"Relabeled {count}/{len(row_indices)} records to {new_attack_label}",
            "relabeled_count": count,
            "total_requested": len(row_indices),
            "new_label": new_attack_label
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to batch relabel: {str(e)}")


@app.post("/storage/find_row")
async def find_row_by_flow_id(request: Dict[str, Any]):
    """
    Tìm row index trong CSV file từ Flow ID
    
    Args:
        category: Category name (benign, known_attacks, unknown_dynamic, unknown_static)
        flow_id: Flow ID value to search for
    """
    try:
        category = request.get('category')
        flow_id = request.get('flow_id')
        
        if not category or not flow_id:
            raise HTTPException(status_code=400, detail="Missing category or flow_id")
        
        storage = get_storage_manager()
        row_index = storage.find_row_by_flow_id(category, flow_id)
        
        if row_index is not None:
            return {
                "status": "success",
                "row_index": row_index,
                "flow_id": flow_id,
                "category": category
            }
        else:
            return {
                "status": "not_found",
                "message": f"Flow ID {flow_id} not found in {category}",
                "row_index": None
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to find row: {str(e)}")



@app.put("/storage/update/{category}/{row_index}")
async def update_storage_record(
    category: str,
    row_index: int,
    new_label: str = None,
    new_confidence: float = None
):
    """
    Cập nhật label hoặc confidence của 1 record
    
    Args:
        category: Nhóm dữ liệu
        row_index: Index của row
        new_label: Label mới (optional)
        new_confidence: Confidence mới (optional)
    """
    try:
        storage = get_storage_manager()
        success = storage.update_record(category, row_index, new_label, new_confidence)
        
        if success:
            return {
                "status": "success",
                "message": "Record updated successfully",
                "category": category,
                "row_index": row_index
            }
        else:
            raise HTTPException(status_code=404, detail=f"Record {row_index} not found in {category}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update record: {str(e)}")


@app.delete("/storage/delete/{category}/{row_index}")
async def delete_storage_record(
    category: str,
    row_index: int
):
    """
    Xóa 1 record khỏi storage
    
    Args:
        category: Nhóm dữ liệu
        row_index: Index của row cần xóa
    """
    try:
        storage = get_storage_manager()
        success = storage.delete_record(category, row_index)
        
        if success:
            return {
                "status": "success",
                "message": "Record deleted successfully",
                "category": category,
                "row_index": row_index
            }
        else:
            raise HTTPException(status_code=404, detail=f"Record {row_index} not found in {category}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete record: {str(e)}")


@app.delete("/storage/delete_by_label/{category}")
async def delete_by_label(
    category: str,
    label: str
):
    """
    Xóa tất cả records có label cụ thể
    
    Args:
        category: Nhóm dữ liệu
        label: Label cần xóa
    """
    try:
        storage = get_storage_manager()
        count = storage.delete_by_label(category, label)
        
        return {
            "status": "success",
            "message": f"Deleted {count} records with label '{label}'",
            "category": category,
            "label": label,
            "deleted_count": count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete by label: {str(e)}")


@app.post("/storage/export/{category}")
async def export_storage(
    category: str,
    output_filename: str,
    file_format: str = "csv"
):
    """
    Export dữ liệu storage ra file
    
    Args:
        category: Nhóm dữ liệu
        output_filename: Tên file output (không cần extension)
        file_format: csv, json, hoặc parquet
    """
    try:
        storage = get_storage_manager()
        
        # Tạo output path
        output_dir = "data/exports"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{output_filename}.{file_format}")
        
        success = storage.export_category(category, output_path, file_format)
        
        if success:
            return {
                "status": "success",
                "message": f"Data exported successfully",
                "category": category,
                "output_path": output_path,
                "format": file_format
            }
        else:
            raise HTTPException(status_code=500, detail="Export failed")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export: {str(e)}")


@app.get("/storage/search/{category}")
async def search_storage(
    category: str,
    label: str = None,
    min_confidence: float = None,
    limit: int = 100
):
    """
    Tìm kiếm records theo criteria
    
    Args:
        category: Nhóm dữ liệu
        label: Lọc theo label (optional)
        min_confidence: Confidence tối thiểu (optional)
        limit: Số lượng kết quả tối đa
    """
    try:
        storage = get_storage_manager()
        
        # Build search criteria
        criteria = {}
        if label:
            criteria[' Label'] = label
        
        df = storage.search_records(category, criteria)
        
        # Filter by confidence if provided
        if min_confidence is not None and 'Confidence' in df.columns:
            df = df[df['Confidence'] >= min_confidence]
        
        # Limit results
        df = df.head(limit)
        
        return {
            "status": "success",
            "category": category,
            "total_found": len(df),
            "records": df.to_dict(orient='records')
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.get("/storage/analytics")
async def get_storage_analytics():
    """Get analytics data from all storage categories"""
    try:
        storage = get_storage_manager()
        
        # Get statistics from all categories
        stats = storage.get_statistics()
        
        # Get label distribution across all data
        label_distribution = {}
        label_by_category = {
            'benign': {},
            'known_attacks': {},
            'unknown_dynamic': {},
            'unknown_static': {}
        }
        
        # Count labels in each category
        for category in ['benign', 'known_attacks', 'unknown_dynamic', 'unknown_static']:
            try:
                df = storage.get_records(category, limit=10000, offset=0, filter_label=None)
                if not df.empty and ' Label' in df.columns:
                    label_counts = df[' Label'].value_counts().to_dict()
                    label_by_category[category] = label_counts
                    
                    # Add to overall distribution
                    for label, count in label_counts.items():
                        label_distribution[label] = label_distribution.get(label, 0) + count
            except Exception as e:
                print(f"Error processing category {category}: {e}")
                continue
        
        return {
            "status": "success",
            "category_stats": stats,
            "label_distribution": label_distribution,
            "label_by_category": label_by_category,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analytics failed: {str(e)}")


# ==========================================
# End of Storage API
# ==========================================


@app.get("/streaming/stats")
async def get_streaming_stats():
    """Get current streaming statistics"""
    simulator = get_simulator()
    return simulator.get_stats()

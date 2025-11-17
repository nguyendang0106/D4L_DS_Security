import pandas as pd
import numpy as np
from sklearn.preprocessing import QuantileTransformer, MinMaxScaler
from sklearn.metrics import auc, roc_curve, accuracy_score, balanced_accuracy_score, f1_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from sklearn.svm import OneClassSVM
from sklearn.ensemble import RandomForestClassifier
import pathlib
import pickle
# import matplotlib.pyplot as plt

# from tensorflow.keras.models import Model, load_model
# from tensorflow.keras.layers import Dense, Input
# from tensorflow.keras.regularizers import l2
import os
import warnings
from fastapi import HTTPException
from app.config import MODELS_DIR, DATA_DIR
from myutil.common import load_data

# MODELS_DIR = "models"
# DATA_DIR = "data"

train = {
    "ocsvm": {}, # 10k samples
    "ae": {}, # 100k samples
    "stage2": {}
}
val = {
    "ocsvm": {},
    "ae": {},
    "stage2": {}
}
test = {
    # "y"
    # "y_binary"
    # "y_unknown"
    # "x"
}

def get_data_paths(data_year: int):
    return os.path.join(DATA_DIR, f"{data_year}/") 

def testing():
    # LOAD DATA STAGE 1 copy from d4l-ds-security-train.ipynb
    clean_dir = get_data_paths(2017)
    print(clean_dir)
    train["ocsvm"]["x"], train["ocsvm"]["y"], x_benign_val, y_benign_val, _, _, x_malicious_train, y_malicious_train, _, _, _, _, _ = load_data(clean_dir, sample_size=1948, train_size=10000, val_size=129485, test_size=56468)

    val["ocsvm"]["x"] = np.concatenate((x_benign_val, x_malicious_train))
    val["ocsvm"]["y"] = np.concatenate((y_benign_val, np.full(y_malicious_train.shape[0], -1)))


    train["ae"]["x"], train["ae"]["y"], x_benign_val, y_benign_val, _, _, x_malicious_train, y_malicious_train, _, _, _, _, _ = load_data(clean_dir, sample_size=1948, val_size=129485, test_size=56468)

    val["ae"]["x"] = np.concatenate((x_benign_val, x_malicious_train))
    val["ae"]["y"] = np.concatenate((y_benign_val, np.full(y_malicious_train.shape[0], -1)))
    # --------------------------------------------------------------------------------------------------------------


    # LOAD DATA STAGE 2 copy from d4l-ds-security-train.ipynb
    n_benign_val = 1500

    x_benign_train, _, _, _, x_benign_test, y_benign_test, x_malicious_train, y_malicious_train, x_malicious_test, y_malicious_test, attack_type_train, _, _ = load_data(clean_dir, sample_size=1948, train_size=n_benign_val, val_size=6815, test_size=56468)
    train["stage2"]["x"], x_val, train["stage2"]["y"], y_val = train_test_split(x_malicious_train, y_malicious_train, stratify=attack_type_train, test_size=1500, random_state=42, shuffle=True)

    test['x'] = np.concatenate((x_benign_test, x_malicious_test))
    test["y_n"] = np.concatenate((y_benign_test, np.full(y_malicious_test.shape[0], -1)))

    val["stage2"]["x"] = np.concatenate((x_val, x_benign_train))
    val["stage2"]["y"] = np.concatenate((y_val, np.full(n_benign_val, "Unknown")))

    train["stage2"]["y_n"] = pd.get_dummies(train["stage2"]["y"])
    val["stage2"]["y_n"] = pd.get_dummies(val["stage2"]["y"])

    test["y"] = np.concatenate((np.full(56468, "Benign"), y_malicious_test))
    test["y_unknown"] = np.where((test["y"] == "Heartbleed") | (test["y"] == "Infiltration"), "Unknown", test["y"])
    test["y_unknown_all"] = np.where(test['y_unknown'] == 'Benign', "Unknown", test['y_unknown'])
    # --------------------------------------------------------------------------------------------------------------
    # Output directory on Kaggle (must be /kaggle/working)
    # output_dir = Path("/kaggle/working")
    # output_dir.mkdir(exist_ok=True)

    ###############################################
    # 1. OCSVM Scaler (normal)
    ###############################################
    scaler_ocsvm = QuantileTransformer(output_distribution='normal')

    train['ocsvm']['x_s'] = scaler_ocsvm.fit_transform(train['ocsvm']['x'])
    val['ocsvm']['x_s'] = scaler_ocsvm.transform(val['ocsvm']['x'])
    test['ocsvm_s'] = scaler_ocsvm.transform(test['x'])

    with open(MODELS_DIR / "scaler_ocsvm_normal.p", "wb") as f:
        pickle.dump(scaler_ocsvm, f)

    print("Saved scaler_ocsvm_normal.p")


    ###############################################
    # 2. AE Scaler (normal)
    ###############################################
    scaler_ae = QuantileTransformer(output_distribution='normal')

    train['ae']['x_s'] = scaler_ae.fit_transform(train['ae']['x'])
    val['ae']['x_s'] = scaler_ae.transform(val['ae']['x'])
    test['ae_s'] = scaler_ae.transform(test['x'])

    with open(MODELS_DIR / "scaler_ae_normal_stage1.p", "wb") as f:
        pickle.dump(scaler_ae, f)

    print("Saved scaler_ae_normal_stage1.p")


    ###############################################
    # 3. Stage2 Scaler (normal)
    ###############################################
    scaler_stage2_normal = QuantileTransformer(output_distribution='normal')

    train['stage2']['x_s'] = scaler_stage2_normal.fit_transform(train['stage2']['x'])
    val['stage2']['x_s'] = scaler_stage2_normal.transform(val['stage2']['x'])
    test['stage2_s'] = scaler_stage2_normal.transform(test['x'])

    with open(MODELS_DIR / "scaler_stage2_normal_stage2.p", "wb") as f:
        pickle.dump(scaler_stage2_normal, f)

    print("Saved scaler_stage2_normal_stage2.p")


    ###############################################
    # 4. Stage2 Scaler (uniform)
    ###############################################
    scaler_stage2_uniform = QuantileTransformer(output_distribution='uniform')

    train['stage2']['x_q'] = scaler_stage2_uniform.fit_transform(train['stage2']['x'])
    val['stage2']['x_q'] = scaler_stage2_uniform.transform(val['stage2']['x'])
    test['stage2_q'] = scaler_stage2_uniform.transform(test['x'])

    with open(MODELS_DIR / "scaler_stage2_uniform.p", "wb") as f:
        pickle.dump(scaler_stage2_uniform, f)

    print("Saved scaler_stage2_uniform.p")

if __name__ == "__main__":
    testing()

def get_model_paths(model_name: str, machine_name: str):
    """Trả về đường dẫn lưu model và scaler."""
    model_base_name = machine_name.replace(' ', '_')
    model_path = os.path.join(MODELS_DIR, f"{model_base_name}_{model_name}_model.pkl")
    scaler_path = os.path.join(MODELS_DIR, f"{model_base_name}_{model_name}_scaler.pkl")
    return model_path, scaler_path

# def retrain_model(model_name: str, machine_name: str, n_samples: int):
#     """Huấn luyện lại mô hình."""
#     if model_name not in {'OCSVM','IForest'}:
#         raise ValueError(f"Không tìm thấy mô hình: {model_name}")

#     if machine_name not in MACHINE_CONFIGS:
#         raise ValueError(f"Không tìm thấy cấu hình cho máy: {machine_name}")
        
#     config = MACHINE_CONFIGS[machine_name]
#     cont_rate = config['cont_rate']
#     model_path, scaler_path = get_model_paths(model_name, machine_name)

#     # 1. Tải và tiền xử lý cơ bản dữ liệu
#     df = load_all_data_and_basic_preprocess(machine_name)
#     df = df.tail(n_samples)

#     if df.empty:
#         raise ValueError(f"Không đủ {n_samples} mẫu hoặc không còn thuộc tính phù hợp sau tiền xử lý.")

#     # 3. Scale dữ liệu
#     scaler = RobustScaler()
#     df_scaled = pd.DataFrame(scaler.fit_transform(df),
#                              index=df.index,
#                              columns=df.columns)

#     # 4. Huấn luyện OCSVM
#     model = OneClassSVM(kernel='rbf', nu=cont_rate, gamma='auto') if model_name == 'OCSVM' else IsolationForest(n_estimators=100, contamination=cont_rate, random_state=42)
#     model.fit(df_scaled)

#     # 5. Lưu Model và Scaler
#     joblib.dump(model, model_path)
#     joblib.dump(scaler, scaler_path)
    
#     return len(df_scaled), len(df_scaled.columns)
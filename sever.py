# chỗ này để viết API, bằng FastAPI cho nhanh. Test bang port http://127.0.0.1:8000/docs
# python -m uvicorn sever:app --reload

import pandas as pd
import numpy as np
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Optional

from model_manager import retrain_OCSVM_model
from myutil.common import load_data

# --- Khởi tạo FastAPI ---
app = FastAPI(title="OCSVM Anomaly Detection API")

# -------------------------- CẤU TRÚC DỮ LIỆU ĐẦU VÀO (JSON) --------------------------

class RetrainParams(BaseModel):
    """Cấu trúc dữ liệu đầu vào cho API Retrain."""
    # Đã thêm trường machine_name
    n_samples: int = Field(10000, description="Số lượng mẫu dùng để huấn luyện - train_size.")

class DataPoint(BaseModel):
    """Cấu trúc dữ liệu đầu vào cho API Infer."""
    pass
#     model_name: str = Field(..., example="IForest", description="Tên model infer")
#     machine_name: str = Field(..., example="Air compressor")
#     time: str = Field(..., example="2025-05-21 12:20:00+07:00", description="Thời gian log (ISO 8601 format).") 
#     data: Dict[str, Optional[float]] = Field(..., example={
#         'point_key=439_First': 1.2, 
#         'point_key=440_First': 3.4,
#     }, description="Các thuộc tính thô dạng key: value")
#     anomaly_threshold: float = Field(-0.5, description="Ngưỡng bất thường: Score < threshold -> Anomaly")


# -------------------------- ROUTES API --------------------------

@app.post("/retrain")
def retrain_model_route(params: RetrainParams):
    """
    🔄 **Retrain Model:** Huấn luyện lại mô hình OCSVM.
    """
    n_samples = params.n_samples
    
    try:
        retrain_OCSVM_model(n_samples)
        return {
            "status": "success",
            "message": f"Huấn luyện lại mô hình OCSVM thành công."
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi trong quá trình retrain: {type(e).__name__}: {str(e)}")


@app.post("/infer")
def infer_data_route(data_point: DataPoint):
    """
    🔍 **Infer Data:** Dự đoán bất thường cho một điểm dữ liệu mới, **ghi data vào file CSV** và trả về kết luận.
    """
    pass
    # model_name = data_point.model_name
    # machine_name = data_point.machine_name
    
    # if machine_name not in MACHINE_CONFIGS:
    #     raise HTTPException(status_code=404, detail=f"Không tìm thấy cấu hình cho máy: {machine_name}")

    # config = MACHINE_CONFIGS[machine_name]
    # fpath = config['fpath']
    # feature_set = config['FEATURE_SET']
    # time_col = feature_set[0]

    # try:
    #     # 1. Chuẩn bị điểm dữ liệu mới (raw)
    #     new_data_dict = {time_col: data_point.time}

    #     for col in feature_set[1:]:
    #         input_value = data_point.data.get(col)
    #         if input_value is not None:
    #             new_data_dict[col] = data_point.data.get(col) 
    #         else:
    #             new_data_dict[col] = 0.0  # Gán 0 nếu không có trong input

    #     df_new_raw = pd.DataFrame([new_data_dict], columns=feature_set)
    #     df_new_raw[time_col] = pd.to_datetime(df_new_raw[time_col]).dt.tz_convert(TZ)
    #     df_new_raw_indexed = df_new_raw.set_index(time_col)

    #     # 2. Ghi dữ liệu mới vào file CSV (append mode)
    #     is_new_file = not os.path.exists(fpath)

    #     if not is_new_file:
    #         with open(fpath, 'rb+') as f:
    #             f.seek(-1, os.SEEK_END)
    #             if f.read(1) != b'\n':
    #                 f.write(b'\n')

    #     df_new_raw.to_csv(fpath, mode='a', index=False, header=is_new_file, lineterminator='\n')

    #     # 3. Thực hiện Infer
    #     anomaly_score, is_anomaly = infer_new_data(
    #         model_name,
    #         machine_name, 
    #         df_new_raw_indexed, 
    #         data_point.anomaly_threshold
    #     )
        
    #     # 4. Trả kết quả
    #     return {
    #         "model_name": model_name,
    #         "machine_name": machine_name,
    #         "log_time": data_point.time,
    #         "anomaly_score": anomaly_score,
    #         "anomaly_threshold": data_point.anomaly_threshold,
    #         "is_anomaly": is_anomaly,
    #         "conclusion": "**BẤT THƯỜNG**" if is_anomaly else "Bình thường",
    #         "data_logged": True
    #     }

    # except Exception as e:
    #     raise HTTPException(status_code=500, detail=f"Lỗi trong quá trình infer: {type(e).__name__}: {str(e)}")
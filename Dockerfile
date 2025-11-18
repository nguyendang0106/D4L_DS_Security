FROM python:3.12-slim
LABEL authors="Dang"

WORKDIR /src

# Cài libomp + các công cụ biên dịch cần thiết cho wordcloud
RUN apt-get update && apt-get install -y \
    gcc \
    libomp-dev \
    build-essential \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Copy model files
COPY model/scaler_ae_normal_stage1.p /src/model/scaler_ae_normal_stage1.p
COPY model/ocsvm_model_100k_stage1.p /src/model/ocsvm_model_100k_stage1.p
COPY model/scaler_stage2_normal_stage2.p /src/model/scaler_stage2_normal_stage2.p
COPY model/sota_stage2.p /src/model/sota_stage2.p
COPY server.py /src/server.py
COPY requirements.txt /src/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
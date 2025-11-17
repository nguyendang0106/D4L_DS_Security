import os
from pathlib import Path

MODELS_DIR = Path("models")
DATA_DIR = Path("data")

MODELS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
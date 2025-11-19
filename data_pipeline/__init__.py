"""
Data Pipeline Package for CICIDS 2017/2018
Preprocessing raw CSV files to cleaned Parquet format
"""

from .data_cleaning_pipeline import DataCleaningPipeline

__version__ = "1.0.0"
__all__ = ["DataCleaningPipeline"]

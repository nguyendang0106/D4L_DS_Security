"""
Data Cleaning Pipeline for CICIDS 2017/2018
Converts raw CSV files from data/20XX/original to cleaned Parquet/Feather files in data/20XX/clean
"""

import pandas as pd
import numpy as np
import os
import glob
import matplotlib.pyplot as plt
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Columns to drop (no variance or irrelevant)
DROP_COLUMNS = [
    # Dataset Specific Information
    "Flow ID", 
    "Source IP", "Src IP", 
    "Source Port", "Src Port", 
    "Destination IP", "Dst IP",
    # Features Without Observed Variance
    "Bwd PSH Flags", 
    "Fwd URG Flags", 
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk", "Fwd Byts/b Avg", 
    "Fwd Avg Packets/Bulk", "Fwd Pkts/b Avg", 
    "Fwd Avg Bulk Rate", "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk", "Bwd Byts/b Avg", 
    "Bwd Avg Packets/Bulk", "Bwd Pkts/b Avg", 
    "Bwd Avg Bulk Rate", "Bwd Blk Rate Avg",
    # Duplicate Column
    'Fwd Header Length.1'
]

# Column name mapping for standardization across 2017 and 2018 datasets
COLUMN_MAPPER = {
    'Dst Port': 'Destination Port',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Fwd Packets Length Total', 
    'Total Length of Fwd Packets': 'Fwd Packets Length Total',
    'TotLen Bwd Pkts': 'Bwd Packets Length Total',
    'Total Length of Bwd Packets': 'Bwd Packets Length Total', 
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min', 
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean', 
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max', 
    'Bwd Pkt Len Min': 'Bwd Packet Length Min', 
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std', 
    'Flow Byts/s': 'Flow Bytes/s', 
    'Flow Pkts/s': 'Flow Packets/s', 
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Bwd IAT Tot': 'Bwd IAT Total', 
    'Fwd Header Len': 'Fwd Header Length', 
    'Bwd Header Len': 'Bwd Header Length', 
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s', 
    'Pkt Len Min': 'Packet Length Min', 
    'Min Packet Length': 'Packet Length Min',
    'Pkt Len Max': 'Packet Length Max', 
    'Max Packet Length': 'Packet Length Max',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std', 
    'Pkt Len Var': 'Packet Length Variance', 
    'FIN Flag Cnt': 'FIN Flag Count', 
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count', 
    'PSH Flag Cnt': 'PSH Flag Count', 
    'ACK Flag Cnt': 'ACK Flag Count', 
    'URG Flag Cnt': 'URG Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count', 
    'Pkt Size Avg': 'Avg Packet Size',
    'Average Packet Size': 'Avg Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size', 
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk', 
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate', 
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk', 
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate', 
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes', 
    'Subflow Bwd Pkts': 'Subflow Bwd Packets', 
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init Fwd Win Bytes', 
    'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
    'Init Bwd Win Byts': 'Init Bwd Win Bytes', 
    'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
    'Fwd Act Data Pkts': 'Fwd Act Data Packets',
    'act_data_pkt_fwd': 'Fwd Act Data Packets',
    'Fwd Seg Size Min': 'Fwd Seg Size Min',
    'min_seg_size_forward': 'Fwd Seg Size Min'
}


class DataCleaningPipeline:
    """
    Pipeline to clean CICIDS network traffic data
    
    Steps:
    1. Rename columns for consistency
    2. Drop irrelevant/no-variance columns
    3. Parse timestamp and sort
    4. Standardize labels
    5. Convert datatypes
    6. Remove invalid/duplicate rows
    7. Save to Parquet/Feather
    """
    
    def __init__(self, dataset_path, filetypes=['parquet'], plot=False):
        """
        Initialize cleaning pipeline
        
        Args:
            dataset_path: Path to dataset directory (e.g., 'data/2017')
            filetypes: List of output formats ['parquet', 'feather']
            plot: Whether to generate timeline plots
        """
        self.dataset_path = Path(dataset_path)
        self.original_dir = self.dataset_path / 'original'
        self.clean_dir = self.dataset_path / 'clean'
        self.filetypes = filetypes
        self.plot = plot
        
        # Create clean directory if not exists
        self.clean_dir.mkdir(parents=True, exist_ok=True)
        
    def clean_file(self, csv_file):
        """
        Clean a single CSV file
        
        Args:
            csv_file: Path to CSV file
            
        Returns:
            Cleaned DataFrame
        """
        filename = csv_file.name
        logger.info(f"------- Processing {filename} -------")
        
        # Read CSV
        df = pd.read_csv(csv_file, skipinitialspace=True, encoding='latin')
        logger.info(f"Original shape: {df.shape}")
        logger.info(f"Label distribution:\n{df['Label'].value_counts()}")
        
        # Step 1: Rename columns
        df.rename(columns=COLUMN_MAPPER, inplace=True)
        
        # Step 2: Drop irrelevant columns
        df.drop(columns=DROP_COLUMNS, inplace=True, errors="ignore")
        
        # Step 3: Parse Timestamp
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        # Fix timestamps before 8am (add 12 hours)
        df['Timestamp'] = df['Timestamp'].apply(
            lambda x: x + pd.Timedelta(hours=12) if x.hour < 8 else x
        )
        df = df.sort_values(by=['Timestamp'])
        
        # Step 4: Standardize Labels
        df['Label'].replace({'BENIGN': 'Benign'}, inplace=True)
        df['Label'] = df['Label'].astype('category')
        
        # Step 5: Convert datatypes
        int_col = df.select_dtypes(include='integer').columns
        df[int_col] = df[int_col].apply(pd.to_numeric, errors='coerce', downcast='integer')
        
        float_col = df.select_dtypes(include='float').columns
        df[float_col] = df[float_col].apply(pd.to_numeric, errors='coerce', downcast='float')
        
        obj_col = df.select_dtypes(include='object').columns
        if len(obj_col) > 0:
            logger.warning(f'Columns with dtype == object: {obj_col}')
            df[obj_col] = df[obj_col].apply(pd.to_numeric, errors='coerce')
        
        # Step 6: Remove invalid rows
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        invalid_count = df.isna().any(axis=1).sum()
        logger.info(f"Dropping {invalid_count} invalid rows")
        df.dropna(inplace=True)
        
        # Step 7: Drop duplicates
        df.drop_duplicates(
            inplace=True, 
            subset=df.columns.difference(['Label', 'Timestamp'])
        )
        
        # Reset index
        df.reset_index(inplace=True, drop=True)
        
        logger.info(f"Final shape: {df.shape}")
        logger.info(f"Final label distribution:\n{df['Label'].value_counts()}\n")
        
        # Optional: Plot timeline
        if self.plot:
            self._plot_timeline(df, filename)
        
        return df
    
    def _plot_timeline(self, df, title):
        """Plot traffic timeline by label"""
        plt.figure(figsize=(12, 6))
        df.loc[df["Label"] == "Benign", 'Timestamp'].plot(
            style='.', color="lightgreen", label='Benign'
        )
        for label in df.Label.unique():
            if label != 'Benign':
                df.loc[df["Label"] == label, 'Timestamp'].plot(style='.', label=label)
        plt.title(f"Traffic Timeline: {title}")
        plt.legend()
        plt.tight_layout()
        plt.savefig(self.clean_dir / f'{title}_timeline.png')
        plt.close()
        
    def save_file(self, df, filename):
        """Save cleaned DataFrame to file(s)"""
        base_name = filename.replace('.csv', '')
        
        if 'feather' in self.filetypes:
            feather_path = self.clean_dir / f'{base_name}.feather'
            df.to_feather(feather_path)
            logger.info(f"Saved: {feather_path}")
            
        if 'parquet' in self.filetypes:
            parquet_path = self.clean_dir / f'{base_name}.parquet'
            df.to_parquet(parquet_path, index=False)
            logger.info(f"Saved: {parquet_path}")
    
    def clean_dataset(self):
        """Clean all CSV files in original directory"""
        csv_files = list(self.original_dir.glob('*.csv'))
        
        if not csv_files:
            logger.warning(f"No CSV files found in {self.original_dir}")
            return
        
        logger.info(f"Found {len(csv_files)} CSV files to process")
        
        for csv_file in csv_files:
            try:
                df_clean = self.clean_file(csv_file)
                self.save_file(df_clean, csv_file.name)
            except Exception as e:
                logger.error(f"Error processing {csv_file.name}: {e}")
                continue
        
        logger.info(" Dataset cleaning completed!")
    
    def aggregate_data(self, filetype='parquet'):
        """
        Aggregate all cleaned files into 3 files:
        - all_data.parquet: All data
        - all_benign.parquet: Only benign traffic
        - all_malicious.parquet: Only malicious traffic
        
        Args:
            filetype: 'parquet' or 'feather'
        """
        logger.info(f"Aggregating {filetype} files...")
        
        # Find all files
        pattern = f'*.{filetype}'
        files = list(self.clean_dir.glob(pattern))
        
        # Filter out already aggregated files
        files = [f for f in files if not f.name.startswith('all_')]
        
        if not files:
            logger.warning(f"No {filetype} files found to aggregate")
            return
        
        logger.info(f"Found {len(files)} files to aggregate")
        
        # Read and concatenate
        all_data = pd.DataFrame()
        for file in files:
            logger.info(f"Reading {file.name}")
            if filetype == 'feather':
                df = pd.read_feather(file)
            else:  # parquet
                df = pd.read_parquet(file)
            
            logger.info(f"  Shape: {df.shape}")
            logger.info(f"  Labels: {df['Label'].value_counts().to_dict()}")
            all_data = pd.concat([all_data, df], ignore_index=True)
        
        logger.info(f"\nAggregated shape: {all_data.shape}")
        
        # Remove duplicates after aggregation
        duplicates = all_data[all_data.duplicated(
            subset=all_data.columns.difference(['Label', 'Timestamp'])
        )]
        logger.info(f"Removing {len(duplicates)} duplicates after aggregation")
        if len(duplicates) > 0:
            logger.info(f"Duplicate labels:\n{duplicates.Label.value_counts()}")
        
        all_data.drop(duplicates.index, axis=0, inplace=True)
        all_data.reset_index(inplace=True, drop=True)
        
        logger.info(f"Final aggregated shape: {all_data.shape}")
        logger.info(f"Final label distribution:\n{all_data['Label'].value_counts()}")
        
        # Split into benign and malicious
        malicious = all_data[all_data.Label != 'Benign'].reset_index(drop=True)
        benign = all_data[all_data.Label == 'Benign'].reset_index(drop=True)
        
        # Save
        if filetype == 'feather':
            all_data.to_feather(self.clean_dir / 'all_data.feather')
            malicious.to_feather(self.clean_dir / 'all_malicious.feather')
            benign.to_feather(self.clean_dir / 'all_benign.feather')
        else:  # parquet
            all_data.to_parquet(self.clean_dir / 'all_data.parquet', index=False)
            malicious.to_parquet(self.clean_dir / 'all_malicious.parquet', index=False)
            benign.to_parquet(self.clean_dir / 'all_benign.parquet', index=False)
        
        logger.info(f" Aggregation completed!")
        logger.info(f"   - all_data: {all_data.shape[0]} records")
        logger.info(f"   - all_benign: {benign.shape[0]} records")
        logger.info(f"   - all_malicious: {malicious.shape[0]} records")


def main():
    """
    Main function to run the pipeline
    
    Usage:
        python data_cleaning_pipeline.py
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Clean CICIDS dataset from CSV to Parquet/Feather'
    )
    parser.add_argument(
        'dataset_path',
        type=str,
        help='Path to dataset directory (e.g., data/2017)'
    )
    parser.add_argument(
        '--filetypes',
        nargs='+',
        default=['parquet'],
        choices=['parquet', 'feather'],
        help='Output file types (default: parquet)'
    )
    parser.add_argument(
        '--plot',
        action='store_true',
        help='Generate timeline plots'
    )
    parser.add_argument(
        '--skip-clean',
        action='store_true',
        help='Skip cleaning step (only aggregate)'
    )
    parser.add_argument(
        '--skip-aggregate',
        action='store_true',
        help='Skip aggregation step (only clean)'
    )
    
    args = parser.parse_args()
    
    # Create pipeline
    pipeline = DataCleaningPipeline(
        dataset_path=args.dataset_path,
        filetypes=args.filetypes,
        plot=args.plot
    )
    
    # Run pipeline
    if not args.skip_clean:
        logger.info("=" * 60)
        logger.info("STEP 1: CLEANING INDIVIDUAL FILES")
        logger.info("=" * 60)
        pipeline.clean_dataset()
    
    if not args.skip_aggregate:
        logger.info("\n" + "=" * 60)
        logger.info("STEP 2: AGGREGATING FILES")
        logger.info("=" * 60)
        for filetype in args.filetypes:
            pipeline.aggregate_data(filetype=filetype)
    
    logger.info("\n" + "=" * 60)
    logger.info(" PIPELINE COMPLETED!")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()

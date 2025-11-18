"""
Simple script to run data cleaning pipeline on CICIDS 2017/2018 datasets
"""

from data_cleaning_pipeline import DataCleaningPipeline
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """
    Run data cleaning pipeline on both 2017 and 2018 datasets
    """
    
    datasets = [
        'data/2018',
        # 'data/2018',  # Uncomment to process 2018 dataset
    ]
    
    for dataset_path in datasets:
        logger.info(f"\n{'='*80}")
        logger.info(f"Processing dataset: {dataset_path}")
        logger.info(f"{'='*80}\n")
        
        try:
            # Create pipeline
            pipeline = DataCleaningPipeline(
                dataset_path=dataset_path,
                filetypes=['parquet'],  # Can add 'feather' if needed
                plot=False  # Set to True if you want timeline plots
            )
            
            # Step 1: Clean individual files
            logger.info("STEP 1: Cleaning individual CSV files...")
            pipeline.clean_dataset()
            
            # Step 2: Aggregate into all_data, all_benign, all_malicious
            logger.info("\nSTEP 2: Aggregating cleaned files...")
            pipeline.aggregate_data(filetype='parquet')
            
            logger.info(f"\n Successfully processed {dataset_path}")
            
        except Exception as e:
            logger.error(f"\n Error processing {dataset_path}: {e}")
            continue
    
    logger.info(f"\n{'='*80}")
    logger.info(" All datasets processed!")
    logger.info(f"{'='*80}")
    logger.info("\nOutput files in data/20XX/clean/:")
    logger.info("  - Individual cleaned files: <filename>.parquet")
    logger.info("  - all_data.parquet: All traffic (benign + malicious)")
    logger.info("  - all_benign.parquet: Only benign traffic")
    logger.info("  - all_malicious.parquet: Only attack traffic")


if __name__ == "__main__":
    main()

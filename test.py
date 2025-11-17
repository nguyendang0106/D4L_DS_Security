import pandas as pd

df = pd.read_parquet('data/2017/clean/all_benign.parquet')

print(df.info())
import pandas as pd

df = pd.read_csv("/data/slow/mehner/netflow100000.csv")
df.to_parquet("/data/slow/mehner/netflow100000.parquet")

df = pd.read_csv("/data/slow/mehner/netflow100000000.csv")
df.to_parquet("/data/slow/mehner/netflow100000000.parquet")

df = pd.read_csv("/data/slow/mehner/netflow.csv")
df.to_parquet("/data/slow/mehner/netflow.parquet")#, encoding='utf-8')
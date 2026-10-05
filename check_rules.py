import pandas as pd

# Load your attack data
df_attack = pd.read_json("falco_alerts.jsonl", lines=True)

print("=== Attack data rules ===")
print(df_attack["rule"].value_counts().head(10))

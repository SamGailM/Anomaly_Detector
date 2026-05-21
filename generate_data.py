import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

users = [f"USER_{str(i).zfill(3)}" for i in range(1, 51)]
locations = ["Server Room A", "Server Room B", "Executive Floor",
             "Finance Office", "HR Office", "Main Lobby", "Parking Garage"]
normal_hours = range(7, 19)

rows = []
start = datetime(2024, 1, 1)

for _ in range(2000):
    user = random.choice(users)
    day_offset = random.randint(0, 89)
    hour = random.choice(normal_hours)
    minute = random.randint(0, 59)
    ts = start + timedelta(days=day_offset, hours=hour, minutes=minute)
    rows.append({
        "timestamp": ts,
        "user_id": user,
        "location": random.choice(locations[2:]),
        "access_granted": True,
        "hour": hour
    })

# inject anomalies
anomaly_users = random.sample(users, 5)
for user in anomaly_users:
    for _ in range(random.randint(8, 15)):
        day_offset = random.randint(0, 89)
        hour = random.choice([0, 1, 2, 3, 22, 23])
        minute = random.randint(0, 59)
        ts = start + timedelta(days=day_offset, hours=hour, minutes=minute)
        rows.append({
            "timestamp": ts,
            "user_id": user,
            "location": random.choice(["Server Room A", "Server Room B"]),
            "access_granted": True,
            "hour": hour
        })

df = pd.DataFrame(rows)
df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv("access_logs.csv", index=False)
print(f"Generated {len(df)} records with anomalies for: {anomaly_users}")
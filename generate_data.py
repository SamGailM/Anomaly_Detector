import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

users = [f"USER_{str(i).zfill(3)}" for i in range(1, 51)]

locations = [
    "Server Room A",
    "Server Room B",
    "Executive Floor",
    "Finance Office",
    "HR Office",
    "Main Lobby",
    "Parking Garage"
]

normal_hours = range(7, 19)

rows = []

# Generate data for the past year
end = datetime.today().replace(hour=23, minute=59, second=59, microsecond=0)
start = end - timedelta(days=365)

# Normal access events
for _ in range(8000):
    user = random.choice(users)
    day_offset = random.randint(0, 365)
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

# Inject after-hours anomalies
anomaly_users = random.sample(users, 5)

for user in anomaly_users:
    for _ in range(random.randint(25, 45)):
        day_offset = random.randint(0, 365)
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

# Add helpful fields for your Streamlit dashboard
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["date"] = df["timestamp"].dt.date
df["hour"] = df["timestamp"].dt.hour
df["is_after_hours"] = ~df["hour"].between(7, 18)

df = df.sort_values("timestamp").reset_index(drop=True)

df.to_csv("access_logs.csv", index=False)

print(f"Generated {len(df)} records from {start.date()} to {end.date()}")
print(f"Injected anomalies for: {anomaly_users}")
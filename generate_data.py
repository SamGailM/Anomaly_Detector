import pandas as pd
import numpy as np
from datetime import datetime, timedelta, time
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
    "Parking Garage",
]
normal_hours = list(range(7, 19))
after_hours_list = [0, 1, 2, 3, 22, 23]

end = datetime.now().replace(second=0, microsecond=0)
start = end - timedelta(days=365)


def random_timestamp(hours, start_dt=start, end_dt=end):
    """Create a timestamp between start_dt and end_dt without generating future times."""
    while True:
        day_span = (end_dt.date() - start_dt.date()).days
        access_date = start_dt.date() + timedelta(days=random.randint(0, day_span))
        access_time = time(hour=random.choice(hours), minute=random.randint(0, 59))
        ts = datetime.combine(access_date, access_time)
        if start_dt <= ts <= end_dt:
            return ts


rows = []

# Normal access events across the past year.
for _ in range(8000):
    user = random.choice(users)
    ts = random_timestamp(normal_hours)
    rows.append(
        {
            "timestamp": ts,
            "user_id": user,
            "location": random.choice(locations[2:]),
            "access_granted": True,
            "hour": ts.hour,
        }
    )

# Users with high overall after-hours access spread across the whole year.
overall_anomaly_users = random.sample(users, 5)
for user in overall_anomaly_users:
    for _ in range(random.randint(35, 50)):
        ts = random_timestamp(after_hours_list)
        rows.append(
            {
                "timestamp": ts,
                "user_id": user,
                "location": random.choice(["Server Room A", "Server Room B"]),
                "access_granted": True,
                "hour": ts.hour,
            }
        )

# Users with a recent spike compared with their own prior monthly pattern.
# Keep these separate from the overall anomaly users so the dashboard demonstrates both checks.
available_for_recent_spike = [u for u in users if u not in overall_anomaly_users]
recent_spike_users = random.sample(available_for_recent_spike, 3)
recent_start = end - timedelta(days=30)

for user in recent_spike_users:
    # Very low prior baseline.
    for _ in range(random.randint(0, 2)):
        ts = random_timestamp(after_hours_list, start_dt=start, end_dt=recent_start)
        rows.append(
            {
                "timestamp": ts,
                "user_id": user,
                "location": random.choice(["Server Room A", "Server Room B"]),
                "access_granted": True,
                "hour": ts.hour,
            }
        )

    # Clear recent spike.
    for _ in range(random.randint(5, 8)):
        ts = random_timestamp(after_hours_list, start_dt=recent_start, end_dt=end)
        rows.append(
            {
                "timestamp": ts,
                "user_id": user,
                "location": random.choice(["Server Room A", "Server Room B"]),
                "access_granted": True,
                "hour": ts.hour,
            }
        )


df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df["date"] = df["timestamp"].dt.date
df["hour"] = df["timestamp"].dt.hour
df["is_after_hours"] = ~df["hour"].between(7, 18)
df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv("access_logs.csv", index=False)

print(f"Generated {len(df):,} records from {start.date()} to {end.date()}.")
print(f"Overall anomaly users: {overall_anomaly_users}")
print(f"Recent spike users: {recent_spike_users}")

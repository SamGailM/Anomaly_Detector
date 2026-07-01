import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from openai import OpenAI

st.set_page_config(page_title="Access Log Anomaly Detector", layout="wide")
st.title("Access Log Anomaly Detector")
st.caption("AI-powered audit tool for identifying unusual access patterns")

# -----------------------------
# Settings
# -----------------------------
AFTER_HOURS_STD_MULTIPLIER = 1.5
RECENT_DAYS = 30
BASELINE_WINDOW_DAYS = 30

# With one year of sample data, the recent 30-day period is the 12th month.
# The baseline therefore uses the previous 11 rolling 30-day windows.
# If you have 13+ months of data, you can change this to 12.
BASELINE_WINDOWS = 11

# Prevent one-off after-hours access from being flagged as a personal anomaly.
MIN_RECENT_AFTER_HOURS = 3
TOP_N_CHART_USERS = 15


@st.cache_data
def load_data():
    df = pd.read_csv("access_logs.csv", parse_dates=["timestamp"])
    df = df.dropna(subset=["timestamp", "user_id"]).copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date
    df["is_after_hours"] = ~df["hour"].between(7, 18)
    return df.sort_values("timestamp").reset_index(drop=True)

# adjust multiplier to change threshold 
def mean_plus_std_threshold(series, multiplier=2):
    if series.empty:
        return 0.0

    mean = series.mean()
    std = series.std(ddof=0)

    if pd.isna(std):
        std = 0.0

    return float(mean + multiplier * std)


def round_for_display(df, columns, decimals=2):
    display_df = df.copy()
    for col in columns:
        if col in display_df.columns:
            display_df[col] = display_df[col].round(decimals)
    return display_df


df_raw = load_data()

# If the sample-data generator accidentally created future timestamps, ignore those
# for the anomaly windows so the "past month" does not extend into the future.
now = pd.Timestamp.now().tz_localize(None)
future_record_count = (df_raw["timestamp"] > now).sum()

if future_record_count > 0:
    st.warning(
        f"{future_record_count:,} records are dated after the current time and were excluded "
        "from anomaly calculations. If this is sample data, regenerate it with the updated generator."
    )
    df = df_raw[df_raw["timestamp"] <= now].copy()
else:
    df = df_raw.copy()

if df.empty:
    st.error("No usable records found in access_logs.csv.")
    st.stop()

# -----------------------------
# Detect anomalies
# -----------------------------
all_users = sorted(df["user_id"].dropna().unique())
after_hours = df[df["is_after_hours"]].copy()

analysis_end = df["timestamp"].max()
recent_start = analysis_end - pd.Timedelta(days=RECENT_DAYS)
baseline_start = recent_start - pd.Timedelta(days=BASELINE_WINDOWS * BASELINE_WINDOW_DAYS)

# 1) Overall abnormal after-hours access compared with the full population.
# Important: include users with zero after-hours events. Excluding them inflates
# the average and can make the threshold misleading.
overall_counts = (
    after_hours.groupby("user_id")
    .size()
    .reindex(all_users, fill_value=0)
    .reset_index(name="after_hours_count")
    .rename(columns={"index": "user_id"})
)

overall_threshold = mean_plus_std_threshold(
    overall_counts["after_hours_count"],
    multiplier=AFTER_HOURS_STD_MULTIPLIER,
)

overall_counts["overall_population_threshold"] = overall_threshold
overall_counts["overall_flag"] = (
    (overall_counts["after_hours_count"] > 0)
    & (overall_counts["after_hours_count"] > overall_threshold)
)

overall_counts = overall_counts.sort_values("after_hours_count", ascending=False)
flagged_overall_users = overall_counts[overall_counts["overall_flag"]].copy()

# 2) Recent abnormal after-hours access compared with each user's own baseline.
# Recent period = most recent 30 days in the usable dataset.
# Baseline = previous rolling 30-day windows for that same user.
recent_after_hours = after_hours[
    (after_hours["timestamp"] > recent_start)
    & (after_hours["timestamp"] <= analysis_end)
].copy()

recent_counts = (
    recent_after_hours.groupby("user_id")
    .size()
    .reindex(all_users, fill_value=0)
    .reset_index(name="recent_after_hours_count")
    .rename(columns={"index": "user_id"})
)

baseline_rows = []
for user in all_users:
    user_after_hours = after_hours[after_hours["user_id"] == user]

    for window_number in range(1, BASELINE_WINDOWS + 1):
        # Window 1 is the oldest baseline window; the final window ends at recent_start.
        window_start = baseline_start + pd.Timedelta(
            days=(window_number - 1) * BASELINE_WINDOW_DAYS
        )
        window_end = window_start + pd.Timedelta(days=BASELINE_WINDOW_DAYS)

        window_count = user_after_hours[
            (user_after_hours["timestamp"] > window_start)
            & (user_after_hours["timestamp"] <= window_end)
        ].shape[0]

        baseline_rows.append(
            {
                "user_id": user,
                "baseline_window": window_number,
                "window_start": window_start.date(),
                "window_end": window_end.date(),
                "baseline_after_hours_count": window_count,
            }
        )

baseline_counts = pd.DataFrame(baseline_rows)

baseline_stats = (
    baseline_counts.groupby("user_id")["baseline_after_hours_count"]
    .agg(
        personal_avg_monthly_after_hours="mean",
        personal_std_monthly_after_hours=lambda s: s.std(ddof=0),
        baseline_windows_used="count",
    )
    .reset_index()
)

baseline_stats["personal_std_monthly_after_hours"] = baseline_stats[
    "personal_std_monthly_after_hours"
].fillna(0)

recent_vs_baseline = recent_counts.merge(baseline_stats, on="user_id", how="left")
recent_vs_baseline["personal_threshold"] = (
    recent_vs_baseline["personal_avg_monthly_after_hours"]
    + AFTER_HOURS_STD_MULTIPLIER
    * recent_vs_baseline["personal_std_monthly_after_hours"]
)
recent_vs_baseline["increase_vs_personal_avg"] = (
    recent_vs_baseline["recent_after_hours_count"]
    - recent_vs_baseline["personal_avg_monthly_after_hours"]
)
recent_vs_baseline["individual_baseline_flag"] = (
    (recent_vs_baseline["recent_after_hours_count"] >= MIN_RECENT_AFTER_HOURS)
    & (
        recent_vs_baseline["recent_after_hours_count"]
        > recent_vs_baseline["personal_threshold"]
    )
)

flagged_recent_users = recent_vs_baseline[
    recent_vs_baseline["individual_baseline_flag"]
].sort_values("increase_vs_personal_avg", ascending=False)

# Combined user-level summary for validation and display.
user_summary = overall_counts.merge(recent_vs_baseline, on="user_id", how="left")
user_summary_display = round_for_display(
    user_summary,
    [
        "overall_population_threshold",
        "personal_avg_monthly_after_hours",
        "personal_std_monthly_after_hours",
        "personal_threshold",
        "increase_vs_personal_avg",
    ],
)

flagged_overall_display = round_for_display(
    flagged_overall_users,
    ["overall_population_threshold"],
)

flagged_recent_display = round_for_display(
    flagged_recent_users,
    [
        "personal_avg_monthly_after_hours",
        "personal_std_monthly_after_hours",
        "personal_threshold",
        "increase_vs_personal_avg",
    ],
)

# -----------------------------
# Summary metrics
# -----------------------------
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Records Used", f"{len(df):,}")
col2.metric("Unique Users", df["user_id"].nunique())
col3.metric("After-Hours Events", f"{len(after_hours):,}")
col4.metric("Overall Flags", len(flagged_overall_users))
col5.metric("Recent Personal Flags", len(flagged_recent_users))

st.caption(
    f"Analysis window: {df['date'].min()} to {df['date'].max()} | "
    f"Recent review period: {recent_start.date()} to {analysis_end.date()} | "
    f"Baseline period: {baseline_start.date()} to {recent_start.date()}"
)

st.divider()

# -----------------------------
# Charts
# -----------------------------
leftCol, rightCol = st.columns(2)

with leftCol:
    st.subheader("Access by hour of day")
    hourly = df.groupby("hour").size().reset_index(name="count")
    hourly["access_period"] = hourly["hour"].apply(
        lambda h: "After hours" if not 7 <= h <= 18 else "Normal hours"
    )
    fig = px.bar(
        hourly,
        x="hour",
        y="count",
        color="access_period",
        color_discrete_map={"After hours": "#E24B4A", "Normal hours": "#1D9E75"},
        labels={"hour": "Hour", "count": "Events", "access_period": ""},
    )
    fig.update_layout(
        showlegend=True,
        legend_title="",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)

with rightCol:
    st.subheader("Overall after-hours access by user")
    st.caption(
        "Compares each user's total after-hours access against the population "
        f"threshold of {overall_threshold:.1f} events."
    )

    overall_chart = overall_counts.head(TOP_N_CHART_USERS).copy()
    overall_chart["status"] = overall_chart["overall_flag"].map(
        {True: "Flagged", False: "Not flagged"}
    )

    fig2 = px.bar(
        overall_chart,
        x="user_id",
        y="after_hours_count",
        color="status",
        color_discrete_map={"Flagged": "#E24B4A", "Not flagged": "#6B7280"},
        labels={"user_id": "User", "after_hours_count": "After-hours events", "status": ""},
    )
    fig2.add_hline(
        y=overall_threshold,
        line_dash="dash",
        annotation_text=f"Threshold: {overall_threshold:.1f}",
        annotation_position="top left",
    )
    fig2.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig2, use_container_width=True)

st.subheader("Past-month after-hours access vs individual baseline")
st.caption(
    f"Compares each user's recent {RECENT_DAYS}-day after-hours count against "
    f"that same user's average plus {AFTER_HOURS_STD_MULTIPLIER} standard deviations "
    f"from the previous {BASELINE_WINDOWS} rolling {BASELINE_WINDOW_DAYS}-day windows. "
    f"A user must also have at least {MIN_RECENT_AFTER_HOURS} recent after-hours events to be flagged."
)

individual_chart = (
    recent_vs_baseline[recent_vs_baseline["recent_after_hours_count"] > 0]
    .sort_values("recent_after_hours_count", ascending=False)
    .head(TOP_N_CHART_USERS)
    .copy()
)

if not individual_chart.empty:
    individual_chart = round_for_display(
        individual_chart,
        ["personal_avg_monthly_after_hours", "personal_threshold"],
    )
    bar_colors = [
        "#F59E0B" if flag else "#6B7280"
        for flag in individual_chart["individual_baseline_flag"]
    ]

    fig3 = go.Figure()
    fig3.add_bar(
        x=individual_chart["user_id"],
        y=individual_chart["recent_after_hours_count"],
        name="Recent 30-day count",
        marker_color=bar_colors,
    )
    fig3.add_trace(
        go.Scatter(
            x=individual_chart["user_id"],
            y=individual_chart["personal_avg_monthly_after_hours"],
            mode="lines+markers",
            name="Personal monthly average",
        )
    )
    fig3.add_trace(
        go.Scatter(
            x=individual_chart["user_id"],
            y=individual_chart["personal_threshold"],
            mode="lines+markers",
            name="Personal threshold",
        )
    )
    fig3.update_layout(
        xaxis_title="User",
        yaxis_title="After-hours events",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No after-hours activity in the recent review period.")

st.divider()

# -----------------------------
# User-level tables
# -----------------------------
st.subheader("Flagged user summaries")

summary_left, summary_right = st.columns(2)

with summary_left:
    st.markdown("**Overall population flags**")
    if not flagged_overall_display.empty:
        table = flagged_overall_display[
            ["user_id", "after_hours_count", "overall_population_threshold"]
        ].rename(
            columns={
                "user_id": "User",
                "after_hours_count": "Total After-Hours Events",
                "overall_population_threshold": "Population Threshold",
            }
        )
        st.dataframe(table, use_container_width=True, hide_index=True)
    else:
        st.info("No users exceed the overall population threshold.")

with summary_right:
    st.markdown("**Past-month personal baseline flags**")
    if not flagged_recent_display.empty:
        table = flagged_recent_display[
            [
                "user_id",
                "recent_after_hours_count",
                "personal_avg_monthly_after_hours",
                "personal_threshold",
                "increase_vs_personal_avg",
            ]
        ].rename(
            columns={
                "user_id": "User",
                "recent_after_hours_count": "Recent Count",
                "personal_avg_monthly_after_hours": "Personal Avg",
                "personal_threshold": "Personal Threshold",
                "increase_vs_personal_avg": "Increase vs Avg",
            }
        )
        st.dataframe(table, use_container_width=True, hide_index=True)
    else:
        st.info("No users exceed their personal recent-period threshold.")

with st.expander("Show full user anomaly scoring table"):
    full_table = user_summary_display[
        [
            "user_id",
            "after_hours_count",
            "overall_population_threshold",
            "overall_flag",
            "recent_after_hours_count",
            "personal_avg_monthly_after_hours",
            "personal_std_monthly_after_hours",
            "personal_threshold",
            "increase_vs_personal_avg",
            "individual_baseline_flag",
        ]
    ].rename(
        columns={
            "user_id": "User",
            "after_hours_count": "Total After-Hours",
            "overall_population_threshold": "Population Threshold",
            "overall_flag": "Overall Flag",
            "recent_after_hours_count": "Recent Count",
            "personal_avg_monthly_after_hours": "Personal Avg",
            "personal_std_monthly_after_hours": "Personal Std Dev",
            "personal_threshold": "Personal Threshold",
            "increase_vs_personal_avg": "Increase vs Avg",
            "individual_baseline_flag": "Personal Baseline Flag",
        }
    )
    st.dataframe(full_table, use_container_width=True, hide_index=True)

# -----------------------------
# Event-level details
# -----------------------------
st.subheader("Flagged event details")

with st.expander("Overall flagged users - after-hours event details"):
    if not flagged_overall_users.empty:
        overall_detail = after_hours[
            after_hours["user_id"].isin(flagged_overall_users["user_id"])
        ].merge(
            flagged_overall_users[["user_id", "after_hours_count"]],
            on="user_id",
            how="left",
        )
        overall_detail = overall_detail[
            ["user_id", "timestamp", "location", "after_hours_count"]
        ].sort_values(["user_id", "timestamp"], ascending=[True, False])
        overall_detail = overall_detail.rename(
            columns={
                "user_id": "User",
                "timestamp": "Timestamp",
                "location": "Location",
                "after_hours_count": "User Total After-Hours",
            }
        )
        st.dataframe(overall_detail, use_container_width=True, hide_index=True)
    else:
        st.info("No overall flagged event details to display.")

with st.expander("Past-month personal baseline flags - recent event details"):
    if not flagged_recent_users.empty:
        recent_detail = recent_after_hours[
            recent_after_hours["user_id"].isin(flagged_recent_users["user_id"])
        ].merge(
            flagged_recent_display[
                [
                    "user_id",
                    "recent_after_hours_count",
                    "personal_avg_monthly_after_hours",
                    "personal_threshold",
                ]
            ],
            on="user_id",
            how="left",
        )
        recent_detail = recent_detail[
            [
                "user_id",
                "timestamp",
                "location",
                "recent_after_hours_count",
                "personal_avg_monthly_after_hours",
                "personal_threshold",
            ]
        ].sort_values(["user_id", "timestamp"], ascending=[True, False])
        recent_detail = recent_detail.rename(
            columns={
                "user_id": "User",
                "timestamp": "Timestamp",
                "location": "Location",
                "recent_after_hours_count": "Recent Count",
                "personal_avg_monthly_after_hours": "Personal Avg",
                "personal_threshold": "Personal Threshold",
            }
        )
        st.dataframe(recent_detail, use_container_width=True, hide_index=True)
    else:
        st.info("No personal-baseline flagged event details to display.")

st.divider()

# -----------------------------
# AI chat
# -----------------------------
st.subheader("Ask AI analyst")
st.caption("Ask questions about access log data in plain English")

api_key = st.text_input("OpenAI API key", type="password", placeholder="sk-...")
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.write(msg["content"])

if prompt := st.chat_input("e.g. Which users look most suspicious and why?"):
    if not api_key:
        st.warning("Please enter OpenAI API key above")
    else:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

        summary = f"""
        Access log dataset summary:
        - Total records used: {len(df):,}
        - Unique users: {df['user_id'].nunique()}
        - Date range used: {df['date'].min()} to {df['date'].max()}
        - After-hours definition: outside 7:00 AM through 6:59 PM
        - After-hours events: {len(after_hours):,}
        - Overall anomaly method: each user's total after-hours count compared to all users, including users with zero after-hours events
        - Overall population threshold: mean + {AFTER_HOURS_STD_MULTIPLIER} std dev = {overall_threshold:.1f} after-hours events
        - Overall flagged users: {flagged_overall_display.to_string(index=False) if not flagged_overall_display.empty else 'None'}
        - Recent individual-baseline review period: {recent_start.date()} to {analysis_end.date()}
        - Individual-baseline method: compare each user's recent {RECENT_DAYS}-day after-hours count against that user's average plus {AFTER_HOURS_STD_MULTIPLIER} std dev from the previous {BASELINE_WINDOWS} rolling {BASELINE_WINDOW_DAYS}-day windows
        - Minimum recent after-hours events required for personal-baseline flag: {MIN_RECENT_AFTER_HOURS}
        - Past-month individual-baseline flagged users: {flagged_recent_display.to_string(index=False) if not flagged_recent_display.empty else 'None'}
        - Top locations accessed after hours: {after_hours['location'].value_counts().head(3).to_string() if not after_hours.empty else 'None'}
        """

        system_prompt = """You are an internal audit AI analyst. You help auditors
        identify anomalies and control gaps in access log data. Be concise,
        specific, and use audit terminology. Reference actual user IDs and
        numbers from the data provided."""

        client = OpenAI(api_key=api_key)
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"Data context:\n{summary}\n\nQuestion: {prompt}"},
                    ],
                )
                answer = response.choices[0].message.content
                st.write(answer)
                st.session_state.messages.append({"role": "assistant", "content": answer})

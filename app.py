import streamlit as st
import pandas as pd
import plotly.express as px
from openai import OpenAI

st.set_page_config(page_title="Access Log Anomaly Detector", layout="wide")
st.title("Access Log Anomaly Detector")
st.caption("AI-powered audit tool for identifying unusual access patterns")

@st.cache_data  # so that load_data is only run once and not on every interaction
def load_data():
    df = pd.read_csv("access_logs.csv", parse_dates=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date
    df["is_after_hours"] = ~df["hour"].between(7, 18)
    return df


def safe_threshold(series, multiplier=1.5):
   
    if series.empty:
        return 0

    mean = series.mean()
    std = series.std()

    if pd.isna(std):
        std = 0

    return mean + multiplier * std


df = load_data()

# detect anomalies

AFTER_HOURS_STD_MULTIPLIER = 1.5
RECENT_DAYS = 30
BASELINE_WINDOWS = 12
BASELINE_WINDOW_DAYS = 30

all_users = sorted(df["user_id"].dropna().unique())
after_hours = df[df["is_after_hours"]].copy()

# 1) Overall abnormal after-hours access compared with all users
# This flags users whose total after-hours access count is unusually high
# compared with the population of users in the dataset.
anomaly_counts = (
    after_hours.groupby("user_id")
    .size()
    .reset_index(name="after_hours_count")
)

overall_threshold = safe_threshold(
    anomaly_counts["after_hours_count"],
    multiplier=AFTER_HOURS_STD_MULTIPLIER
)

flagged_overall_users = anomaly_counts[
    anomaly_counts["after_hours_count"] >= overall_threshold
].sort_values("after_hours_count", ascending=False)

# 2) Recent abnormal after-hours access compared with each user's own baseline
# This compares each user's after-hours access during the most recent 30 days
# against that same user's average from the previous twelve 30-day windows.
analysis_end = df["timestamp"].max()
recent_start = analysis_end - pd.Timedelta(days=RECENT_DAYS)

recent_after_hours = after_hours[after_hours["timestamp"] >= recent_start].copy()

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
        window_end = recent_start - pd.Timedelta(
            days=BASELINE_WINDOW_DAYS * (window_number - 1)
        )
        window_start = recent_start - pd.Timedelta(
            days=BASELINE_WINDOW_DAYS * window_number
        )

        window_count = user_after_hours[
            (user_after_hours["timestamp"] >= window_start)
            & (user_after_hours["timestamp"] < window_end)
        ].shape[0]

        baseline_rows.append({
            "user_id": user,
            "baseline_window": window_number,
            "window_start": window_start.date(),
            "window_end": window_end.date(),
            "baseline_after_hours_count": window_count
        })

baseline_counts = pd.DataFrame(baseline_rows)

baseline_stats = (
    baseline_counts.groupby("user_id")["baseline_after_hours_count"]
    .agg(
        personal_avg_monthly_after_hours="mean",
        personal_std_monthly_after_hours="std"
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


flagged_recent_users = recent_vs_baseline[
    # Use > instead of >= so users with 0 recent events and a 0 threshold are not flagged.
    (recent_vs_baseline["recent_after_hours_count"] > 0)
    & (
        recent_vs_baseline["recent_after_hours_count"]
        > recent_vs_baseline["personal_threshold"]
    )
].sort_values("increase_vs_personal_avg", ascending=False)

# Round display fields for readability
flagged_recent_users_display = flagged_recent_users.copy()
for col in [
    "personal_avg_monthly_after_hours",
    "personal_std_monthly_after_hours",
    "personal_threshold",
    "increase_vs_personal_avg"
]:
    flagged_recent_users_display[col] = flagged_recent_users_display[col].round(2)

# create summary metrics

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Records", f"{len(df):,}")
col2.metric("Unique Users", df["user_id"].nunique())
col3.metric("After-Hours Events", len(after_hours))
col4.metric("Overall Flagged", len(flagged_overall_users))
col5.metric("Recent Baseline Flags", len(flagged_recent_users))

st.divider()

# create charts
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
        labels={"hour": "Hour", "count": "Events", "access_period": ""}
    )
    fig.update_layout(
        showlegend=True,
        legend_title="",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(fig, use_container_width=True)

with rightCol:
    st.subheader("Overall abnormal after-hours users")
    st.caption(
        "Flags users with total after-hours access above the population threshold "
        f"of {overall_threshold:.1f} events."
    )
    if not flagged_overall_users.empty:
        fig2 = px.bar(
            flagged_overall_users,
            x="user_id",
            y="after_hours_count",
            color_discrete_sequence=["#E24B4A"],
            labels={"user_id": "User", "after_hours_count": "After-hours events"}
        )
        fig2.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)"
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No users flagged by the overall population threshold.")

st.divider()

# create chart for individual baseline flags

st.subheader("Past-month after-hours anomalies vs individual baseline")
st.caption(
    f"Compares each user's after-hours access from {recent_start.date()} to "
    f"{analysis_end.date()} against that user's average from the previous "
    f"{BASELINE_WINDOWS} rolling {BASELINE_WINDOW_DAYS}-day windows."
)

if not flagged_recent_users_display.empty:
    fig3 = px.bar(
        flagged_recent_users_display,
        x="user_id",
        y="recent_after_hours_count",
        color_discrete_sequence=["#F59E0B"],
        hover_data=[
            "personal_avg_monthly_after_hours",
            "personal_threshold",
            "increase_vs_personal_avg"
        ],
        labels={
            "user_id": "User",
            "recent_after_hours_count": "Recent after-hours events",
            "personal_avg_monthly_after_hours": "Personal monthly avg",
            "personal_threshold": "Personal threshold",
            "increase_vs_personal_avg": "Increase vs avg"
        }
    )
    fig3.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No users flagged against their individual past-year baseline.")

st.divider()

# create tables for flagged users

st.subheader("Overall flagged user detail")
if not flagged_overall_users.empty:
    overall_detail = after_hours[
        after_hours["user_id"].isin(flagged_overall_users["user_id"])
    ].merge(flagged_overall_users, on="user_id")

    overall_flagged_detail = overall_detail[
        ["user_id", "timestamp", "location", "after_hours_count"]
    ].sort_values("timestamp", ascending=False)

    st.dataframe(overall_flagged_detail, use_container_width=True, hide_index=True)
else:
    st.info("No overall flagged user detail to display.")

st.subheader("Past-month individual baseline flagged user detail")
if not flagged_recent_users_display.empty:
    recent_detail = recent_after_hours[
        recent_after_hours["user_id"].isin(flagged_recent_users_display["user_id"])
    ].merge(flagged_recent_users_display, on="user_id")

    recent_flagged_detail = recent_detail[
        [
            "user_id",
            "timestamp",
            "location",
            "recent_after_hours_count",
            "personal_avg_monthly_after_hours",
            "personal_threshold",
            "increase_vs_personal_avg"
        ]
    ].sort_values("timestamp", ascending=False)

    st.dataframe(recent_flagged_detail, use_container_width=True, hide_index=True)
else:
    st.info("No past-month individual baseline flagged user detail to display.")

st.divider()

# create ai chat

st.subheader("Ask AI analyst")
st.caption("Ask question about access log data in plain English")

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
        - Total records: {len(df):,}
        - Unique users: {df['user_id'].nunique()}
        - Date range: {df['date'].min()} to {df['date'].max()}
        - After-hours events outside 7am-7pm: {len(after_hours)}
        - Overall population anomaly threshold: mean + {AFTER_HOURS_STD_MULTIPLIER} std dev = {overall_threshold:.1f} after-hours events
        - Overall flagged users: {flagged_overall_users.to_string(index=False) if not flagged_overall_users.empty else 'None'}
        - Recent individual-baseline review period: {recent_start.date()} to {analysis_end.date()}
        - Individual-baseline method: compare each user's recent 30-day after-hours count against that user's average plus {AFTER_HOURS_STD_MULTIPLIER} std dev from the previous {BASELINE_WINDOWS} rolling {BASELINE_WINDOW_DAYS}-day windows
        - Past-month individual-baseline flagged users: {flagged_recent_users_display.to_string(index=False) if not flagged_recent_users_display.empty else 'None'}
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
                        {"role": "user", "content": f"Data context:\n{summary}\n\nQuestion: {prompt}"}
                    ]
                )
                answer = response.choices[0].message.content
                st.write(answer)
                st.session_state.messages.append({"role": "assistant", "content": answer})

import streamlit as st
import pandas as pd
import plotly.express as px
import anthropic

st.set_page_config(page_title="Access Log Anomaly Detector", layout="wide")
st.title("Access Log Anomaly Detector")
st.caption("AI-powered audit tool for identifying unusual access patterns")

@st.cache_data #so that load_data is only run once and not on every interation
def load_data():
    df = pd.read_csv("access_logs.csv", parse_dates=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date
    df["is_after_hours"] = ~df["hour"].between(7, 18)
    return df

df = load_data()

# detect anomalies

after_hours = df[df["is_after_hours"]]
anomaly_counts = after_hours.groupby("user_id").size().reset_index(name="after_hours_count")
threshold = anomaly_counts["after_hours_count"].mean() + 2 * anomaly_counts["after_hours_count"].std()
flaggedUsers = anomaly_counts[anomaly_counts["after_hours_count"] >= threshold].sort_values(
    "after_hours_count", ascending=False
)
# create summary metrics

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Records", f"{len(df):,}")
col2.metric("Unique Users", df["user_id"].nunique())
col3.metric("After-Hours Events", len(after_hours))
col4.metric("Flagged Users", len(flaggedUsers))

st.divider()

# create charts
leftCol, rightCol = st.columns(2)

with leftCol:
    st.subheader("Access by hour of day")
    hourly = df.groupby("hour").size().reset_index(name="count")
    fig = px.bar(hourly, x="hour", y="count",
                 color=hourly["hour"].apply(lambda h: "After hours" if not 7 <= h <= 18 else "Normal hours"),
                 color_discrete_map={"After hours": "#E24B4A", "Normal hours": "#1D9E75"},
                 labels={"hour": "Hour", "count": "Events"})
    fig.update_layout(showlegend=True, legend_title="", plot_bgcolor="rgba(0,0,0,0)",
                      paper_bgcolor="rgba(0,0,0,0)")
    st.plotly_chart(fig, use_container_width=True)

with rightCol:
    st.subheader("Flagged users")
    if not flaggedUsers.empty:
        fig2 = px.bar(flaggedUsers, x="user_id", y="after_hours_count",
                      color_discrete_sequence=["#E24B4A"],
                      labels={"user_id": "User", "after_hours_count": "After-hours events"})
        fig2.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No users flagged.")

st.divider()

# create table for flagged users

st.subheader("Flagged user detail")
if not flaggedUsers.empty:
    detail = df[df["user_id"].isin(flaggedUsers["user_id"])].merge(flagged_users, on="user_id")
    flagged_detail = detail[detail["is_after_hours"]][
        ["user_id", "timestamp", "location", "after_hours_count"]
    ].sort_values("timestamp", ascending=False)
    st.dataframe(flagged_detail, use_container_width=True, hide_index=True)

st.divider()
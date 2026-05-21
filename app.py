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

# create summary metrics


# AI-Enhanced Access Log Anomaly Detector

An audit analytics tool for flagging unusual access patterns in access log data using statistical thresholding, with a built-in AI analyst tool for natural language querying of results

## Overviews

This project incorporates AI into a statistical analysis tool to support audit and access-control review workflows. The tool ingests access log data, performs full-population analysis to identify after-hours anomalies, and allows users to ask natural language questions about the data through the integrated LLM interface

## Features

-**Full-population anomaly detection** using mean and standard deviation thresholding to identify users with unusual after-hours access activity 
-**Interactve Dashboard** built with Streamlit and Plotly, displaying summary metrics, hourly access patterns, and details about flagged users
-**AI analyst chat** powered by OpenAI API, allows natural language queries on the data findings 

## Tech Stack

- **Python 3.9+**
- **Streamlit** — web interface and dashboard
- **pandas** — data manipulation and analysis
- **Plotly Express** — interactive visualizations
- **OpenAI API** — LLM integration for natural language querying

## Project Structure

```
audit-anomaly-detector/
├── app.py              # Main Streamlit application
├── generate_data.py    # Generates synthetic access log data (only run once)
├── access_logs.csv     # Generated dataset (created on first run)
└── README.md
```

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/SamGailM/audit-anomaly-detector.git
   cd audit-anomaly-detector
   ```

2. Install dependencies:
   ```bash
   pip install streamlit pandas plotly openai
   ```

3. Generate the synthetic dataset:
   ```bash
   python generate_data.py
   ```

4. Run the app:
   ```bash
   streamlit run app.py
   ```

5. Enter your OpenAI API key in the app to enable the AI analyst feature.

## How It Works

The dataset contains synthetic access log records across 50 users and several enterprise facility locations. Five users are seeded with after-hours access patterns to simulate suspicious activity. The detection logic:

1. Filters all events occurring outside standard business hours (7 AM – 7 PM)
2. Aggregates after-hours event counts by user
3. Calculates the threshold as `mean + (multiplier × standard deviation)`
4. Flags any user whose after-hours count meets or exceeds the threshold

Flagged users and their full event detail are presented in the dashboard, and the AI analyst can interpret the results in audit-relevant terminology.

## Use Cases

- **Internal audit support** — identify anomalies for risk-prioritized review
- **Access control monitoring** — identify users with unusual access patterns
- **License optimization** — combined with usage data, identify inactive users or assets
- **Audit training** — demonstrate AI-augmented audit workflows

## Notes

This is a prototype built with synthetic data for demonstration purposes. In a production environment, additional considerations would include integration with real access control systems, role-based filtering, time-zone handling, and stricter API key management.

Samantha Miller — [LinkedIn](https://linkedin.com/in/samanthagailmiller) · [GitHub](https://github.com/SamGailM)
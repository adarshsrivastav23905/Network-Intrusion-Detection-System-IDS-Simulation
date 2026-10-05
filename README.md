# Network Intrusion Detection System (IDS) Simulation

A defensive cybersecurity project that simulates a network intrusion detection system using synthetic traffic, rule-based detection, anomaly detection, and optional machine-learning scoring.

## Overview

This project is designed for students, beginners, and professionals who want a practical cybersecurity portfolio project. It demonstrates how SOC teams can monitor flow records, classify suspicious behavior, and triage alerts without using real malicious traffic or external network scanning.

The system focuses on defensive, ethical monitoring and uses only synthetic or local lab-style network-flow data.

## Problem Statement

Organizations need to detect suspicious behavior early. A typical IDS monitors inbound and outbound network flows, flags abnormal traffic, and helps analysts decide whether the activity needs investigation. This project simulates that workflow with a hybrid IDS that combines:

- rule-based detection
- anomaly detection
- optional ML scoring
- risk scoring
- alert creation
- dashboard visualization

## Goals

- generate safe synthetic network-flow datasets
- monitor network traffic behavior
- detect suspicious patterns
- produce actionable alerts
- show alerts on a dashboard
- explain IDS concepts in simple and technical terms
- create a GitHub-friendly, beginner-friendly project

## Project Architecture

```text
Synthetic Traffic Generator
        ↓
Feature Extractor
        ↓
Rule Engine  +  Anomaly Detector  +  Optional ML Model
        ↓
Risk Scoring Engine
        ↓
Alert Engine
        ↓
SQLite Database
        ↓
FastAPI Backend
        ↓
Streamlit Dashboard
```

## Folder Structure

```text
Network-IDS-Simulation/
├── backend/
│   ├── app.py
│   └── __init__.py
├── dashboard/
│   └── app.py
├── data/
│   └── network_traffic.csv
├── ids/
│   ├── __init__.py
│   ├── alert_engine.py
│   ├── anomaly_detector.py
│   ├── feature_extractor.py
│   ├── risk_engine.py
│   └── rule_engine.py
├── ml/
│   ├── __init__.py
│   ├── evaluate.py
│   └── train_model.py
├── simulator/
│   ├── __init__.py
│   ├── generate_dataset.py
│   └── traffic_simulator.py
├── tests/
│   ├── __init__.py
│   └── test_ids.py
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
└── .
```

## Quick Start

1. Create a virtual environment

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

2. Install dependencies

```bash
pip install -r requirements.txt
```

3. Generate the synthetic dataset

```bash
python simulator/generate_dataset.py --count 5000 --output data/network_traffic.csv
```

4. Train the optional ML model

```bash
python ml/train_model.py --dataset data/network_traffic.csv --output models/ids_model.joblib
```

5. Start the backend API

```bash
python backend/app.py
```

6. Start the dashboard

```bash
streamlit run dashboard/app.py
```

7. Simulate traffic

```bash
python simulator/traffic_simulator.py --mode mixed --speed slow --duration 30 --output data/live_traffic.csv
```

## Key Detection Features

### Rule-Based Detection

The rule engine detects patterns such as:

- excessive connection rate
- repeated failed connection patterns
- high destination-port diversity
- SYN-heavy behavior
- abnormal traffic volume

### Anomaly Detection

The anomaly detector compares a flow against a baseline using measures such as:

- packet rate
- byte rate
- connection rate
- failure ratio
- destination-port diversity

### Risk Scoring

A final hybrid score is calculated using rule strength, anomaly score, and optional ML probability.

### Alert Generation

Each suspicious or anomalous event is converted into a structured alert with:

- alert ID
- timestamp
- source/destination IPs
- protocol
- ports
- rule name
- severity
- risk score
- investigation status

## API Endpoints

The backend exposes several API endpoints:

- `GET /health`
- `POST /api/flows`
- `GET /api/flows`
- `GET /api/alerts`
- `PUT /api/alerts/{alert_id}/status`
- `POST /api/alerts/{alert_id}/notes`
- `GET /api/dashboard/stats`
- `GET /api/dashboard/traffic`
- `GET /api/dashboard/alerts`
- `GET /api/rules`

## Testing

Run the included test suite:

```bash
python -m unittest discover -s tests -v
```

## Security and Ethics Notice

This project is intentionally defensive and educational. It uses synthetic data only. It does not scan or attack external systems, and all suspicious behavior is represented through local simulated records.

## Learning Outcomes

This project demonstrates:

- network security concepts
- IDS design
- synthetic traffic generation
- feature engineering
- signature detection
- anomaly detection
- risk scoring
- SOC dashboard design
- alert investigation workflow
- Python cybersecurity implementation

## Future Improvements

Possible upgrades include:

- Zeek log ingestion
- Suricata rule integration
- SIEM export
- better ML models
- more detailed alert correlation
- cloud or container deployment

## Author

This project is designed to be beginner-friendly, GitHub-ready, and suitable for cybersecurity portfolio and interview discussion.

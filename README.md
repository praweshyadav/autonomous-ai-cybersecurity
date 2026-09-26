Autonomous AI Cybersecurity Analyst & Incident Response Agent

An AI-assisted cybersecurity platform for continuous security-event
ingestion, ML-based attack detection, incident correlation,
evidence-grounded investigation, and controlled incident response.

The system is designed around a clear separation between
machine-learning detection and LLM-based
investigation/reasoning. Response actions are policy-controlled,
allowlisted, auditable, and subject to human approval for medium- and
high-risk actions.

Project Links

GitHub Repository:
https://github.com/praweshyadav/autonomous-ai-cybersecurity

Developer GitHub: https://github.com/praweshyadav

Live Dashboard: https://autonomous-ai-cybersecurity.vercel.app

Backend API: https://autonomous-ai-cybersecurity-1.onrender.com

API Health:
https://autonomous-ai-cybersecurity-1.onrender.com/health

API Documentation:
https://autonomous-ai-cybersecurity-1.onrender.com/docs

Prometheus Metrics:
https://autonomous-ai-cybersecurity-1.onrender.com/metrics

Note: Some API endpoints require Bearer-token authentication.

Overview

Traditional security monitoring systems can generate large numbers of
alerts without automatically connecting related events, retrieving
relevant security knowledge, or producing evidence-backed investigation
results.

This project combines:

Security-event ingestion and normalization

Redis Streams for event processing

Machine-learning attack detection

Incident correlation

PostgreSQL persistence

Neo4j knowledge-graph relationships

Qdrant vector retrieval

MITRE ATT&CK knowledge

RAG-based investigation

LLM-assisted security analysis

Evidence and grounding validation

Policy-controlled response planning

Human approval for higher-risk actions

FastAPI backend

Next.js/React dashboard

Prometheus/Grafana monitoring

Docker-based local infrastructure

High-Level Architecture

Authorized Sources
        │
        ▼
Ingestion & Normalization
        │
        ▼
Redis Streams
        │
        ▼
ML Detection
        │
        ▼
Incident Correlation
        │
        ├──────────────► PostgreSQL
        │
        └──────────────► Neo4j
                         │
                         ▼
                 RAG / Knowledge Graph
                         │
                         ▼
                 AI Investigation
                         │
                         ▼
                Evidence Validation
                         │
                         ▼
                 Response Policy
                         │
                         ▼
                  Approval Gate
                         │
                         ▼
                 Audit & Monitoring
                         │
                         ▼
              FastAPI + Next.js Dashboard

Key Objectives

Detect suspicious or malicious security events using
machine-learning models.

Correlate related events into meaningful security incidents.

Preserve incident and event relationships in structured databases.

Retrieve relevant cybersecurity knowledge using RAG and a knowledge
graph.

Use an LLM for investigation and reasoning rather than replacing the
numerical detection layer.

Ground investigation results in retrieved evidence.

Control response actions through an explicit policy layer.

Require human approval for medium- and high-risk response actions.

Maintain an auditable record of investigation and response activity.

Provide API and dashboard access to security operations data.

Core Workflow

1. Authorized Data Sources

The system accepts security telemetry from authorized sources such as:

Linux logs

Windows Event Logs

Network/security telemetry

Web/server logs

Other approved security-event sources

Only authorized monitoring sources should be connected to the system.

2. Ingestion and Normalization

Collectors and parsers convert source-specific events into a normalized
security-event format.

This allows downstream components to process events consistently
regardless of their original source.

3. Redis Streams

Normalized events are published to Redis Streams.

Redis provides the event-processing handoff between ingestion and
downstream detection/correlation components.

4. ML Detection

Machine-learning models analyze numerical/network features to identify
suspicious traffic and attack behavior.

The project uses the CSE-CIC-IDS2018 dataset for model development and
evaluation.

5. Incident Correlation

Related detections are grouped into incidents using event relationships,
timestamps, source/destination information, attack families, confidence,
and severity.

6. Persistence

Incident and event information is stored in PostgreSQL.

Neo4j is used to represent relationships useful for security
investigation and knowledge-graph reasoning.

7. RAG and Knowledge Retrieval

Relevant cybersecurity information is retrieved from the vector store
and knowledge graph.

The project includes MITRE ATT&CK information to provide investigation
context.

8. AI Investigation

The investigation layer uses retrieved evidence and incident context to
produce:

Investigation findings

Attack context

Relevant techniques

Evidence-backed reasoning

Recommended response actions

The LLM is not treated as the primary numerical detector.

9. Evidence Validation

Investigation results are checked against available evidence and
retrieved context before response planning.

10. Response Policy

Response actions are evaluated through a policy layer.

Allowlisted actions can be considered.

Unknown actions are denied.

Medium- and high-risk actions require human approval.

Response activity is recorded for auditability.

11. Dashboard and Monitoring

The FastAPI backend exposes application APIs, while the Next.js
dashboard provides an operational interface.

Prometheus and Grafana provide monitoring and observability.

Technology Stack

Area                  Technology

Language              Python
Backend               FastAPI
Frontend              Next.js, React
ML                    Scikit-learn, XGBoost
Deep Learning / AI    PyTorch, LLM providers
RAG                   Qdrant, retrieval pipeline
Knowledge Graph       Neo4j
Database              PostgreSQL
Event Streaming       Redis Streams
Security Monitoring   Wazuh
Monitoring            Prometheus, Grafana
Containers            Docker
Deployment            Render, Vercel
Testing               Pytest
Security Knowledge    MITRE ATT&CK
Dataset               CSE-CIC-IDS2018

Machine Learning Evaluation

The evaluated detection pipeline achieved the following reported
results:

Metric          Result

Precision       0.9659
Recall          0.8619
F1 Score        0.9109
ROC-AUC       0.999875
PR-AUC        0.914517

Selected attack-family recall:

Attack Family       Recall

Brute Force-Web     0.8153
XSS                 0.9873
SQL Injection       0.9118

Confusion matrix:

[[1,048,202, 11],
 [50,          312]]

The evaluation uses file-aware dataset splitting to reduce leakage
between training and evaluation data.

RAG / Knowledge Retrieval

The project includes a cybersecurity knowledge-retrieval layer using:

Qdrant

Embedding-based retrieval

MITRE ATT&CK knowledge

Knowledge-graph relationships

Incident context

The reported RAG index contains approximately:

697 documents

2,811 chunks/vectors

Retrieved context is used to ground the AI investigation.

Controlled End-to-End Test

A controlled end-to-end test processed:

1,000 network flows
        ↓
Detection
        ↓
Correlation
        ↓
3 incidents
        ↓
High-severity incident selected
        ↓
905 related events
        ↓
MITRE ATT&CK retrieval
        ↓
Grounded AI investigation

The test demonstrates the intended flow from network events through
detection, correlation, retrieval, and AI-assisted investigation.

API

The backend is implemented with FastAPI.

Health Check

GET /health

Live endpoint:

https://autonomous-ai-cybersecurity-1.onrender.com/health

API Documentation

FastAPI Swagger documentation:

https://autonomous-ai-cybersecurity-1.onrender.com/docs

Prometheus Metrics

GET /metrics

Live endpoint:

https://autonomous-ai-cybersecurity-1.onrender.com/metrics

Protected Incidents API

GET /api/v1/incidents

Protected endpoints require a Bearer token.

Dashboard

The project includes a Next.js/React dashboard for operational
visibility.

Dashboard:

https://autonomous-ai-cybersecurity.vercel.app

The dashboard communicates with the FastAPI backend through a
server-side API proxy so the backend credential is not exposed directly
to the browser.

Local Development

Prerequisites

Recommended components:

Python 3.10+

Docker Desktop

PostgreSQL

Redis

Neo4j

Qdrant

Wazuh

Node.js / npm for the dashboard

Clone the Repository

git clone https://github.com/praweshyadav/autonomous-ai-cybersecurity.git
cd autonomous-ai-cybersecurity

Create a Virtual Environment

Windows PowerShell:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Linux/macOS:

python3 -m venv .venv
source .venv/bin/activate

Install Python Dependencies

pip install -r requirements.txt

For reproducible dependency installation where appropriate:

pip install -r requirements-lock.txt

Environment Configuration

Create a local .env file based on the project's environment template.

Example variables include:

DATABASE_URL=postgresql://...
REDIS_URL=redis://localhost:6379/0
REDIS_STREAM_NAME=security_events

NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=...

QDRANT_URL=http://localhost:6333

OPENAI_API_KEY=...
TAVILY_API_KEY=...

Never commit real credentials, API keys, passwords, or private tokens
to GitHub.

Start the Backend

uvicorn backend.api.main:app --reload

The default local API is:

http://localhost:8000

Health:

http://localhost:8000/health

Swagger:

http://localhost:8000/docs

Start the Dashboard

From the dashboard directory:

cd dashboard
npm install
npm run dev

Docker Services

The local deployment can use Docker for the supporting infrastructure.

Main services include:

Wazuh
PostgreSQL
Redis
Neo4j
Qdrant
Prometheus
Grafana
FastAPI

Typical service relationships:

                 ┌──────────────┐
                 │    Wazuh     │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │   Ingestion  │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Redis Stream │
                 └──────┬───────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
       ┌────────────┐      ┌──────────────┐
       │ ML Detect  │      │ Correlation  │
       └─────┬──────┘      └──────┬───────┘
             └──────────┬─────────┘
                        ▼
              ┌──────────────────┐
              │ Persistence/RAG  │
              └──────────────────┘

Testing

The project uses Pytest for automated testing.

Reported test results include:

564 tests passed

0 tests failed

Redis tests: 21/21

Ollama provider test passed

End-to-end 1,000-flow test passed

API authentication tested

Prometheus metrics tested

PostgreSQL connectivity verified

Neo4j connectivity verified

Run the test suite with:

pytest -q

Security Design

Security is a central part of the architecture.

Authorized Monitoring

Only authorized servers, systems, and log sources should be connected.

Secret Management

Secrets are provided through environment variables and are excluded from
source control.

ML / LLM Separation

The system separates:

ML Detection
     ↓
Incident Context
     ↓
LLM Investigation

The LLM does not replace the numerical detection model.

Grounded Investigation

AI investigation uses retrieved evidence and incident context rather
than relying only on unconstrained model output.

Controlled Response

Response actions are restricted by policy:

Known + Allowed Action
        │
        ▼
Policy Evaluation
        │
        ├── Low Risk ───────► Execute if permitted
        │
        └── Medium/High ────► Human Approval

Unknown actions are denied.

Auditability

Investigation and response activity is recorded so that actions and
outcomes can be reviewed.

Repository Structure

autonomous-ai-cybersecurity/
│
├── agent/                 # AI investigation and reasoning
├── api/                   # API routes
├── configs/               # Configuration
├── correlation/           # Incident correlation
├── dashboard/             # Next.js/React dashboard
├── data/                  # Runtime/data directories
├── detection/             # ML detection pipeline and models
├── evaluation/            # Evaluation scripts/results
├── ingestion/             # Event ingestion and normalization
├── knowledge_graph/       # Neo4j integration
├── monitoring/            # Monitoring configuration
├── notebooks/             # Analysis notebooks
├── persistence/           # PostgreSQL/incident persistence
├── rag/                   # RAG and retrieval components
├── response/              # Response policy and actions
├── scripts/               # Utility scripts
├── tests/                 # Automated tests
├── db/                    # Database schema
├── Dockerfile
├── docker-compose.yml
├── README.md
├── requirements.txt
└── requirements-lock.txt

Project Status

Implemented and Tested

Security-event ingestion

Event normalization

ML detection

Incident correlation

PostgreSQL persistence

Neo4j integration

Qdrant retrieval

RAG pipeline

AI investigation

Evidence validation

Response policy

Audit lifecycle

FastAPI backend

API authentication

Next.js dashboard

Docker infrastructure

Prometheus/Grafana monitoring

Automated testing

Integration Work

Direct integration of additional real authorized server/log sources can
be added to the existing ingestion and Redis processing path.

Limitations

The supervised detector is trained and evaluated using selected
CSE-CIC-IDS2018 data.

Detection of completely unseen attack families is not guaranteed.

Real-world deployment requires explicit authorization and secure
network configuration.

Additional live validation is required before connecting new
production data sources.

Response automation should remain constrained by organizational
security procedures and approval requirements.

Future Improvements

Add more authorized Linux, Windows, firewall, and web-server
sources.

Expand attack scenarios and validation datasets.

Improve out-of-distribution detection.

Scale event processing for larger environments.

Expand security operations dashboards.

Add additional access-control and deployment hardening.

Improve deployment automation.

Extend investigation knowledge and response playbooks.

Responsible Use

This project is intended for authorized cybersecurity monitoring,
defensive security research, and educational use.

Only connect systems and data sources for which you have explicit
authorization. Do not use the system to access, monitor, or interfere
with systems without permission.

Author

Prawesh Yadav

Computer Science Undergraduate | AI/ML Engineer

GitHub:
https://github.com/praweshyadav

Project Repository:
https://github.com/praweshyadav/autonomous-ai-cybersecurity

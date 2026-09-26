Autonomous AI Cybersecurity Analyst & Incident Response Agent

An end-to-end defensive cybersecurity platform that combines
security-event ingestion, machine-learning detection, incident
correlation, RAG-based evidence retrieval, AI-assisted investigation,
controlled response planning, auditability, and operational
monitoring.


Responsibilities include:

health checks,

incident APIs,

authentication,

application services,

persistence access,

metrics exposure,

dashboard backend integration.

Live Backend

https://autonomous-ai-cybersecurity-1.onrender.com

Health

https://autonomous-ai-cybersecurity-1.onrender.com/health

Swagger API Documentation

https://autonomous-ai-cybersecurity-1.onrender.com/docs

Prometheus Metrics

https://autonomous-ai-cybersecurity-1.onrender.com/metrics

Protected Incidents API

GET /api/v1/incidents

Protected endpoints require Bearer-token authentication.



1. Project Overview

The Autonomous AI Cybersecurity Analyst & Incident Response Agent is
a production-oriented cybersecurity platform designed to process
authorized security telemetry, detect suspicious activity, correlate
related events into incidents, retrieve relevant cybersecurity
knowledge, investigate incidents using grounded AI, and plan controlled
response actions.

The architecture deliberately separates:

Numerical / ML Detection
          ↓
Incident Correlation
          ↓
Evidence Retrieval
          ↓
AI Investigation & Reasoning
          ↓
Policy-Controlled Response
          ↓
Audit & Monitoring

The LLM is used for investigation and reasoning; it is not treated as a
replacement for the numerical detection layer.

2. Problem Statement

Modern security environments generate large volumes of logs, alerts, and
network events. Looking at individual alerts independently can make it
difficult to understand:

which events belong to the same incident,

what attack technique may be involved,

what evidence supports an investigation,

what response action is appropriate,

and how the complete incident lifecycle should be audited.

This project addresses these problems by connecting event ingestion, ML
detection, incident correlation, databases, RAG, knowledge graphs, AI
investigation, response policy, and security monitoring into one
workflow.

3. Main Objectives

Collect and normalize authorized security events.

Stream events through Redis.

Detect suspicious activity using ML models.

Correlate related detections into incidents.

Store structured incident/event information in PostgreSQL.

Represent investigation relationships in Neo4j.

Retrieve cybersecurity knowledge using Qdrant and RAG.

Integrate MITRE ATT&CK context.

Use AI/LLM reasoning for evidence-grounded investigation.

Validate evidence before response planning.

Restrict response actions through explicit policies.

Require human approval for medium/high-risk actions.

Maintain audit records.

Expose the system through FastAPI.

Provide a Next.js/React security dashboard.

Monitor the platform using Prometheus and Grafana.

Package the infrastructure using Docker.

<img width="1177" height="4109" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/8ea9f005-8f2c-4558-b0d7-4985a1314888" />


5. System Architecture

Data and Event Layer

Authorized Sources

The platform is intended for security telemetry from systems for which
monitoring authorization exists.

Examples:

Linux system logs

Windows Event Logs

Network/security events

Web/server logs

Wazuh security alerts

Other approved sources

Ingestion

The ingestion layer:

Receives source events.

Parses source-specific formats.

Normalizes events.

Publishes normalized events into Redis Streams.

Redis Streams

Redis provides the event-processing path between ingestion and
downstream detection/correlation.

The project also uses a durable worker checkpoint so event processing
can continue from the recorded position.

6. Wazuh Security Monitoring

Wazuh is integrated as a security monitoring and alerting component.

It provides visibility into authorized security events and alerts and
can act as an upstream security-event source for the broader platform.

The overall relationship is:

Authorized Host
      ↓
Wazuh Agent / Monitoring
      ↓
Wazuh Manager
      ↓
Security Alert
      ↓
Ingestion / Normalization
      ↓
Redis Stream
      ↓
Detection / Correlation

Wazuh is therefore part of the monitoring layer, while the ML/RAG/AI
pipeline performs additional detection, correlation, investigation, and
response orchestration.

7. Machine Learning Detection

The ML layer is responsible for numerical security-event detection.

The project uses models including:

XGBoost

Isolation Forest

The detection pipeline is designed to identify suspicious
network/security behavior before incidents are correlated and
investigated.

Dataset

Model development and evaluation use the:

CSE-CIC-IDS2018 dataset

The project uses file-aware dataset splitting for evaluation.

8. ML Metric Calculation & Evaluation

Reported evaluation results:

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

                 Predicted
                 Benign   Attack
Actual Benign    1,048,202   11
Actual Attack           50  312

The evaluation includes precision, recall, F1, ROC-AUC, PR-AUC,
confusion-matrix analysis, and attack-family performance.

9. Incident Correlation

The correlation layer converts individual detections into higher-level
incidents.

Correlation considers information such as:

timestamps,

source IPs,

destination IPs,

destination ports,

protocols,

attack families,

confidence,

severity,

related security events.

This reduces the problem of treating every detection as an independent
alert.

10. PostgreSQL Persistence

PostgreSQL stores structured application and security data.

Examples include:

incidents,

incident events,

security events,

audit events,

incident metadata,

severity,

confidence,

attack-family distributions.

PostgreSQL provides durable relational persistence for the application.

11. Neo4j Knowledge Graph

Neo4j represents relationships useful for investigation.

The knowledge-graph layer can connect concepts such as:

Incident
   ↓
Security Event
   ↓
Source / Destination
   ↓
Attack Family
   ↓
MITRE Technique
   ↓
Evidence / Context

This complements relational persistence with graph-oriented
relationships.

12. RAG and Qdrant

The RAG layer retrieves relevant cybersecurity knowledge for an
investigation.

Technology includes:

Qdrant

embeddings

vector retrieval

MITRE ATT&CK information

incident context

knowledge-graph relationships

Reported RAG index:

~697 documents
~2,811 chunks / vectors

Retrieved knowledge is supplied as evidence/context for the AI
investigation layer.

13. AI Investigation

The AI investigation layer uses the incident context and retrieved
evidence to assist with:

incident interpretation,

attack-technique identification,

evidence analysis,

investigation reasoning,

recommended response actions.

The project uses an agentic orchestration approach with LangGraph
and LLM-based reasoning.

Conceptually:

Incident
   ↓
Context Builder
   ↓
Evidence Retrieval
   ↓
Knowledge / MITRE Context
   ↓
LLM Investigation
   ↓
Evidence Validation
   ↓
Investigation Result

The AI layer is deliberately separated from the numerical ML detection
layer.

14. Evidence and Grounding Validation

Before response planning, investigation output is checked against
available evidence and retrieved context.

The goal is to reduce unsupported conclusions and keep AI-generated
investigation results tied to the security data available to the system.

15. Response Policy & Human Approval

The response layer does not allow arbitrary actions.

It uses:

explicit response policies,

allowlisted actions,

risk classification,

human approval,

audit logging.

General flow:

Investigation Result
        ↓
Response Recommendation
        ↓
Policy Evaluation
        ↓
 ┌──────┴────────┐
 ↓               ↓
Low Risk      Medium/High Risk
 ↓               ↓
Policy          Human Approval
Permission          ↓
 ↓              Approved?
Execute          ↓      ↓
              Yes      No
               ↓       ↓
             Execute  Reject

Unknown actions are denied.

16. FastAPI Backend

FastAPI provides the application backend and API layer.

Responsibilities include:

health checks,

incident APIs,

authentication,

application services,

persistence access,

metrics exposure,

dashboard backend integration.

Live Backend

https://autonomous-ai-cybersecurity-1.onrender.com

Health

https://autonomous-ai-cybersecurity-1.onrender.com/health

Swagger API Documentation

https://autonomous-ai-cybersecurity-1.onrender.com/docs

Prometheus Metrics

https://autonomous-ai-cybersecurity-1.onrender.com/metrics

Protected Incidents API

GET /api/v1/incidents

Protected endpoints require Bearer-token authentication.

17. Next.js / React Dashboard

The frontend provides an operational interface for viewing security
information.

The dashboard is built with:

Next.js

React

TypeScript

It communicates with the backend through the configured API layer.

The dashboard includes operational information such as:

API connection status,

incidents,

severity information,

security-event information,

investigation results,

system status.

Live Dashboard

https://autonomous-ai-cybersecurity.vercel.app

18. Docker & Container Architecture

Docker is used to package and run the project's services consistently.

The local infrastructure includes services such as:

┌─────────────────────────────────────────┐
│              Docker Environment         │
│                                         │
│  ┌─────────┐   ┌──────────────┐        │
│  │ FastAPI │   │ Wazuh        │        │
│  └─────────┘   └──────────────┘        │
│                                         │
│  ┌─────────┐   ┌──────────────┐        │
│  │Postgres │   │ Redis        │        │
│  └─────────┘   └──────────────┘        │
│                                         │
│  ┌─────────┐   ┌──────────────┐        │
│  │ Neo4j   │   │ Qdrant       │        │
│  └─────────┘   └──────────────┘        │
│                                         │
│  ┌────────────┐ ┌────────────┐         │
│  │ Prometheus │ │ Grafana    │         │
│  └────────────┘ └────────────┘         │
└─────────────────────────────────────────┘

Docker provides isolated, repeatable environments for the backend and
supporting infrastructure.

19. Monitoring & Observability

The platform includes:

Prometheus

Used for application/system metrics.

Live metrics:

https://autonomous-ai-cybersecurity-1.onrender.com/metrics

Grafana

Used for monitoring dashboards and operational visibility.

Wazuh

Used for security monitoring and alert visibility.

Together:

Application Metrics → Prometheus → Grafana
Security Alerts     → Wazuh     → Security Pipeline

20. Deployment

The project includes a deployed architecture:

                         Internet
                            │
              ┌─────────────┴─────────────┐
              ↓                           ↓
      Vercel Dashboard               Render Backend
      Next.js / React                 FastAPI
                                          │
                         ┌────────────────┼───────────────┐
                         ↓                ↓               ↓
                    PostgreSQL          APIs        Authentication

Frontend

Hosted on Vercel:

https://autonomous-ai-cybersecurity.vercel.app

Backend

Hosted on Render:

https://autonomous-ai-cybersecurity-1.onrender.com

The backend requires authentication for protected application endpoints.

21. End-to-End Controlled Test

A controlled test processed:

1,000 network flows
        ↓
ML Detection
        ↓
Incident Correlation
        ↓
3 incidents
        ↓
Selected high-severity incident
        ↓
905 related events
        ↓
MITRE ATT&CK retrieval
        ↓
Grounded AI investigation

This validates the intended relationship between detection, correlation,
persistence, retrieval, and AI investigation.

22. Automated Testing

The project uses Pytest.

Reported test status:

564 tests passed
0 tests failed

Additional verified areas include:

Redis tests                 21/21
Ollama provider             Passed
End-to-end 1,000-flow test  Passed
API authentication          Tested
Prometheus metrics          Tested
PostgreSQL connectivity     Verified
Neo4j connectivity          Verified

Run tests:

pytest -q

23. Local Setup

Requirements

Recommended environment:

Python 3.10+

Docker Desktop

WSL2 / Ubuntu where required

Node.js / npm

PostgreSQL

Redis

Neo4j

Qdrant

Wazuh

Clone

git clone https://github.com/praweshyadav/autonomous-ai-cybersecurity.git
cd autonomous-ai-cybersecurity

Python Environment

Windows PowerShell:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Linux/macOS:

python3 -m venv .venv
source .venv/bin/activate

Install Dependencies

pip install -r requirements.txt

For the locked environment:

pip install -r requirements-lock.txt

Environment Variables

Create a local .env using the project's environment template.

Typical configuration includes:

DATABASE_URL=...
REDIS_URL=redis://localhost:6379/0
REDIS_STREAM_NAME=security_events

NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=...

QDRANT_URL=http://localhost:6333

OPENAI_API_KEY=...
TAVILY_API_KEY=...

Never commit real API keys, passwords, database credentials, or other
secrets.

Run FastAPI

uvicorn backend.api.main:app --reload

Local API:

http://localhost:8000

Swagger:

http://localhost:8000/docs

Health:

http://localhost:8000/health

Run Dashboard

cd dashboard
npm install
npm run dev

24. Repository Structure

autonomous-ai-cybersecurity/
│
├── agent/                    # AI investigation and orchestration
├── api/                      # API layer
├── configs/                  # Configuration
├── correlation/              # Incident correlation
├── dashboard/                # Next.js / React frontend
├── data/                     # Runtime/data directories
├── detection/                # ML detection and model files
├── evaluation/               # Evaluation scripts/results
├── ingestion/                # Event ingestion and normalization
├── knowledge_graph/          # Neo4j integration
├── notebooks/                # Data/ML analysis notebooks
├── persistence/              # Database repositories/adapters
├── rag/                      # RAG and retrieval
├── response/                 # Response policy/actions
├── scripts/                  # Utility scripts
├── tests/                    # Automated tests
├── db/                       # Database schema
│
├── dashboard/
│   ├── src/
│   └── ...
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-lock.txt
├── pytest.ini
├── .gitignore
└── README.md

25. Security Principles

Authorized Monitoring

Only authorized systems and telemetry sources should be connected.

Secrets

Secrets are supplied through environment variables and must not be
committed to source control.

ML / LLM Separation

ML handles numerical detection while the AI layer handles investigation
and reasoning.

Evidence Grounding

AI investigation is supported by retrieved context and available
incident evidence.

Controlled Response

Response actions are constrained by explicit policies.

Human Approval

Medium- and high-risk actions require human approval.

Auditability

Investigation and response lifecycle information is recorded for review.

Internal Service Protection

Internal services such as databases, Redis, Qdrant, and Neo4j should not
be exposed publicly without appropriate security controls.

26. Current Project Status

Implemented / Tested

Security-event ingestion

Event normalization

Redis Streams processing

ML detection

Incident correlation

PostgreSQL persistence

Neo4j integration

Qdrant vector retrieval

RAG pipeline

MITRE ATT&CK context

AI investigation

LangGraph orchestration

Evidence validation

Response policy

Human approval flow

Audit lifecycle

FastAPI backend

API authentication

Next.js/React dashboard

Docker infrastructure

Wazuh monitoring

Prometheus metrics

Grafana monitoring

Automated testing

Render backend deployment

Vercel frontend deployment

Integration / Future Work

Direct connection of additional real authorized Linux, Windows,
firewall, and web-server sources can be added to the existing ingestion
and Redis processing path.

27. Limitations

The supervised detector is trained and evaluated using selected
CSE-CIC-IDS2018 data.

Detection of completely unseen attack families is not guaranteed.

Real-world deployment requires explicit authorization and secure
network configuration.

Additional live validation is required before connecting new
production data sources.

Response automation must remain constrained by organizational
security procedures and approval requirements.

28. Future Improvements

Add more authorized Linux/Windows/firewall/web sources.

Expand attack scenarios and validation datasets.

Improve out-of-distribution detection.

Scale event processing for larger environments.

Expand SOC-style dashboard capabilities.

Add additional access-control hardening.

Improve deployment automation.

Expand cybersecurity knowledge and response playbooks.

Improve real-time investigation and correlation capabilities.

29. Responsible Use

This project is intended for:

authorized cybersecurity monitoring,

defensive security research,

cybersecurity education,

controlled testing environments.

Only connect systems and data sources for which explicit authorization
exists.

Do not use this platform to access, monitor, disrupt, or interfere with
systems without permission.

30. Project Documentation

The repository and submission package contain additional project
documentation, test results, screenshots, source code, and deployment
information.

The project submission documentation covers:

system architecture,

workflow,

ML evaluation,

RAG,

AI investigation,

response policy,

security design,

testing,

deployment,

limitations,

future work.

31. Author

Prawesh Yadav

Computer Science Undergraduate | AI/ML Engineer

GitHub:
https://github.com/praweshyadav

Project Repository:
https://github.com/praweshyadav/autonomous-ai-cybersecurity

License / Usage

Use this project only in environments where you have appropriate
authorization to collect and analyze security telemetry.

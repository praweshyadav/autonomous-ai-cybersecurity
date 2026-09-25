# Autonomous AI Cybersecurity Analyst & Incident Response System

## Project Overview
Production-oriented cybersecurity platform integrating AI, machine learning, RAG, security event ingestion, incident correlation, and policy-controlled incident response.

## Technology Stack
- Python
- FastAPI
- PostgreSQL
- Redis
- Neo4j
- Qdrant
- Wazuh
- Prometheus
- Grafana
- Docker
- WSL2 / Ubuntu

## Verified Live Pipeline
WSL auth.log -> Redis Publisher -> Redis security_events -> Redis Worker -> Detection Handler -> Incident Manager

## Wazuh Verification
A controlled authentication test was detected through the Wazuh Agent, Manager, rule processing, and Dashboard.

## Testing
The project includes tests covering API functionality, authentication, health checks, metrics, persistence, Redis processing, RAG, LLM connectivity, response policy, and end-to-end processing.

## Repository
https://github.com/praweshyadav/autonomous-ai-cybersecurity

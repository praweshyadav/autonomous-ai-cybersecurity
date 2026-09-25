# Autonomous AI Cybersecurity Analyst & Incident Response System

## 1. Project Overview

The Autonomous AI Cybersecurity Analyst & Incident Response System is a production-oriented cybersecurity platform designed to ingest security events, detect suspicious activity using machine learning and rule-based analysis, correlate related events into incidents, retrieve relevant security knowledge using RAG, assist with AI-based investigation, and generate policy-controlled response plans.

The system combines cybersecurity monitoring, machine learning, Retrieval-Augmented Generation (RAG), knowledge graphs, event streaming, observability, and controlled incident response.

## 2. Architecture

Authorized Servers / Network Sources
        |
        v
Log Collectors / Event Sources
        |
        v
Parsing & Normalization
        |
        v
Redis Event Queue
        |
        v
ML Detection Engine
        |
        v
Incident Correlation
        |
        +--------------------+
        |                    |
        v                    v
PostgreSQL              Neo4j
        |                    |
        +---------+----------+
                  |
                  v
          RAG / Qdrant /
          Security Knowledge
                  |
                  v
          AI Investigation
              Agent
                  |
                  v
        Response Planner
                  |
                  v
       Policy / Human Approval
                  |
                  v
        Controlled Response

## 3. Main Technologies

- Python
- FastAPI
- PostgreSQL
- Redis
- Neo4j
- Qdrant
- Wazuh
- Docker
- WSL2 / Ubuntu
- Prometheus
- Grafana
- Machine Learning
- Retrieval-Augmented Generation (RAG)
- Large Language Model integration

## 4. Major Components

### Event Ingestion
Collects security events from authorized sources and converts them into a normalized event format.

### Redis Event Queue
Provides streaming-based event processing through the security_events Redis stream.

### Detection Engine
Analyzes normalized events using the project's detection and machine-learning components.

### Incident Correlation
Groups related security events and maintains incident context.

### PostgreSQL
Stores structured application, event, incident, and audit information.

### Neo4j
Provides graph-based representation and relationships for security investigation and incident context.

### Qdrant
Provides vector storage for retrieval-based security knowledge.

### RAG
Retrieves relevant security information to provide contextual evidence for investigation.

### AI Investigation Agent
Uses available evidence and retrieved knowledge to assist with investigation and analysis.

### Response Planning
Generates response plans according to configured policies.

### Policy and Human Approval
Response actions are controlled by policy. Higher-impact actions can require human approval, while unknown or unauthorized actions are not automatically executed.

### Wazuh Integration
Wazuh is used as a security monitoring and event-detection component.

## 5. Verified Live Pipeline

A live controlled test was performed using the Ubuntu WSL authentication log.

Verified flow:

WSL uth.log
    ->
Redis Publisher
    ->
Redis security_events
    ->
Redis Worker
    ->
Detection Handler
    ->
Incident Manager

The test generated controlled authentication events from 127.0.0.1.

Example event types observed:

- invalid_user
- uthentication_failure

The Redis publisher successfully published the events and the Redis worker successfully consumed and processed them.

## 6. Wazuh Verification

A controlled authentication test was performed against the project's Ubuntu WSL environment.

The event was observed through:

Ubuntu authentication log
    ->
Wazuh Agent
    ->
Wazuh Manager
    ->
Wazuh Rule Processing
    ->
Wazuh Dashboard

The Wazuh dashboard displayed an authentication-related alert for a non-existent user, demonstrating successful event collection and rule processing.

## 7. Testing

The repository contains an extensive automated test suite covering areas including:

- API functionality
- Authentication
- Health checks
- Metrics
- Persistence
- Redis processing
- Detection
- Incident correlation
- RAG
- LLM connectivity
- Response planning
- Response policy
- Audit handling
- End-to-end processing
- Model loading
- Neo4j integration
- Qdrant/vector-store functionality
- Event parsing and normalization

The project has also been tested with live Redis event publishing and consumption.

## 8. Docker Services

The project uses containerized infrastructure including:

- FastAPI application
- PostgreSQL
- Redis
- Neo4j
- Qdrant
- Prometheus
- Grafana

Wazuh is deployed separately using its Docker-based single-node deployment.

## 9. Configuration

A sanitized .env.example file is included with the submission.

Do not commit real credentials, passwords, API keys, or private configuration files.

Required infrastructure and environment variables depend on the deployment configuration.

## 10. Repository

GitHub:
https://github.com/praweshyadav/autonomous-ai-cybersecurity

## 11. Submission Contents

Source_Code/
    Complete application source code and tests

Documentation/
    Project documentation

Screenshots/
    Project screenshots

Test_Results/
    Testing evidence and results


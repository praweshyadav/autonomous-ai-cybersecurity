# Test Results & Verification

## Autonomous AI Cybersecurity Analyst & Incident Response System

## 1. Automated Test Coverage

The project contains an extensive automated test suite covering the following areas:

- API functionality
- API authentication
- Health checks
- Metrics
- Database persistence
- Redis event processing
- Detection
- Incident correlation
- RAG and retrieval
- LLM connectivity
- LLM investigation components
- Response planning
- Response policy
- Response auditing
- Model loading
- Neo4j integration
- Vector store / Qdrant functionality
- Event parsing
- Event normalization
- Pipeline integration
- End-to-end processing

## 2. Redis Infrastructure Verification

Redis container:

cybersecurity-redis

Connectivity test:

docker exec cybersecurity-redis redis-cli ping

Expected and observed result:

PONG

This confirms that the Redis service was running and accepting connections.

## 3. PostgreSQL Infrastructure Verification

PostgreSQL container:

cybersecurity-postgres

Connectivity test:

docker exec cybersecurity-postgres pg_isready -U cybersecurity -d cybersecurity

Observed result:

ccepting connections

This confirms that PostgreSQL was running and accepting database connections.

## 4. FastAPI Verification

The FastAPI application health endpoint was tested.

Observed response:

{"status":"ok","service":"autonomous-ai-cybersecurity"}

This confirms that the API application was running successfully.

## 5. Live Redis Event Pipeline Test

A controlled live test was performed using the Ubuntu WSL authentication log.

Source:

\\wsl.localhost\Ubuntu\var\log\auth.log

The Redis publisher monitored the authentication log and published newly observed authentication events to the Redis stream:

security_events

### Publisher Results

Observed events included:

event_id=LINUX-AUTH-d6c674fa848a0872

	ype=invalid_user

src_ip=127.0.0.1

and

event_id=LINUX-AUTH-e37503529f804872

	ype=authentication_failure

src_ip=127.0.0.1

Both events were successfully published to Redis.

### Redis Worker Results

The Redis worker successfully consumed the events.

Observed processing:

Processed 1 event(s).

event_id=LINUX-AUTH-d6c674fa848a0872

and

Processed 1 event(s).

event_id=LINUX-AUTH-e37503529f804872

The worker reported the configured handlers:

['detection', 'incident_manager']

This verifies the live flow:

WSL auth.log
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

The controlled test used 127.0.0.1 and did not target an external system.

## 6. Redis Worker Verification

The Redis worker was successfully started after correcting environment initialization.

Observed startup:

Redis worker started.

Handlers: ['detection', 'incident_manager']

Waiting for Redis events...

The worker also successfully saved Redis checkpoints while processing events.

## 7. Wazuh Verification

A controlled authentication test was performed against the Ubuntu WSL environment.

The resulting security event was observed through the following pipeline:

Ubuntu authentication log
    ->
Wazuh Agent
    ->
Wazuh Manager
    ->
Wazuh Rule Processing
    ->
Wazuh Dashboard

The Wazuh dashboard displayed an authentication-related alert for a non-existent user.

Observed details included:

- Rule: 5710
- Description: sshd: Attempt to login using a non-existent user
- Source address: 127.0.0.1
- Test username: wronguser
- Alert level: 5

This verifies that Wazuh successfully collected and processed the controlled authentication event.

## 8. Docker Infrastructure

The following project services were verified as running during testing:

- cybersecurity-api
- cybersecurity-grafana
- cybersecurity-prometheus
- cybersecurity-neo4j
- cybersecurity-qdrant
- cybersecurity-postgres
- cybersecurity-redis

Wazuh services were also running through the Wazuh Docker deployment.

## 9. Security / Safety of Live Testing

The live authentication tests were controlled tests against the local Ubuntu WSL environment.

The tested source address was:

127.0.0.1

No external target was used for the demonstrated authentication tests.

## 10. Environment Configuration

The submission contains a sanitized:

.env.example

Real credentials, passwords, API keys, and private .env configuration are excluded from the submission source copy.

## 11. Repository

GitHub:

https://github.com/praweshyadav/autonomous-ai-cybersecurity

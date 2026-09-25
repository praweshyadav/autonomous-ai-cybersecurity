from prometheus_client import Counter, Histogram


API_REQUESTS_TOTAL = Counter(
    "cybersecurity_api_requests_total",
    "Total number of HTTP requests handled by the cybersecurity API.",
    ["method", "path", "status"],
)

API_REQUEST_DURATION_SECONDS = Histogram(
    "cybersecurity_api_request_duration_seconds",
    "HTTP request duration in seconds for the cybersecurity API.",
    ["method", "path"],
)

API_ERRORS_TOTAL = Counter(
    "cybersecurity_api_errors_total",
    "Total number of HTTP responses with status code 400 or higher.",
    ["method", "path", "status"],
)

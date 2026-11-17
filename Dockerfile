# syntax=docker/dockerfile:1
# Multi-stage / lightweight enterprise base image
FROM python:3.11-alpine AS base

# Create non-root system security user for least-privilege compliance
RUN addgroup -S aegis && adduser -S aegis -G aegis

WORKDIR /app

# Copy application files
COPY engine/ /app/engine/
COPY dashboard/ /app/dashboard/
COPY target_app/ /app/target_app/
COPY README.md /app/

# Set ownership to non-root user
RUN chown -R aegis:aegis /app

# Switch to unprivileged security context
USER aegis

EXPOSE 8080

# Default command launches the web posture dashboard
CMD ["python3", "dashboard/server.py"]

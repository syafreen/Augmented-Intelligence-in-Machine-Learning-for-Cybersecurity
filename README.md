# Augmented Intelligence in Machine Learning for Cybersecurity

This project implements an intelligent Intrusion Detection and Response platform that combines **machine learning**, **explainable AI**, and **threat intelligence** to support Security Operations Center (SOC) analysts.

At a high level, the system:

- Ingests network flow data and evaluates it using an ensemble of machine learning models.
- Produces risk scores, severity levels, and human-readable explanations for each detection.
- Enriches detections with external IP reputation information from honeypot or threat‑intelligence sources.
- Presents the results in an interactive web dashboard designed for analysts.

---

## High-Level Architecture

- **ML & Explainability Layer**
  - Uses multiple trained models to detect malicious traffic and anomalies.
  - Normalizes and scales features consistently with the original training pipeline.
  - Generates per-detection explanations that highlight the most influential features and deviations from typical behaviour.

- **Application & API Layer**
  - Exposes a service interface for authentication, detections, analytics, and honeypot insights.
  - Implements token-based authentication with protections against brute-force attempts.
  - Centralizes error handling and logging for observability.

- **Persistence Layer**
  - Uses a relational database to persist detections, analyst feedback, and login activity.
  - Stores both structured fields (for querying and statistics) and the full detection payload (for flexible downstream analysis).
  - Takes all connection details and credentials from environment variables or external configuration.

- **Analyst Dashboard**
  - Provides a modern web interface for monitoring detections and trends.
  - Allows analysts to inspect individual detections, review explanations, and record feedback.
  - Visualizes honeypot and login telemetry to highlight suspicious IPs and authentication patterns.

---

## Setup & Installation (Conceptual)

### Setup & Installation (Conceptual)

To run the full stack, the typical flow is:

1. **Prepare the backend environment**
   - Create and activate a Python virtual environment.
   - Install the backend dependencies from the provided dependency list.
   - Ensure the trained models and configuration files are available to the backend.

2. **Configure infrastructure and security**
   - Provision a relational database instance and create appropriate user credentials.
   - Configure environment variables for:
     - Database connectivity.
     - Authentication secrets and administrative credentials.
     - Optional honeypot / threat‑intelligence integration.
   - Optionally adjust detection thresholds, model weights, and application ports via external configuration.

3. **Start the backend services**
   - Launch the backend so that it:
     - Initializes logging and configuration.
     - Ensures database tables exist.
     - Loads models and optional explainability components.

4. **Prepare and run the frontend**
   - Install JavaScript dependencies with a package manager.
   - Configure the frontend to point to the backend’s API via environment-based configuration.
   - Start a development server during development, or build and serve a production-ready bundle.

Once these steps are complete, an analyst can open the dashboard in a browser, authenticate, and start working with live detections, explanations, and honeypot analytics.

---

## Example Commands for Local Development

The exact commands may vary slightly by platform, but a typical local workflow looks like this.

### Backend (Python / ML / API)

From the backend directory:

```bash
# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate      # On Windows
# or: source venv/bin/activate  # On Unix-like systems

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run the backend application
python app.py
```

Before starting the backend, ensure that:

- The database is reachable and the database connection string is provided via environment variables or configuration.
- Authentication secrets and administrative credentials are configured via environment variables.
- Any optional external integrations (for example, honeypot or threat‑intelligence APIs) are configured if required.

### Frontend (Web Dashboard)

From the frontend directory:

```bash
# Install dependencies
npm install

# Start a development server
npm run dev

# Create a production build
npm run build

# Optionally preview the production build locally
npm run preview
```

The frontend expects an API base URL to be provided via its own environment‑based configuration (for example, through a dedicated environment file or variables), rather than being hardcoded.

---

## Security & Operational Considerations

- Keep secrets (authentication keys, database passwords, external API keys) strictly in environment variables or a secret‑management system, not in source control.
- Use strong, unique administrative credentials and rotate them periodically.
- When deploying beyond a local environment, run the application behind secure transport (for example, via a reverse proxy that terminates TLS) and restrict cross‑origin access to trusted frontends.
- Consider adding schema‑migration tooling for database changes and monitoring for model performance drift over time.

---

## Licensing

This project is licensed under the **MIT License**. The full license text is provided in the accompanying license file.

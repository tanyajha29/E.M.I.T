# E.M.I.T. Development Setup Guide
## Evidence-backed Mobile Investigation Tool (Revised Docker-First Strategy)

This document outlines the software requirements, installation steps, and environment verification for E.M.I.T. based on the Docker-First strategy. To keep the Windows host minimal, E.M.I.T. runs its core security analysis tools within containerized runtimes.

---

## 1. Dependency Strategy: Host vs. Docker

To maintain a clean and reproducible environment on a standard 8 GB RAM developer machine, dependencies are split as follows:

### A. Host Dependencies (Installed on Windows)
These are minimal bootstrap runtimes required to check out code, run the local React frontend, run the Python FastAPI orchestrator in development, and orchestrate containers.
1. **Git**: Source control.
2. **Node.js & npm**: For Vite, React, and TypeScript frontend development.
3. **Python (with venv)**: For backend development and package management.
4. **Java JDK 17+**: Required on host for any local auxiliary tasks or linting.
5. **Docker Desktop**: The primary container engine for local databases and security services.

### B. Containerized Dependencies (Run via Docker)
These security tools run strictly inside Docker to avoid polluting the host PATH and deal with JDK/Python version mismatch.
1. **MobSF (Mobile Security Framework)**: Run using the official `opensecurity/mobile-security-framework-mobsf:latest` image. Performs static APK decompilation, manifest inspection, and security analysis.
2. **Androguard**: Runs inside the backend container to parse APK files and extract DEX info.
3. **JADX & APKTool**: Bundled inside MobSF container or custom analysis containers. No global host installation required.
4. **tshark**: Runs inside the backend/analysis container to parse PCAP file uploads (static PCAP analysis).
5. **Scapy**: Installed inside the backend Python container/virtual environment for static PCAP file packet parsing.

---

## 2. Environment Status Checklist

| Tool | Category | Status | Version | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Git** | Host (Required) | **PASS** | 2.51.0.windows.2 | Installed and accessible |
| **Node.js** | Host (Required) | **PASS** | v22.20.0 | Installed and accessible |
| **npm** | Host (Required) | **PASS** | 9.9.4 | Installed and accessible |
| **Python** | Host (Required) | **PASS** | 3.13.7 | Installed and accessible (venv verified) |
| **Java JDK** | Host (Required) | **PASS** | openjdk 17.0.20.1 | Installed and accessible |
| **Docker Desktop** | Host (Required) | **PASS** | 29.0.1 | Daemon running and hello-world verified |
| **MobSF Image** | Docker (Required) | **PASS** | Latest | Pulled and execution verified |
| **Wireshark / tshark**| Host (Optional) | **FAIL** | Not Found | Optional; Docker handles containerized tshark |

---

## 3. Tool Analysis & Docker Reliability

| Dependency | Can run in Docker? | Reliability / Configuration Details |
| :--- | :--- | :--- |
| **MobSF** | **Yes (Highly Reliable)** | Run using the official `opensecurity/mobile-security-framework-mobsf:latest` image. Since we restrict analysis to **static Android analysis only** (no dynamic analysis, no Android emulator, no Frida), it runs with low footprint and doesn't require any host virtualization bypasses. |
| **Androguard** | **Yes (Highly Reliable)** | Runs inside the backend Python container/virtual environment. Simple Python-based static parser. |
| **JADX** | **Yes (Highly Reliable)** | Java decompiler. Bundled inside the MobSF container. Can also be added to a custom backend container if direct Java generation is needed outside MobSF. |
| **APKTool** | **Yes (Highly Reliable)** | Java decompiler for resources. Bundled inside the MobSF container. |
| **tshark** | **Yes (Highly Reliable)** | Used for **static PCAP analysis only**. PCAP files are uploaded via FastAPI and parsed inside the container. Since no live network capture is performed, it runs reliably without special host network capabilities (`--net=host` is not required). |
| **Scapy** | **Yes (Highly Reliable)** | Python packet parsing library. Installed as a pip dependency in the backend container for static PCAP parsing. |

---

## 4. Verification Commands

### A. Host Verification
* **Git**: `git --version`
* **Node.js / npm**: `node --version` and `npm --version`
* **Python**: `python --version`
* **JDK**: `java -version`
* **Docker Client**: `docker --version`

### B. Docker Runtime Verification
* **Docker Daemon & Hello World**:
  ```powershell
  docker run hello-world
  ```
* **MobSF Image Pull & Run Verification**:
  ```powershell
  docker pull opensecurity/mobile-security-framework-mobsf:latest
  docker run -d --name mobsf-test -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
  ```

---

## 5. Host Optimization (8 GB RAM Constraints)

Running Docker Desktop and WSL 2 on an 8 GB RAM Windows host can cause resource starvation. To optimize:
1. Create/edit `C:\Users\<Your-Username>\.wslconfig` and limit WSL 2 memory:
   ```ini
   [wsl2]
   memory=4GB
   ```
2. Set Docker Desktop resource limits to match the 4GB cap.
3. Stop the MobSF container (`docker stop mobsf-test`) when not actively performing static mobile analysis.

---

## 6. Database Setup (MongoDB)

E.M.I.T. utilizes **MongoDB** as its primary persistence engine. Relational engines (Supabase, PostgreSQL, SQLite) have been superseded and are not utilized.

### A. Local Setup (MongoDB Community Server)
1. Install MongoDB Community Server locally, or run MongoDB via Docker Desktop:
   ```powershell
   docker run -d --name mongodb-local -p 27017:27017 mongo:latest
   ```
2. Set configuration variables in `backend/.env`:
   ```env
   MONGODB_URI=mongodb://localhost:27017
   MONGODB_DATABASE=emit
   ```
3. Initialize the collections and indexes:
   ```powershell
   python scripts/init_mongodb.py
   ```

### B. Cloud Setup (MongoDB Atlas)
1. Deploy a free tier cluster (M0) on MongoDB Atlas.
2. In the Atlas console, go to **Network Access** and add your IP address to allow traffic. In local development, you may use `0.0.0.0/0` to allow all IP addresses, but do NOT use this in production.
3. Append the Atlas connection string to `backend/.env`:
   ```env
   MONGO_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/?appName=Cluster0
   MONGO_DB_NAME=emit_forensics
   ```

---

## 7. MobSF (Mobile Security Framework) Configuration

E.M.I.T. can connect to a containerized MobSF instance to enrich static APK analysis:

1. **Pull and Launch MobSF via Docker**:
   ```powershell
   docker run -d --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
   ```
2. **Retrieve API Key**:
   * Open `http://localhost:8000` in your browser.
   * Navigate to the REST API section or inspect the container log (`docker logs mobsf`) to locate the auto-generated REST API key.
3. **Configure Backend Environment**:
   In `backend/.env`:
   ```env
   ENABLE_PROVIDER_MOBSF=true
   MOBSF_URL=http://localhost:8000
   MOBSF_API_KEY=your-mobsf-api-key-here
   ```
4. **Verify MobSF Availability**:
   Query `GET http://localhost:8000/health` to confirm `mobsf.available: true`.

---

## 8. Legacy Supabase Configuration Note

In early project design (Phase 1), a relational Supabase/PostgreSQL schema was evaluated. However, **MongoDB was selected as the permanent, authoritative database engine** starting in Phase 2 due to the nested, polymorphic JSON documents produced by APK decompilation and PCAP protocol dissection.

If you are migrating from an experimental Supabase instance:
1. No Supabase tables or schemas are required for E.M.I.T. v1.0+.
2. Any historical `SUPABASE_URL` or `SUPABASE_KEY` variables in `.env` can be safely removed.
3. All persistent data resides exclusively in MongoDB collections via `backend/scripts/init_mongodb.py`.



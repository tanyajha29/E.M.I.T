# E.M.I.T. Production Deployment & Operations Guide

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Deployment Target:** On-Premises Forensic Workstations, Air-Gapped Labs, or Dedicated SOC VPCs

---

## 1. Architecture Overview

E.M.I.T. is packaged as a containerized or service-oriented architecture comprising:
1. **Frontend Service**: React single-page application built with Vite and Tailwind CSS, served via Nginx or a lightweight static file server.
2. **Backend Service**: FastAPI asynchronous application running under Uvicorn with multi-worker concurrency.
3. **Database Service**: MongoDB Community/Enterprise instance (or MongoDB Atlas Cloud).
4. **Analysis Containers**: Optional containerized MobSF and Tshark execution environments.

```
       [ Client Browser (SOC Analyst) ]
                      │
              :80 / :443 (TLS)
                      ▼
             [ Reverse Proxy (Nginx) ]
              │                     │
       /api/* │                     │ /* (Static SPA)
              ▼                     ▼
     [ FastAPI Backend ]     [ React Frontend ]
      (:8000 / Python)        (:5173 / Vite Dist)
              │
      ┌───────┴───────┬───────────────┐
      ▼               ▼               ▼
 [ MongoDB ]    [ Storage ]    [ Docker MobSF ]
  (:27017)       (Encrypted      (:8000 Local)
                  Volume)
```

---

## 2. Environment Configuration

All environment variables must be declared in `backend/.env`. A template is provided at `backend/.env.example`:

```ini
# Core Backend Configuration
ENV=production
DEBUG=false
ALLOWED_ORIGINS=https://emit.internal.domain,http://localhost:5173

# Authoritative MongoDB Database Connection
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=emit_forensics

# Evidence File Storage Limits
MAX_EVIDENCE_SIZE_BYTES=524288000 # 500 MB

# Analysis Providers Activation
ENABLE_PROVIDER_ANDROGUARD=true
ENABLE_PROVIDER_SCAPY=true
ENABLE_PROVIDER_MOBSF=false
ENABLE_PROVIDER_TSHARK=false

# Optional MobSF Container Endpoint
MOBSF_URL=http://localhost:8000
MOBSF_API_KEY=your-mobsf-api-key

# Optional External Threat Intelligence Credentials
ENABLE_THREAT_INTEL_VIRUSTOTAL=false
VIRUSTOTAL_API_KEY=your-virustotal-key

ENABLE_THREAT_INTEL_URLHAUS=false

ENABLE_THREAT_INTEL_ABUSEIPDB=false
ABUSEIPDB_API_KEY=your-abuseipdb-key

ENABLE_THREAT_INTEL_OTX=false
OTX_API_KEY=your-alienvault-key

THREAT_INTEL_CACHE_HOURS=24
```

---

## 3. Deployment via Docker Compose

Create a `docker-compose.yml` file in the root directory:

```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:7.0
    container_name: emit-mongodb
    restart: unless-stopped
    ports:
      - "27017:27017"
    volumes:
      - mongo-data:/data/db
    environment:
      MONGO_INITDB_DATABASE: emit_forensics

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: emit-backend
    restart: unless-stopped
    ports:
      - "8000:8000"
    env_file:
      - ./backend/.env
    volumes:
      - evidence-storage:/app/storage
    depends_on:
      - mongodb

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: emit-frontend
    restart: unless-stopped
    ports:
      - "80:80"
    depends_on:
      - backend

volumes:
  mongo-data:
  evidence-storage:
```

### Launch Commands
```bash
# Initialize MongoDB indexes
python backend/scripts/init_mongodb.py

# Launch all services
docker compose up -d --build

# Verify container health
docker compose ps
curl http://localhost:8000/health
```

---

## 4. Operational Hardening Best Practices

1. **Storage Volume Isolation**: Mount the evidence `storage/` directory on a dedicated, encrypted partition (e.g. BitLocker or LUKS).
2. **Network Segmentation**: Isolate the analysis host in a restricted VLAN or sandbox network to prevent accidental lateral communication.
3. **Log Rotation**: Configure log rotation on Uvicorn and Nginx to avoid disk exhaustion during long-term investigation runs.
4. **Air-Gapped Operation**: When deploying in classified or air-gapped environments, set all `ENABLE_THREAT_INTEL_*` variables to `false`. E.M.I.T. will function autonomously without any external internet connection.

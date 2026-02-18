# ZedID — Zero Trust Identity Dashboard & AI Policy Generator

<div align="center">

![ZedID Banner](https://img.shields.io/badge/ZedID-Zero%20Trust%20Identity-6366f1?style=for-the-badge&logo=rust)
![Tetrate Buildathon 2026](https://img.shields.io/badge/Tetrate-Buildathon%202025-0ea5e9?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-f97316?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/License-Apache%202.0-22c55e?style=for-the-badge)

**A next-generation identity control plane built with Rust, powered by Tetrate TARS.**

[Live Demo](#-running-locally-on-windows) · [Architecture](#️-architecture) · [API Reference](#-api-reference) · [TARS Integration](#-tars-integration)

</div>

---

## 🎯 What is ZedID?

ZedID is a **Zero Trust identity control plane** that solves a critical problem in modern cloud-native environments: *how do you manage, visualize, and enforce identity-based access policies across workloads, humans, and AI agents — all from a single pane of glass?*

ZedID answers this by combining:
- **SPIFFE/SPIRE** for cryptographic workload identity (X.509 SVIDs)
- **JWT tokens** for human and AI agent identity
- **OPA Rego, AWS Cedar, and Istio AuthorizationPolicy** for policy enforcement
- **Tetrate TARS** for AI-powered, natural-language policy generation

### The Problem ZedID Solves

In a typical microservices environment, security teams face:
1. **Identity sprawl** — hundreds of workloads, humans, and AI agents with no unified view
2. **Policy complexity** — writing Rego/Cedar policies requires deep expertise
3. **Audit gaps** — no single place to see who accessed what, when, and why
4. **AI governance** — AI agents (like TARS) need identities and budget controls too

ZedID addresses all four with a single Rust binary.

---

## ✨ Features

| Feature | Description | Standard |
|---------|-------------|----------|
| 🛡️ **Identity Dashboard** | Real-time view of all workload, human, and AI agent identities | SPIFFE/SPIRE |
| 🤖 **AI Policy Generator** | Generate production-ready policies from plain English via TARS | OPA, Cedar, Istio |
| ⚡ **Policy Decision Engine** | Sub-millisecond policy evaluation with OPA-compatible semantics | NIST SP 800-207 |
| 📜 **SVID Inspector** | Issue and inspect SPIFFE X.509 Verifiable Identity Documents | SPIFFE RFC |
| 🔑 **JWT Token Issuance** | Issue signed JWT tokens for human and AI agent identities | OAuth2/OIDC |
| 📊 **Audit Log** | Immutable, structured audit trail for every identity and policy decision | SOC 2 / ISO 27001 |
| 🌐 **Zero Trust Posture** | NIST SP 800-207 compliance dashboard | Zero Trust Architecture |

---

## 🏗️ Architecture

ZedID is structured as a **Cargo workspace** with three focused crates:

```
zedid/
├── zedid-core/          # Axum web server, REST API, dashboard UI
│   ├── src/
│   │   ├── main.rs      # Server entrypoint, router setup
│   │   ├── config.rs    # Environment-based configuration
│   │   ├── state.rs     # Shared application state (Arc<RwLock<...>>)
│   │   └── api/
│   │       ├── mod.rs         # Route registration
│   │       ├── health.rs      # GET /health, GET /system/info
│   │       ├── identities.rs  # CRUD + SVID + JWT token endpoints
│   │       ├── policies.rs    # Policy CRUD + AI generation + evaluation
│   │       └── audit.rs       # Audit log endpoints
│   └── static/
│       ├── index.html   # Single-page dashboard UI
│       ├── style.css    # Dark-mode glassmorphism design system
│       └── app.js       # Vanilla JS frontend (no framework needed)
│
├── zedid-identity/      # Identity models, SPIFFE/SVID, JWT
│   └── src/
│       ├── models.rs    # Identity, Svid, AuditEvent, TrustLevel
│       ├── spiffe.rs    # SpiffeId parser, SpireClient (simulated)
│       ├── jwt.rs       # JwtService — issue & validate HS256 tokens
│       └── error.rs     # IdentityError enum
│
└── zedid-policy/        # Policy engine, TARS client, AI generator
    └── src/
        ├── models.rs    # Policy, PolicyKind, AccessModel, Decision types
        ├── engine.rs    # PolicyEngine — in-memory store + OPA-compatible eval
        ├── generator.rs # PolicyGenerator — TARS-powered AI generation
        ├── tars.rs      # TarsClient — OpenAI-compatible TARS HTTP client
        └── error.rs     # PolicyError enum
```

### Data Flow

```
Browser / curl
     │
     ▼
┌─────────────────────────────────────────┐
│  zedid-core  (Axum HTTP Server :8080)   │
│                                         │
│  GET  /api/v1/identities                │
│  POST /api/v1/identities                │
│  GET  /api/v1/identities/:id/svid       │
│  POST /api/v1/identities/:id/token      │
│  POST /api/v1/policies/generate   ──────┼──► TARS API (LLM routing)
│  POST /api/v1/policies/evaluate         │
│  GET  /api/v1/audit                     │
└─────────────────────────────────────────┘
     │                    │
     ▼                    ▼
zedid-identity       zedid-policy
(SPIFFE/JWT)         (OPA/Rego engine)
```

### Identity Types

| Kind | Auth Protocol | SPIFFE ID | Use Case |
|------|--------------|-----------|----------|
| `workload` | SPIFFE X.509 SVID | `spiffe://domain/ns/{ns}/sa/{name}` | Microservices, containers |
| `human` | JWT (HS256) | None | Developers, operators |
| `ai_agent` | SPIFFE X.509 SVID | `spiffe://domain/ns/{ns}/agent/{name}` | TARS agents, LLM workers |
| `service_account` | SPIFFE X.509 SVID | `spiffe://domain/ns/{ns}/sa/{name}` | CI/CD, automation |

### Trust Levels

| Level | Value | Description |
|-------|-------|-------------|
| `untrusted` | 0 | Newly registered, not yet attested |
| `low` | 1 | Basic authentication only |
| `medium` | 2 | MFA verified |
| `high` | 3 | Hardware-attested or SPIFFE-verified |
| `critical` | 4 | Privileged admin identity |

---

## 🤖 TARS Integration

ZedID integrates with **Tetrate Agent Router Service (TARS)** to route policy generation requests to the optimal LLM.

### How It Works

```
User Intent (natural language)
        │
        ▼
┌───────────────────┐
│  PolicyGenerator  │  Builds a structured prompt with:
│  (generator.rs)   │  - Policy format (Rego/Cedar/Istio)
│                   │  - Access model (RBAC/ABAC/Zero Trust)
│                   │  - Subjects, resources, actions
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   TarsClient      │  HTTP POST to TARS endpoint
│   (tars.rs)       │  OpenAI-compatible API format
│                   │  Bearer token authentication
└────────┬──────────┘
         │
         ▼
   TARS Router ──► Best LLM (Gemini 2.0 Flash / GPT-4o / etc.)
         │
         ▼
┌───────────────────┐
│  PolicyEngine     │  Validates generated policy:
│  (engine.rs)      │  - Syntax checks (package, allow/deny)
│                   │  - Coverage scoring
│                   │  - Subject/resource/action completeness
└───────────────────┘
```

### TARS Client Implementation

The TARS client (`zedid-policy/src/tars.rs`) implements the OpenAI-compatible chat completions API:

```rust
// Initialize TARS client
let client = TarsClient::new(
    "https://api.router.tetrate.ai/v1",
    Some("your-tars-api-key".to_string()),
);

// Generate a policy via TARS
let (policy_code, model_used, tokens) = client
    .generate_policy(
        "Allow checkout service to read inventory. Deny all writes.",
        &PolicyKind::Rego,
    )
    .await?;
```

### Simulation Mode

Without a TARS API key, ZedID automatically runs in **simulation mode** — generating realistic policy stubs locally. This is perfect for demos and development.

```
TARS_MODE: simulation (demo mode)   ← No API key needed
TARS_MODE: live-tars                ← With TARS_API_KEY set
TARS_MODE: local-ollama             ← With localhost endpoint
```

---

## 📋 Policy Formats Supported

### 1. OPA Rego (Primary)
```rego
package zedid.production.inventory

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input.subject == "spiffe://tetrate.io/ns/production/sa/checkout"
    input.action in {"GET", "LIST"}
    input.resource == "inventory-service"
    input.trust_level >= 3
}
```

### 2. AWS Cedar
```cedar
permit (
    principal is ZedID::Identity,
    action in [ZedID::Action::"GET", ZedID::Action::"LIST"],
    resource is ZedID::Resource
)
when {
    principal.trust_level >= 2 &&
    resource.name == "inventory-service"
};
```

### 3. Istio AuthorizationPolicy
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: checkout-reads-inventory
  namespace: production
spec:
  selector:
    matchLabels:
      app: inventory-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "spiffe://tetrate.io/ns/production/sa/checkout"
      to:
        - operation:
            methods: ["GET", "LIST"]
```

### 4. RBAC YAML
```yaml
apiVersion: zedid.tetrate.io/v1
kind: RBACPolicy
spec:
  roles:
    - name: inventory-reader
      rules:
        - resources: ["inventory-service"]
          verbs: ["get", "list"]
  roleBindings:
    - role: inventory-reader
      subjects:
        - kind: ServiceAccount
          spiffeId: "spiffe://tetrate.io/ns/production/sa/checkout"
```

---

## 🚀 Running Locally on Windows

### Prerequisites

1. **Rust & Cargo** (1.75 or later)
   ```powershell
   # Install via rustup (https://rustup.rs)
   winget install Rustlang.Rustup
   # Or download from: https://rustup.rs
   rustup update stable
   ```

2. **Visual Studio C++ Build Tools** (required for Rust on Windows)
   ```powershell
   winget install Microsoft.VisualStudio.2022.BuildTools
   # Select "Desktop development with C++" workload
   ```

3. **Git** (to clone the repository)
   ```powershell
   winget install Git.Git
   ```

### Step-by-Step Setup

**1. Clone the repository**
```powershell
git clone https://github.com/your-username/zedid.git
cd zedid
```

**2. Configure environment variables**
```powershell
# Copy the example config
Copy-Item .env.example .env

# Edit .env with your preferred editor
notepad .env
```

The `.env` file controls all ZedID configuration:
```ini
# Required: your SPIFFE trust domain
ZEDID_TRUST_DOMAIN="tetrate.io"

# Optional: TARS API key for live LLM policy generation
# Without this, ZedID uses simulation mode (still fully functional)
# TARS_API_KEY="your-tars-api-key-here"
TARS_ENDPOINT="https://api.router.tetrate.ai/v1"

# Security: change this in any non-demo environment
ZEDID_JWT_SECRET="z3did-suPer-s3cr3t-k3y-d0-n0t-us3-th1s-1n-pr0d"
ZEDID_JWT_ISSUER="zedid.tetrate.io"

# Database (in-memory SQLite — data resets on restart)
DATABASE_URL="sqlite::memory:"

# Server port
PORT=8080

# Log level
RUST_LOG="zedid=debug,tower_http=info,axum=info"
```

**3. Build the project**
```powershell
# Development build (fast compile, debug symbols)
cargo build

# Production build (optimized, ~3x faster runtime)
cargo build --release
```

**4. Run ZedID**
```powershell
# Development (from workspace root)
cargo run -p zedid-core

# Or run the compiled binary directly
.\target\debug\zedid.exe

# Production binary
.\target\release\zedid.exe
```

**5. Open the dashboard**

Navigate to **[http://localhost:8080](http://localhost:8080)** in your browser.

You should see:
```
🛡️  ZedID — Identity Dashboard & Policy Generator
   Built with Rust × Tetrate TARS × Zero Trust
   Tetrate Buildathon 2026
Trust domain: tetrate.io
TARS endpoint: https://api.router.tetrate.ai/v1
🚀 ZedID API server listening on http://0.0.0.0:8080
📊 Dashboard available at http://localhost:8080
📖 API health at http://localhost:8080/api/v1/health
```

### Verifying the Installation

```powershell
# Check health endpoint
Invoke-RestMethod http://localhost:8080/api/v1/health

# Expected output:
# status  service version timestamp
# ------  ------- ------- ---------
# healthy ZedID   0.1.0   2025-02-18T...

# List demo identities
Invoke-RestMethod http://localhost:8080/api/v1/identities

# List demo policies
Invoke-RestMethod http://localhost:8080/api/v1/policies

# Generate a policy via TARS (simulation mode)
$body = @{
    intent = "Allow checkout service to read inventory data"
    kind = "rego"
    access_model = "zero_trust"
    namespace = "production"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://localhost:8080/api/v1/policies/generate `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

### Running Tests

```powershell
# Run all tests across the workspace
cargo test --workspace

# Run tests with output visible
cargo test --workspace -- --nocapture

# Run only identity crate tests
cargo test -p zedid-identity
```

---

## 📖 API Reference

Base URL: `http://localhost:8080/api/v1`

### Health & System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/system/info` | System capabilities and TARS mode |

### Identity Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/identities` | List all identities |
| `POST` | `/identities` | Create a new identity |
| `GET` | `/identities/:id` | Get identity by UUID |
| `GET` | `/identities/:id/svid` | Issue a SPIFFE SVID for a workload |
| `POST` | `/identities/:id/token` | Issue a JWT token for any identity |

**Create Identity Request:**
```json
{
  "name": "payment-service",
  "kind": "workload",
  "namespace": "production",
  "email": null
}
```

**Issue Token Request:**
```json
{
  "ttl_minutes": 60
}
```

### Policy Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/policies` | List policies (optional `?namespace=production`) |
| `POST` | `/policies` | Create a policy manually |
| `GET` | `/policies/:id` | Get policy by UUID |
| `POST` | `/policies/generate` | **AI-generate a policy via TARS** |
| `POST` | `/policies/evaluate` | Evaluate a policy decision |
| `POST` | `/policies/:id/activate` | Activate a draft/disabled policy |
| `POST` | `/policies/:id/disable` | Disable an active policy |

**Generate Policy Request:**
```json
{
  "intent": "Allow the checkout service to read inventory data but deny all writes",
  "kind": "rego",
  "access_model": "zero_trust",
  "namespace": "production",
  "subjects": ["spiffe://tetrate.io/ns/production/sa/checkout"],
  "resources": ["inventory-service"],
  "actions": ["GET", "LIST"]
}
```

**Evaluate Policy Request:**
```json
{
  "subject": "spiffe://tetrate.io/ns/production/sa/checkout",
  "resource": "inventory-service",
  "action": "GET",
  "namespace": "production",
  "context": {
    "trust_level": 3,
    "mfa_verified": true
  }
}
```

### Audit Log

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/audit` | List recent audit events (last 100) |
| `GET` | `/audit/stats` | Audit statistics (allow/deny counts) |

---

## 🔒 Security Design

### Zero Trust Principles (NIST SP 800-207)

ZedID enforces all five Zero Trust tenets:

1. **Verify explicitly** — Every request requires a valid SPIFFE SVID or JWT token with trust level verification
2. **Use least privilege** — Policies default to `deny`; access must be explicitly permitted
3. **Assume breach** — All decisions are logged to the immutable audit trail
4. **Verify identity continuously** — SVIDs have short TTLs (1 hour for workloads, 4 hours for AI agents)
5. **Micro-segmentation** — Policies are scoped to namespaces and specific subjects/resources

### SPIFFE Identity Format

```
spiffe://tetrate.io/ns/production/sa/checkout-service
         ├─────────┤ ├──────────┤ ├─┤ ├───────────────┤
         trust domain namespace  type  workload name
```

### JWT Claims

ZedID-issued JWT tokens include:
```json
{
  "sub": "identity-uuid",
  "iss": "zedid.tetrate.io",
  "aud": ["zedid-api"],
  "exp": 1234567890,
  "name": "checkout-service",
  "namespace": "production",
  "kind": "workload",
  "trust_level": 3,
  "spiffe_id": "spiffe://tetrate.io/ns/production/sa/checkout-service"
}
```

---

## 🧪 Testing

```powershell
# Run all unit tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture

# Test the JWT roundtrip specifically
cargo test -p zedid-identity test_jwt_roundtrip -- --nocapture
```

The test suite covers:
- JWT token issuance and validation roundtrip
- SPIFFE ID parsing and validation
- Policy validation logic

---

## 🗺️ Roadmap (Post-Hackathon)

| Feature | Priority | Description |
|---------|----------|-------------|
| Real SPIRE gRPC | High | Connect to actual SPIRE Agent via tonic |
| PostgreSQL backend | High | Replace in-memory store with sqlx + PostgreSQL |
| OPA REST integration | High | Call real OPA `/v1/data` endpoint for evaluation |
| mTLS enforcement | Medium | Envoy/Istio sidecar integration |
| OIDC provider | Medium | Full OAuth2/OIDC flow for human identities |
| Policy versioning | Medium | Git-like policy history and rollback |
| Webhook alerts | Low | Slack/PagerDuty alerts on policy violations |
| Multi-cluster | Low | Federation across multiple trust domains |

---

## 🏆 Hackathon Highlights

### Why Rust?

- **Memory safety** — No buffer overflows or use-after-free in the identity control plane
- **Performance** — Sub-millisecond policy evaluation, handles thousands of concurrent requests
- **Correctness** — The type system prevents entire classes of bugs at compile time
- **Async-first** — Tokio runtime with Axum for non-blocking I/O throughout

### Why TARS?

TARS (Tetrate Agent Router Service) is the ideal backbone for ZedID's AI policy generator because:
- **Model routing** — Automatically selects the best LLM (Gemini, GPT-4o) for policy complexity
- **Cost control** — Budget enforcement per agent per day, enforced by ZedID's own policies
- **Governance** — AI agents in ZedID have SPIFFE identities and are subject to the same policies they generate

### Demo Scenario

The default demo seeds 9 identities and 3 policies that tell a complete Zero Trust story:

1. **`checkout-service`** (workload, trust=high) — can READ inventory, not write
2. **`tars-policy-agent`** (AI agent, trust=medium) — can route through TARS within budget
3. **`admin`** (human, trust=critical) — full access with MFA + session age requirements

---

## 📜 License

Apache 2.0 — See [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ in Rust for the **Tetrate Buildathon 2025**

*ZedID — Because every identity deserves a zero trust future.*

</div>

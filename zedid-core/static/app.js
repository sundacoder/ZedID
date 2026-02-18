/* =============================================
   ZedID — JavaScript Application
   Connects to Rust/axum backend API
   ============================================= */

const API = 'http://localhost:8080/api/v1';

// ---- State ----
let state = {
  identities: [],
  policies: [],
  auditEvents: [],
  evalHistory: [],
  generatedPolicy: null,
  currentView: 'dashboard',
};

// ---- Quick intent examples ----
const QUICK_INTENTS = [
  {
    intent: "Allow the checkout service to read inventory data but deny all write operations. Require trust level 2 or higher and verify the SPIFFE identity.",
    kind: "rego", model: "zero_trust", namespace: "production",
    subjects: "spiffe://tetrate.io/ns/production/sa/checkout",
    resources: "inventory-service", actions: "GET, LIST, HEAD"
  },
  {
    intent: "AI agents with trust level 2 or higher may route requests through TARS. Enforce daily token budget limits of 10000 tokens per agent. High-risk models require trust level 3.",
    kind: "rego", model: "abac", namespace: "ai-platform",
    subjects: "spiffe://tetrate.io/ns/ai-platform/agent/tars-policy-agent",
    resources: "tars-router", actions: "route"
  },
  {
    intent: "Platform administrators with trust level 4 (Critical) and active MFA sessions under 60 minutes old have full access to all ZedID management APIs.",
    kind: "rego", model: "rbac", namespace: "system",
    subjects: "role:platform-admin", resources: "zedid-api/*", actions: "*"
  },
  {
    intent: "Isolate the payment service so it can only communicate with the auth service and the payment gateway. All other inbound and outbound traffic must be denied.",
    kind: "istio_authz", model: "zero_trust", namespace: "production",
    subjects: "spiffe://tetrate.io/ns/production/sa/payment-service",
    resources: "payment-gateway, auth-service", actions: "POST, GET"
  },
];

// ---- Eval presets ----
const EVAL_PRESETS = [
  { subject: "spiffe://tetrate.io/ns/production/sa/checkout", resource: "inventory-service", action: "GET", namespace: "production" },
  { subject: "spiffe://tetrate.io/ns/production/sa/checkout", resource: "inventory-service", action: "DELETE", namespace: "production" },
  { subject: "spiffe://tetrate.io/ns/ai-platform/agent/tars-policy-agent", resource: "tars-router", action: "route", namespace: "ai-platform" },
  { subject: "spiffe://tetrate.io/ns/unknown/sa/rogue-service", resource: "payment-gateway", action: "POST", namespace: "production" },
];

// ---- Navigation ----
function showView(viewName) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const view = document.getElementById(`view-${viewName}`);
  const nav = document.getElementById(`nav-${viewName}`);
  if (view) view.classList.add('active');
  if (nav) nav.classList.add('active');

  state.currentView = viewName;

  const titles = {
    dashboard: 'Dashboard',
    identities: 'Identity Inventory',
    svid: 'SPIFFE / SVID Inspector',
    policies: 'Policy Management',
    generator: 'AI Policy Generator',
    evaluate: 'Policy Evaluation',
    audit: 'Audit Log',
  };
  const breadcrumbs = {
    dashboard: 'ZedID / Overview',
    identities: 'ZedID / Identity / Inventory',
    svid: 'ZedID / Identity / SPIFFE',
    policies: 'ZedID / Policies / List',
    generator: 'ZedID / Policies / AI Generator',
    evaluate: 'ZedID / Policies / Evaluate',
    audit: 'ZedID / Observability / Audit',
  };

  document.getElementById('page-title').textContent = titles[viewName] || viewName;
  document.getElementById('breadcrumb').textContent = breadcrumbs[viewName] || '';

  // Load data for the view
  if (viewName === 'dashboard') loadDashboard();
  if (viewName === 'identities') renderIdentityCards();
  if (viewName === 'policies') renderPolicies();
  if (viewName === 'svid') populateSvidSelect();
  if (viewName === 'audit') loadAudit();
}

// ---- Data loading ----
async function loadAll() {
  try {
    const [identRes, polRes] = await Promise.all([
      fetch(`${API}/identities`).catch(() => null),
      fetch(`${API}/policies`).catch(() => null),
    ]);

    if (identRes && identRes.ok) {
      const data = await identRes.json();
      state.identities = data.identities || [];
      // Update trust domain label
      if (data.trust_domain) {
        document.getElementById('trust-domain-label').textContent = data.trust_domain;
      }
    } else {
      // Use demo data if API not available
      state.identities = getDemoIdentities();
    }

    if (polRes && polRes.ok) {
      const data = await polRes.json();
      state.policies = data.policies || [];
    } else {
      state.policies = getDemoPolicies();
    }

    updateBadges();
    loadDashboard();
  } catch (e) {
    console.warn('API not reachable, using demo data:', e.message);
    state.identities = getDemoIdentities();
    state.policies = getDemoPolicies();
    updateBadges();
    loadDashboard();
  }
}

function updateBadges() {
  document.getElementById('identity-count-badge').textContent = state.identities.length;
  const activePolicies = state.policies.filter(p => p.status === 'active').length;
  document.getElementById('policy-count-badge').textContent = activePolicies;
}

// ---- Dashboard ----
function loadDashboard() {
  // Stats
  animateCount('stat-identities', state.identities.length);

  const activePolicies = state.policies.filter(p => p.status === 'active').length;
  animateCount('stat-policies', activePolicies);

  const svids = state.identities.filter(i => i.spiffe_id && i.is_active).length;
  animateCount('stat-svids', svids);

  animateCount('stat-audit', state.auditEvents.length);

  // Identity breakdown
  const workloads = state.identities.filter(i => i.kind === 'workload').length;
  const humans = state.identities.filter(i => i.kind === 'human').length;
  const agents = state.identities.filter(i => i.kind === 'ai_agent').length;
  const total = state.identities.length || 1;

  document.getElementById('bd-workload').textContent = workloads;
  document.getElementById('bd-human').textContent = humans;
  document.getElementById('bd-agent').textContent = agents;

  // Update bar widths
  const bars = document.querySelectorAll('.breakdown-bar');
  if (bars[0]) bars[0].style.width = `${(workloads/total*100).toFixed(0)}%`;
  if (bars[1]) bars[1].style.width = `${(humans/total*100).toFixed(0)}%`;
  if (bars[2]) bars[2].style.width = `${(agents/total*100).toFixed(0)}%`;

  // Policy health
  renderPolicyHealth();

  // Recent identities table
  renderRecentIdentities();
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const step = Math.max(1, Math.floor(target / 20));
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 40);
}

function renderPolicyHealth() {
  const container = document.getElementById('policy-health-list');
  if (!container) return;
  if (state.policies.length === 0) {
    container.innerHTML = '<div class="loading-pulse">No policies found</div>';
    return;
  }
  container.innerHTML = state.policies.map(p => `
    <div class="policy-health-item">
      <div class="status-dot status-${p.status}"></div>
      <span class="ph-name">${p.name}</span>
      <span class="ph-kind">${kindLabel(p.kind)}</span>
    </div>
  `).join('');
}

function renderRecentIdentities() {
  const tbody = document.getElementById('recent-identities-body');
  if (!tbody) return;
  const recent = state.identities.slice(0, 8);
  if (recent.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No identities found</td></tr>';
    return;
  }
  tbody.innerHTML = recent.map(i => `
    <tr>
      <td><strong style="color:var(--text-primary)">${i.name}</strong></td>
      <td><span class="kind-badge">${kindEmoji(i.kind)} ${i.kind.replace('_', ' ')}</span></td>
      <td><code style="font-size:11px;color:var(--text-muted)">${i.namespace}</code></td>
      <td>${trustBadge(i.trust_level)}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        ${i.spiffe_id ? `<code style="font-size:10px;color:var(--blue)">${i.spiffe_id}</code>` : '<span style="color:var(--text-muted)">—</span>'}
      </td>
      <td>${i.svid_expiry ? svidTtl(i.svid_expiry) : '<span style="color:var(--text-muted)">—</span>'}</td>
      <td>${i.is_active
        ? '<span style="color:var(--green);font-size:11px;font-weight:700">● Active</span>'
        : '<span style="color:var(--text-muted);font-size:11px">○ Inactive</span>'}</td>
    </tr>
  `).join('');
}

// ---- Identity cards ----
function renderIdentityCards(filter = '') {
  const grid = document.getElementById('identity-cards-grid');
  if (!grid) return;

  const kindFilter = document.getElementById('identity-kind-filter')?.value || '';
  let filtered = state.identities.filter(i => {
    const matchText = !filter || i.name.toLowerCase().includes(filter.toLowerCase())
      || (i.namespace || '').toLowerCase().includes(filter.toLowerCase());
    const matchKind = !kindFilter || i.kind === kindFilter;
    return matchText && matchKind;
  });

  if (filtered.length === 0) {
    grid.innerHTML = '<div class="loading-pulse">No identities match your filter</div>';
    return;
  }

  grid.innerHTML = filtered.map(i => `
    <div class="identity-card">
      <div class="identity-card-header">
        <div style="display:flex;align-items:center;gap:12px">
          <div class="identity-avatar avatar-${i.kind}">
            ${kindEmoji(i.kind)}
          </div>
          <div>
            <div class="identity-name">${i.name}</div>
            <div class="identity-ns">${i.namespace}</div>
          </div>
        </div>
        <div>${i.is_active
          ? '<span style="color:var(--green);font-size:18px">●</span>'
          : '<span style="color:var(--text-muted);font-size:18px">○</span>'}</div>
      </div>
      ${i.spiffe_id ? `<div class="identity-spiffe">${i.spiffe_id}</div>` : ''}
      ${i.email ? `<div style="font-size:11px;color:var(--text-muted);margin-bottom:10px">✉ ${i.email}</div>` : ''}
      <div class="identity-meta">
        ${trustBadge(i.trust_level)}
        <span class="kind-badge">${i.kind.replace('_', ' ')}</span>
        ${i.svid_expiry ? `<span class="svid-ttl">⏱ ${svidTtl(i.svid_expiry)}</span>` : ''}
      </div>
      <div style="margin-top:12px;display:flex;gap:8px">
        ${i.spiffe_id ? `<button class="btn btn-sm" onclick="showSvid('${i.id}')">View SVID</button>` : ''}
        <button class="btn btn-sm" onclick="issueToken('${i.id}')">Issue Token</button>
      </div>
    </div>
  `).join('');
}

function filterIdentities() {
  const filter = document.getElementById('identity-filter')?.value || '';
  renderIdentityCards(filter);
}

// ---- Policies ----
function renderPolicies(filter = '') {
  const list = document.getElementById('policy-list');
  if (!list) return;

  const statusFilter = document.getElementById('policy-status-filter')?.value || '';
  let filtered = state.policies.filter(p => {
    const matchText = !filter || p.name.toLowerCase().includes(filter.toLowerCase())
      || p.description.toLowerCase().includes(filter.toLowerCase());
    const matchStatus = !statusFilter || p.status === statusFilter;
    return matchText && matchStatus;
  });

  if (filtered.length === 0) {
    list.innerHTML = '<div class="loading-pulse">No policies found</div>';
    return;
  }

  list.innerHTML = filtered.map(p => `
    <div class="policy-item">
      <div class="policy-item-header">
        <div>
          <div class="policy-name">${p.name}</div>
          <div class="policy-desc">${p.description}</div>
        </div>
        <div class="policy-actions">
          ${p.status === 'active'
            ? `<button class="btn btn-sm btn-danger" onclick="togglePolicy('${p.id}', 'disable')">Disable</button>`
            : `<button class="btn btn-sm btn-primary" onclick="togglePolicy('${p.id}', 'activate')">Activate</button>`}
        </div>
      </div>
      <div class="policy-meta">
        <span class="policy-kind-badge">${kindLabel(p.kind)}</span>
        <span class="policy-status-badge status-${p.status}-badge">${p.status}</span>
        ${p.ai_generated ? `<span class="ai-badge">🤖 AI Generated${p.ai_model_used ? ' · ' + p.ai_model_used : ''}</span>` : ''}
        <span style="font-size:11px;color:var(--text-muted)">ns: ${p.namespace}</span>
        ${p.validation_passed ? '<span style="font-size:11px;color:var(--green)">✓ Validated</span>' : '<span style="font-size:11px;color:var(--amber)">⚠ Not validated</span>'}
      </div>
      ${p.subjects && p.subjects.length > 0 ? `
        <div style="margin-top:10px;font-size:11px;color:var(--text-muted)">
          <strong style="color:var(--text-secondary)">Subjects:</strong> ${p.subjects.join(', ')}
        </div>` : ''}
      ${p.explanation ? `
        <div style="margin-top:8px;font-size:12px;color:var(--text-muted);padding:8px;background:rgba(255,255,255,0.02);border-radius:6px;border-left:2px solid var(--blue)">
          ${p.explanation.substring(0, 200)}${p.explanation.length > 200 ? '...' : ''}
        </div>` : ''}
    </div>
  `).join('');
}

function filterPolicies() {
  const filter = document.getElementById('policy-filter')?.value || '';
  renderPolicies(filter);
}

async function togglePolicy(id, action) {
  try {
    const res = await fetch(`${API}/policies/${id}/${action}`, { method: 'POST' });
    if (res.ok) {
      const updated = await res.json();
      const idx = state.policies.findIndex(p => p.id === id);
      if (idx >= 0) state.policies[idx] = updated;
      renderPolicies();
      showToast(`Policy ${action}d successfully`, 'success');
    }
  } catch (e) {
    // Demo mode: update locally
    const idx = state.policies.findIndex(p => p.id === id);
    if (idx >= 0) {
      state.policies[idx].status = action === 'activate' ? 'active' : 'disabled';
      renderPolicies();
      showToast(`Policy ${action}d (demo mode)`, 'info');
    }
  }
}

// ---- AI Policy Generator ----
function setQuickIntent(idx) {
  const q = QUICK_INTENTS[idx];
  document.getElementById('gen-intent').value = q.intent;
  document.getElementById('gen-kind').value = q.kind;
  document.getElementById('gen-model').value = q.model;
  document.getElementById('gen-namespace').value = q.namespace;
  document.getElementById('gen-subjects').value = q.subjects || '';
  document.getElementById('gen-resources').value = q.resources || '';
  document.getElementById('gen-actions').value = q.actions || '';
}

async function generatePolicy() {
  const intent = document.getElementById('gen-intent').value.trim();
  if (!intent) { showToast('Please describe your security intent', 'error'); return; }

  const btn = document.getElementById('generate-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Routing through TARS...';

  const subjects = document.getElementById('gen-subjects').value.trim();
  const resources = document.getElementById('gen-resources').value.trim();
  const actions = document.getElementById('gen-actions').value.trim();

  const body = {
    intent,
    kind: document.getElementById('gen-kind').value,
    access_model: document.getElementById('gen-model').value,
    namespace: document.getElementById('gen-namespace').value || 'default',
    subjects: subjects ? subjects.split(',').map(s => s.trim()) : null,
    resources: resources ? resources.split(',').map(s => s.trim()) : null,
    actions: actions ? actions.split(',').map(s => s.trim()) : null,
  };

  try {
    const res = await fetch(`${API}/policies/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (res.ok) {
      const data = await res.json();
      state.generatedPolicy = data;
      renderGeneratedPolicy(data);
      showToast(`Policy generated via ${data.model_used} in ${data.generation_time_ms}ms`, 'success');
    } else {
      throw new Error(`API error: ${res.status}`);
    }
  } catch (e) {
    // Demo mode: simulate generation
    showToast('Using TARS simulation mode', 'info');
    await simulateGeneration(body);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"><path d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z"/></svg> Generate Policy via TARS`;
  }
}

async function simulateGeneration(body) {
  // Simulate network delay
  await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));

  const mockData = {
    policy: {
      id: crypto.randomUUID ? crypto.randomUUID() : 'mock-' + Date.now(),
      name: 'policy-' + body.intent.split(' ').slice(0,4).join('-').toLowerCase().replace(/[^a-z0-9-]/g, ''),
      description: body.intent,
      kind: body.kind,
      access_model: body.access_model,
      status: 'draft',
      content: generateMockPolicyContent(body),
      explanation: generateMockExplanation(body),
      natural_language_intent: body.intent,
      namespace: body.namespace,
      subjects: body.subjects || [],
      resources: body.resources || [],
      actions: body.actions || [],
      ai_generated: true,
      ai_model_used: 'gemini-2.0-flash [via TARS simulation]',
      validation_passed: true,
      created_at: new Date().toISOString(),
      tags: ['ai-generated', 'tars'],
    },
    validation_result: { passed: true, errors: [], warnings: ['Review before production deployment'], coverage_score: 0.85 },
    generation_time_ms: Math.floor(1200 + Math.random() * 800),
    model_used: 'gemini-2.0-flash [via TARS simulation]',
    tokens_used: Math.floor(400 + Math.random() * 600),
  };

  state.generatedPolicy = mockData;
  renderGeneratedPolicy(mockData);
  showToast(`Policy generated via TARS simulation in ${mockData.generation_time_ms}ms`, 'success');
}

function generateMockPolicyContent(body) {
  const ns = body.namespace.replace(/-/g, '_');
  const subject = body.subjects?.[0] || 'spiffe://tetrate.io/ns/default/sa/workload';
  const resource = body.resources?.[0] || 'target-service';
  const actions = body.actions || ['GET'];

  if (body.kind === 'cedar') {
    return `// ZedID Generated Cedar Policy
// Intent: ${body.intent.substring(0, 80)}
// Generated by: TARS → Gemini 2.0 Flash

permit (
    principal is ZedID::Identity,
    action in [${actions.map(a => `ZedID::Action::"${a}"`).join(', ')}],
    resource is ZedID::Resource
)
when {
    principal.spiffe_id like "${subject.replace(/\/[^/]+$/, '')}/*" &&
    resource.name == "${resource}" &&
    principal.trust_level >= 2 &&
    context.session_valid == true
};

forbid (
    principal is ZedID::Identity,
    action in [ZedID::Action::"delete", ZedID::Action::"admin"],
    resource is ZedID::Resource
)
unless {
    principal.trust_level >= 4
};`;
  }

  if (body.kind === 'istio_authz') {
    return `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: zedid-generated
  namespace: ${body.namespace}
  annotations:
    zedid.tetrate.io/generated-by: tars
    zedid.tetrate.io/model: gemini-2.0-flash
spec:
  selector:
    matchLabels:
      app: ${resource}
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "${subject}"
      to:
        - operation:
            methods: [${actions.map(a => `"${a}"`).join(', ')}]
            paths: ["/api/*"]
      when:
        - key: source.principal
          values: ["${subject}"]`;
  }

  if (body.kind === 'rbac_yaml') {
    return `apiVersion: zedid.tetrate.io/v1
kind: RBACPolicy
metadata:
  name: zedid-generated
  namespace: ${body.namespace}
  labels:
    generated-by: zedid-ai
    tars-model: gemini-2.0-flash
spec:
  roles:
    - name: service-accessor
      rules:
        - resources: ["${resource}"]
          verbs: [${actions.map(a => `"${a.toLowerCase()}"`).join(', ')}]
  roleBindings:
    - role: service-accessor
      subjects:
        - kind: ServiceAccount
          spiffeId: "${subject}"
      conditions:
        trustLevel: ">=2"
        mfaRequired: false`;
  }

  // Default: Rego
  return `package zedid.${ns}.generated

import future.keywords.if
import future.keywords.in

# ZedID Generated Policy
# Intent: ${body.intent.substring(0, 80)}
# Generated by: TARS → Gemini 2.0 Flash
# Model: ${body.access_model}
# Zero-trust: deny by default

default allow := false

# Primary allow rule — explicit permit
allow if {
    valid_subject
    valid_resource
    valid_action
    sufficient_trust_level
    not explicitly_denied
}

# Subject must match expected SPIFFE identity
valid_subject if {
    startswith(input.subject, "${subject.replace(/\/[^/]+$/, '')}")
}

# Resource must be the target service
valid_resource if {
    input.resource in {${(body.resources || ['target-service']).map(r => `"${r}"`).join(', ')}}
}

# Only permitted actions are allowed
valid_action if {
    input.action in {${actions.map(a => `"${a}"`).join(', ')}}
}

# Zero Trust: minimum trust level 2 (MFA verified)
sufficient_trust_level if {
    input.trust_level >= 2
}

# Explicit deny conditions
explicitly_denied if {
    input.context.is_revoked == true
}

explicitly_denied if {
    input.trust_level < 1
}

# Audit metadata for every decision
audit := {
    "policy": "zedid-generated",
    "namespace": "${body.namespace}",
    "decision": allow,
    "subject": input.subject,
    "resource": input.resource,
    "action": input.action,
    "timestamp": time.now_ns(),
}`;
}

function generateMockExplanation(body) {
  return `This policy implements **${body.access_model.replace('_', ' ').toUpperCase()}** access control based on your intent.

**What it does:**
- Grants access only to identities matching the specified subject pattern
- Restricts access to the defined resources: ${(body.resources || ['target-service']).join(', ')}
- Permits only the specified actions: ${(body.actions || ['GET']).join(', ')}
- Requires a minimum trust level of 2 (MFA-verified identity)
- Denies access to revoked identities regardless of other conditions

**Security properties:**
- **Deny-by-default**: access is denied unless explicitly permitted by a matching rule
- **Least privilege**: only the minimum necessary actions are allowed
- **Zero trust**: trust level is verified on every request — no implicit trust
- **Audit trail**: every decision produces an audit record for compliance`;
}

function renderGeneratedPolicy(data) {
  const output = document.getElementById('generator-output');
  const resultActions = document.getElementById('result-actions');
  if (!output) return;

  const p = data.policy;
  const v = data.validation_result;

  output.innerHTML = `
    <div class="generated-policy-output">
      <div class="gen-meta">
        <div class="gen-meta-item">🤖 <strong>Model:</strong> ${data.model_used}</div>
        <div class="gen-meta-item">⚡ <strong>Time:</strong> ${data.generation_time_ms}ms</div>
        ${data.tokens_used ? `<div class="gen-meta-item">🔤 <strong>Tokens:</strong> ${data.tokens_used}</div>` : ''}
        <div class="gen-meta-item">📋 <strong>Format:</strong> ${kindLabel(p.kind)}</div>
        <div class="gen-meta-item">🏷 <strong>Namespace:</strong> ${p.namespace}</div>
      </div>

      <div class="validation-result ${v.passed ? 'validation-pass' : 'validation-fail'}">
        ${v.passed ? '✓ Validation passed' : '✗ Validation failed'}
        ${v.warnings.length > 0 ? ` — ⚠ ${v.warnings[0]}` : ''}
        ${v.errors.length > 0 ? ` — ${v.errors[0]}` : ''}
        <span style="float:right">Coverage: ${(v.coverage_score * 100).toFixed(0)}%</span>
      </div>

      <div style="margin-bottom:8px;font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">
        ${kindLabel(p.kind)} Policy
      </div>
      <div class="policy-code-block">${syntaxHighlight(p.content, p.kind)}</div>

      ${p.explanation ? `
        <div style="margin-bottom:8px;font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Explanation</div>
        <div class="policy-explanation">${formatExplanation(p.explanation)}</div>
      ` : ''}
    </div>
  `;

  if (resultActions) resultActions.style.display = 'flex';
}

function syntaxHighlight(code, kind) {
  if (!code) return '';
  // Simple syntax highlighting for Rego
  return code
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/(#[^\n]*)/g, '<span class="rego-comment">$1</span>')
    .replace(/\b(package|import|default|if|not|in|else|every|some|with|as)\b/g, '<span class="rego-keyword">$1</span>')
    .replace(/\b(allow|deny|permit|forbid|true|false|null)\b/g, '<span class="rego-builtin">$1</span>')
    .replace(/"([^"]*)"/g, '<span class="rego-string">"$1"</span>')
    .replace(/\b(\d+)\b/g, '<span class="rego-number">$1</span>');
}

function formatExplanation(text) {
  return text
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n- /g, '<br>• ')
    .replace(/^/, '<p>').replace(/$/, '</p>');
}

function copyPolicy() {
  if (!state.generatedPolicy) return;
  navigator.clipboard.writeText(state.generatedPolicy.policy.content)
    .then(() => showToast('Policy copied to clipboard', 'success'))
    .catch(() => showToast('Copy failed', 'error'));
}

function savePolicy() {
  if (!state.generatedPolicy) return;
  state.policies.push(state.generatedPolicy.policy);
  updateBadges();
  showToast('Policy saved to draft', 'success');
  setTimeout(() => showView('policies'), 800);
}

// ---- Policy Evaluation ----
function setEvalPreset(idx) {
  const p = EVAL_PRESETS[idx];
  document.getElementById('eval-subject').value = p.subject;
  document.getElementById('eval-resource').value = p.resource;
  document.getElementById('eval-action').value = p.action;
  document.getElementById('eval-namespace').value = p.namespace;
}

async function evaluatePolicy() {
  const body = {
    subject: document.getElementById('eval-subject').value.trim(),
    resource: document.getElementById('eval-resource').value.trim(),
    action: document.getElementById('eval-action').value.trim(),
    namespace: document.getElementById('eval-namespace').value.trim(),
    context: { trust_level: 3, mfa_verified: true, session_age_minutes: 15 },
  };

  if (!body.subject || !body.resource || !body.action) {
    showToast('Please fill in subject, resource, and action', 'error');
    return;
  }

  let result;
  try {
    const res = await fetch(`${API}/policies/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      result = await res.json();
    } else {
      throw new Error('API error');
    }
  } catch (e) {
    // Demo mode: simulate evaluation
    result = simulateEvaluation(body);
  }

  renderEvalResult(result, body);

  // Add to history
  state.evalHistory.unshift({ ...result, request: body, timestamp: new Date() });
  renderEvalHistory();
}

function simulateEvaluation(body) {
  // Find matching policy in demo data
  const matchingPolicy = state.policies.find(p => {
    if (p.status !== 'active') return false;
    const subjectMatch = p.subjects.length === 0 || p.subjects.some(s =>
      body.subject.includes(s.replace('*', '')) || s.includes('*'));
    const resourceMatch = p.resources.length === 0 || p.resources.some(r =>
      r === body.resource || r === '*' || r.endsWith('/*'));
    const actionMatch = p.actions.length === 0 || p.actions.some(a =>
      a === body.action || a === '*');
    return subjectMatch && resourceMatch && actionMatch;
  });

  const allowed = !!matchingPolicy;
  return {
    allowed,
    reason: allowed
      ? `Allowed by policy: ${matchingPolicy.name}`
      : 'No matching policy rule — implicit deny (zero trust)',
    policy_id: matchingPolicy?.id,
    policy_name: matchingPolicy?.name,
    evaluation_time_ms: Math.floor(2 + Math.random() * 8),
    decision_id: 'eval-' + Date.now(),
  };
}

function renderEvalResult(result, body) {
  const card = document.getElementById('eval-result-card');
  const container = document.getElementById('eval-result');
  if (!card || !container) return;

  card.style.display = 'block';
  container.innerHTML = `
    <div class="${result.allowed ? 'eval-result-allow' : 'eval-result-deny'}">
      <div class="eval-decision ${result.allowed ? 'eval-allow-text' : 'eval-deny-text'}">
        ${result.allowed ? '✓ ALLOW' : '✗ DENY'}
      </div>
      <div class="eval-detail"><strong>Subject:</strong> ${body.subject}</div>
      <div class="eval-detail"><strong>Resource:</strong> ${body.resource} → <strong>Action:</strong> ${body.action}</div>
      <div class="eval-detail"><strong>Reason:</strong> ${result.reason}</div>
      ${result.policy_name ? `<div class="eval-detail"><strong>Policy:</strong> ${result.policy_name}</div>` : ''}
      <div class="eval-detail"><strong>Evaluated in:</strong> ${result.evaluation_time_ms}ms</div>
      <div class="eval-detail" style="font-size:10px;color:var(--text-muted)"><strong>Decision ID:</strong> ${result.decision_id}</div>
    </div>
  `;
}

function renderEvalHistory() {
  const container = document.getElementById('eval-history');
  if (!container) return;
  if (state.evalHistory.length === 0) {
    container.innerHTML = '<div style="color:var(--text-muted);font-size:12px;padding:16px">No evaluations yet</div>';
    return;
  }
  container.innerHTML = state.evalHistory.slice(0, 10).map(h => `
    <div class="eval-history-item">
      <span class="${h.allowed ? 'eval-allow-dot' : 'eval-deny-dot'}">${h.allowed ? '✓' : '✗'}</span>
      <span style="flex:1;color:var(--text-secondary)">${h.request.subject.split('/').pop()}</span>
      <span style="color:var(--text-muted)">→</span>
      <span style="color:var(--text-secondary)">${h.request.resource}</span>
      <span style="color:var(--text-muted)">·</span>
      <span style="color:var(--text-muted)">${h.request.action}</span>
      <span style="color:var(--text-muted);font-size:10px">${h.evaluation_time_ms}ms</span>
    </div>
  `).join('');
}

// ---- SVID ----
function populateSvidSelect() {
  const select = document.getElementById('svid-identity-select');
  if (!select) return;
  const workloads = state.identities.filter(i => i.spiffe_id);
  select.innerHTML = '<option value="">Choose a workload...</option>' +
    workloads.map(i => `<option value="${i.id}">${i.name} (${i.namespace})</option>`).join('');
}

async function fetchSvid() {
  const id = document.getElementById('svid-identity-select')?.value;
  if (!id) { showToast('Please select a workload identity', 'error'); return; }

  const identity = state.identities.find(i => i.id === id);
  if (!identity) return;

  const result = document.getElementById('svid-result');
  result.innerHTML = '<div class="loading-pulse">Issuing SVID from SPIRE...</div>';

  try {
    const res = await fetch(`${API}/identities/${id}/svid`);
    if (res.ok) {
      const data = await res.json();
      renderSvid(data.svid, identity);
    } else {
      throw new Error('API error');
    }
  } catch (e) {
    // Demo SVID
    const mockSvid = {
      spiffe_id: identity.spiffe_id,
      cert_pem: `-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQD${Math.random().toString(36).substr(2,16).toUpperCase()}==\nSubject: URI:${identity.spiffe_id}\nSerial: ${Math.random().toString(36).substr(2,32)}\n-----END CERTIFICATE-----`,
      key_pem: `-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkjKL${Math.random().toString(36).substr(2,16).toUpperCase()}==\n-----END EC PRIVATE KEY-----`,
      bundle_pem: `-----BEGIN CERTIFICATE-----\n# Trust bundle for: tetrate.io\nMIICpDCCAYwCCQDRootCA==\n-----END CERTIFICATE-----`,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      serial_number: Math.random().toString(36).substr(2,32),
    };
    renderSvid(mockSvid, identity);
  }
}

function renderSvid(svid, identity) {
  const result = document.getElementById('svid-result');
  const ttl = Math.floor((new Date(svid.expires_at) - new Date()) / 1000);
  result.innerHTML = `
    <div class="svid-data">
      <div class="svid-field">
        <div class="svid-key">SPIFFE ID</div>
        <div class="svid-val">${svid.spiffe_id}</div>
      </div>
      <div class="svid-field">
        <div class="svid-key">Issued At</div>
        <div class="svid-val">${new Date(svid.issued_at).toLocaleString()}</div>
      </div>
      <div class="svid-field">
        <div class="svid-key">Expires At</div>
        <div class="svid-val">${new Date(svid.expires_at).toLocaleString()} <span style="color:var(--green)">(TTL: ${ttl}s)</span></div>
      </div>
      <div class="svid-field">
        <div class="svid-key">Serial Number</div>
        <div class="svid-val">${svid.serial_number}</div>
      </div>
      <div class="svid-field">
        <div class="svid-key">X.509 Certificate (PEM)</div>
        <div class="svid-cert">${svid.cert_pem}</div>
      </div>
      <div class="svid-field">
        <div class="svid-key">Trust Bundle</div>
        <div class="svid-cert">${svid.bundle_pem}</div>
      </div>
    </div>
  `;
  showToast(`SVID issued for ${identity.name} — TTL: ${ttl}s`, 'success');
}

function showSvid(id) {
  showView('svid');
  setTimeout(() => {
    const select = document.getElementById('svid-identity-select');
    if (select) { select.value = id; fetchSvid(); }
  }, 100);
}

async function issueToken(id) {
  const identity = state.identities.find(i => i.id === id);
  if (!identity) return;
  try {
    const res = await fetch(`${API}/identities/${id}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl_minutes: 60 }),
    });
    if (res.ok) {
      const data = await res.json();
      showToast(`JWT token issued for ${identity.name} (${data.expires_in_seconds}s TTL)`, 'success');
    } else {
      throw new Error('API error');
    }
  } catch (e) {
    showToast(`Token issued for ${identity.name} (demo mode)`, 'info');
  }
}

// ---- Audit ----
async function loadAudit() {
  try {
    const [eventsRes, statsRes] = await Promise.all([
      fetch(`${API}/audit`),
      fetch(`${API}/audit/stats`),
    ]);
    if (eventsRes.ok) {
      const data = await eventsRes.json();
      state.auditEvents = data.events || [];
    }
    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('audit-total').textContent = stats.total_events;
      document.getElementById('audit-allow').textContent = stats.allow_count;
      document.getElementById('audit-deny').textContent = stats.deny_count;
    }
  } catch (e) {
    // Demo mode
    state.auditEvents = getDemoAuditEvents();
    document.getElementById('audit-total').textContent = state.auditEvents.length;
    document.getElementById('audit-allow').textContent = state.auditEvents.filter(e => e.decision === 'allow').length;
    document.getElementById('audit-deny').textContent = state.auditEvents.filter(e => e.decision === 'deny').length;
  }
  renderAuditTable();
}

function renderAuditTable() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;
  if (state.auditEvents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No audit events yet</td></tr>';
    return;
  }
  tbody.innerHTML = state.auditEvents.map(e => `
    <tr>
      <td style="font-size:11px;font-family:var(--font-mono);color:var(--text-muted)">${new Date(e.timestamp).toLocaleString()}</td>
      <td><code style="font-size:11px;color:var(--blue)">${e.action}</code></td>
      <td style="color:var(--text-secondary)">${e.actor}</td>
      <td style="font-size:11px;color:var(--text-muted)">${e.resource}</td>
      <td><span class="${e.decision === 'allow' ? 'decision-allow' : 'decision-deny'}">${e.decision === 'allow' ? '✓ ALLOW' : '✗ DENY'}</span></td>
      <td style="font-size:11px;color:var(--text-muted)">${e.reason || '—'}</td>
    </tr>
  `).join('');
}

// ---- Modals ----
function showCreateIdentityModal() {
  document.getElementById('create-identity-modal').classList.add('open');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

async function createIdentity() {
  const name = document.getElementById('new-identity-name').value.trim();
  const kind = document.getElementById('new-identity-kind').value;
  const namespace = document.getElementById('new-identity-namespace').value.trim();
  const email = document.getElementById('new-identity-email').value.trim();

  if (!name || !namespace) { showToast('Name and namespace are required', 'error'); return; }

  const body = { name, kind, namespace, email: email || null };

  try {
    const res = await fetch(`${API}/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      const data = await res.json();
      state.identities.push(data.identity);
      updateBadges();
      renderIdentityCards();
      closeModal('create-identity-modal');
      showToast(`Identity '${name}' created successfully`, 'success');
    } else {
      throw new Error('API error');
    }
  } catch (e) {
    // Demo mode
    const newIdentity = {
      id: 'demo-' + Date.now(),
      name, kind, namespace,
      email: email || null,
      trust_level: kind === 'human' ? 'medium' : 'high',
      spiffe_id: kind !== 'human' ? `spiffe://tetrate.io/ns/${namespace}/sa/${name}` : null,
      is_active: true,
      created_at: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      svid_expiry: kind !== 'human' ? new Date(Date.now() + 3600000).toISOString() : null,
    };
    state.identities.push(newIdentity);
    updateBadges();
    renderIdentityCards();
    closeModal('create-identity-modal');
    showToast(`Identity '${name}' created (demo mode)`, 'success');
  }
}

// ---- Toast notifications ----
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  const icons = { success: '✓', error: '✗', info: 'ℹ' };
  toast.innerHTML = `<span style="font-weight:700">${icons[type] || 'ℹ'}</span> ${message}`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(100%)'; toast.style.transition = 'all 0.3s'; setTimeout(() => toast.remove(), 300); }, 3500);
}

// ---- Refresh ----
async function refreshData() {
  showToast('Refreshing data...', 'info');
  await loadAll();
  if (state.currentView === 'identities') renderIdentityCards();
  if (state.currentView === 'policies') renderPolicies();
  if (state.currentView === 'audit') loadAudit();
  showToast('Data refreshed', 'success');
}

// ---- Helpers ----
function kindLabel(kind) {
  const labels = { rego: 'OPA Rego', cedar: 'Cedar', rbac_yaml: 'RBAC YAML', istio_authz: 'Istio AuthZ' };
  return labels[kind] || kind;
}

function kindEmoji(kind) {
  const emojis = { workload: '⚙️', human: '👤', ai_agent: '🤖', service_account: '🔑' };
  return emojis[kind] || '●';
}

function trustBadge(level) {
  const levels = {
    untrusted: { label: 'Untrusted', cls: 'trust-0' },
    low: { label: 'Low', cls: 'trust-1' },
    medium: { label: 'Medium', cls: 'trust-2' },
    high: { label: 'High', cls: 'trust-3' },
    critical: { label: 'Critical', cls: 'trust-4' },
  };
  const l = levels[level] || { label: level, cls: 'trust-2' };
  return `<span class="trust-badge ${l.cls}">${l.label}</span>`;
}

function svidTtl(expiry) {
  const ttl = Math.floor((new Date(expiry) - new Date()) / 1000);
  if (ttl <= 0) return '<span style="color:var(--red)">Expired</span>';
  if (ttl < 300) return `<span style="color:var(--amber)">${ttl}s</span>`;
  return `<span style="color:var(--green)">${Math.floor(ttl/60)}m</span>`;
}

// ---- Demo data ----
function getDemoIdentities() {
  const td = 'tetrate.io';
  return [
    { id: '1', name: 'checkout-service', kind: 'workload', namespace: 'production', trust_level: 'high', spiffe_id: `spiffe://${td}/ns/production/sa/checkout-service`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+3600000).toISOString() },
    { id: '2', name: 'payment-service', kind: 'workload', namespace: 'production', trust_level: 'high', spiffe_id: `spiffe://${td}/ns/production/sa/payment-service`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+3600000).toISOString() },
    { id: '3', name: 'inventory-service', kind: 'workload', namespace: 'production', trust_level: 'high', spiffe_id: `spiffe://${td}/ns/production/sa/inventory-service`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+3600000).toISOString() },
    { id: '4', name: 'auth-service', kind: 'workload', namespace: 'platform', trust_level: 'high', spiffe_id: `spiffe://${td}/ns/platform/sa/auth-service`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+3600000).toISOString() },
    { id: '5', name: 'tars-policy-agent', kind: 'ai_agent', namespace: 'ai-platform', trust_level: 'medium', spiffe_id: `spiffe://${td}/ns/ai-platform/agent/tars-policy-agent`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+14400000).toISOString() },
    { id: '6', name: 'anomaly-detector', kind: 'ai_agent', namespace: 'ai-platform', trust_level: 'medium', spiffe_id: `spiffe://${td}/ns/ai-platform/agent/anomaly-detector`, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: new Date(Date.now()+14400000).toISOString() },
    { id: '7', name: 'alice.chen', kind: 'human', namespace: 'platform', trust_level: 'medium', email: 'alice.chen@tetrate.io', spiffe_id: null, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: null },
    { id: '8', name: 'bob.kumar', kind: 'human', namespace: 'production', trust_level: 'medium', email: 'bob.kumar@tetrate.io', spiffe_id: null, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: null },
    { id: '9', name: 'admin', kind: 'human', namespace: 'system', trust_level: 'critical', email: 'admin@tetrate.io', spiffe_id: null, is_active: true, created_at: new Date().toISOString(), last_seen: new Date().toISOString(), svid_expiry: null },
  ];
}

function getDemoPolicies() {
  return [
    { id: 'p1', name: 'checkout-reads-inventory', description: 'Allow checkout service to read inventory data', kind: 'rego', access_model: 'zero_trust', status: 'active', namespace: 'production', subjects: ['spiffe://tetrate.io/ns/production/sa/checkout-service'], resources: ['inventory-service'], actions: ['GET', 'LIST'], explanation: 'The checkout service is permitted to read inventory data to display product availability. Write operations are explicitly denied.', ai_generated: false, validation_passed: true, tags: ['production'] },
    { id: 'p2', name: 'tars-agent-llm-routing', description: 'TARS AI agent routing policy — controls which LLMs agents can access', kind: 'rego', access_model: 'abac', status: 'active', namespace: 'ai-platform', subjects: ['spiffe://tetrate.io/ns/ai-platform/agent/*'], resources: ['tars-router'], actions: ['route'], explanation: 'AI agents with trust_level >= 2 may route requests through TARS. Budget limits are enforced per agent per day.', ai_generated: true, ai_model_used: 'gemini-2.0-flash', validation_passed: true, tags: ['ai-governance', 'tars'] },
    { id: 'p3', name: 'admin-full-access', description: 'Platform administrators have full access to ZedID management APIs', kind: 'rego', access_model: 'rbac', status: 'active', namespace: 'system', subjects: ['role:platform-admin'], resources: ['zedid-api/*'], actions: ['*'], explanation: 'Platform administrators can perform all operations on ZedID APIs. This policy requires trust_level=4 (Critical).', ai_generated: false, validation_passed: true, tags: ['admin', 'privileged'] },
  ];
}

function getDemoAuditEvents() {
  const now = Date.now();
  return [
    { id: 'a1', identity_id: '1', action: 'identity.create', actor: 'zedid-api', resource: 'identity/checkout-service', decision: 'allow', reason: 'Identity created successfully', timestamp: new Date(now - 300000).toISOString() },
    { id: 'a2', identity_id: '5', action: 'policy.evaluate', actor: 'tars-policy-agent', resource: 'tars-router', decision: 'allow', reason: 'Allowed by policy: tars-agent-llm-routing', timestamp: new Date(now - 240000).toISOString() },
    { id: 'a3', identity_id: '1', action: 'policy.evaluate', actor: 'checkout-service', resource: 'inventory-service', decision: 'allow', reason: 'Allowed by policy: checkout-reads-inventory', timestamp: new Date(now - 180000).toISOString() },
    { id: 'a4', identity_id: '2', action: 'policy.evaluate', actor: 'payment-service', resource: 'admin-api', decision: 'deny', reason: 'No matching policy rule — implicit deny', timestamp: new Date(now - 120000).toISOString() },
    { id: 'a5', identity_id: '9', action: 'identity.token.issue', actor: 'zedid-api', resource: 'identity/admin', decision: 'allow', reason: 'JWT token issued for admin', timestamp: new Date(now - 60000).toISOString() },
  ];
}

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  // Wire up nav clicks
  document.querySelectorAll('.nav-item[data-view]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      showView(item.dataset.view);
    });
  });

  // Global search
  document.getElementById('global-search')?.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    if (state.currentView === 'identities') {
      document.getElementById('identity-filter').value = q;
      filterIdentities();
    } else if (state.currentView === 'policies') {
      document.getElementById('policy-filter').value = q;
      filterPolicies();
    }
  });

  // Load all data
  loadAll();
});

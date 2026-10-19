// Safe DOM helper utilities (strictly uses createElement / textContent / replaceChildren)
let selectedPersonaId = "P1";

function createEl(tag, className, text) {
  const el = document.createElement(tag);
  if (className) {
    el.className = className;
  }
  if (text !== undefined && text !== null) {
    el.textContent = String(text);
  }
  return el;
}

async function loadPersonas() {
  const grid = document.getElementById("persona-grid");
  grid.replaceChildren();
  const resp = await fetch("/api/personas");
  const data = await resp.json();

  data.personas.forEach((p) => {
    const card = createEl(
      "div",
      "persona-card" + (p.id === selectedPersonaId ? " active" : "")
    );
    card.dataset.personaId = p.id;

    const title = createEl("div", "persona-card-title", p.id + " — " + p.name);
    const email = createEl("div", "persona-card-email", p.email);
    const desc = createEl("div", "persona-card-desc", p.role_summary);

    card.appendChild(title);
    card.appendChild(email);
    card.appendChild(desc);

    card.addEventListener("click", () => {
      selectedPersonaId = p.id;
      document.querySelectorAll(".persona-card").forEach((c) => {
        c.classList.toggle("active", c.dataset.personaId === selectedPersonaId);
      });
    });

    grid.appendChild(card);
  });
}

function renderAuditSummary(data, httpStatus) {
  const container = document.getElementById("audit-summary");
  container.replaceChildren();

  if (httpStatus !== 200) {
    const badge = createEl("span", "status-badge status-err", "HTTP " + httpStatus + " " + (data.status || "ERROR"));
    const line1 = createEl("div", "audit-line", "Category: " + (data.category || "ERROR"));
    line1.appendChild(badge);
    const line2 = createEl("div", "audit-line", "Message: " + (data.message || ""));
    const line3 = createEl("div", "audit-line", "Remediation: " + (data.remediation || ""));
    container.appendChild(line1);
    container.appendChild(line2);
    container.appendChild(line3);
    return;
  }

  const bq = data.bq_telemetry || {};
  const bqStatus = bq.status || "UNKNOWN";
  let badgeClass = "status-ok";
  if (bqStatus.includes("PARTIAL")) badgeClass = "status-warn";
  if (bqStatus === "ERROR") badgeClass = "status-err";

  const l1 = createEl("div", "audit-line", "Data-Access Principal (BigQuery & Drive): " + (bq.user_email || data.persona?.email || ""));
  const l2 = createEl("div", "audit-line", "Propagated Header: " + (data.token_source_header || ""));
  const l3 = createEl("div", "audit-line", "BigQuery Status: ");
  l3.appendChild(createEl("span", "status-badge " + badgeClass, bqStatus));

  const l4 = createEl("div", "audit-line", "BigQuery Job ID (Billed to heygreg-telco-demo): " + (bq.job_id || "None (Blocked before job execution)"));
  const l5 = createEl("div", "audit-line", "Rows Visible After RLS: " + String(bq.row_count ?? 0) + " of 8 total [DEMO] HLF accounts");

  container.appendChild(l1);
  container.appendChild(l2);
  container.appendChild(l3);
  container.appendChild(l4);
  container.appendChild(l5);

  if (bq.cls_denial_diagnostic) {
    const clsLine = createEl(
      "div",
      "audit-line",
      "Policy Tag Enforcement: " + bq.cls_denial_diagnostic.summary
    );
    container.appendChild(clsLine);
  }
  if (bq.error_diagnostic) {
    const errLine = createEl(
      "div",
      "audit-line",
      "Diagnostic (" + bq.error_diagnostic.category + "): " + bq.error_diagnostic.summary + " | Fix: " + bq.error_diagnostic.remediation
    );
    container.appendChild(errLine);
  }
}

function renderBqTable(rows) {
  const container = document.getElementById("bq-table-container");
  container.replaceChildren();

  if (!rows || rows.length === 0) {
    container.appendChild(createEl("p", "muted", "0 rows returned."));
    return;
  }

  const table = createEl("table");
  const thead = createEl("thead");
  const headerRow = createEl("tr");
  const cols = [
    "account_id",
    "customer_name",
    "sales_territory",
    "assigned_rep",
    "qoq_case_volume_change_pct",
    "late_deliveries_90d",
    "churn_risk_tier",
    "buyer_state",
    "supplier_rebate_margin_pct",
  ];
  cols.forEach((c) => headerRow.appendChild(createEl("th", "", c)));
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = createEl("tbody");
  rows.forEach((r) => {
    const tr = createEl("tr");
    cols.forEach((c) => {
      let val = r[c];
      if (c === "supplier_rebate_margin_pct" && val === undefined) {
        val = "[REDACTED BY POLICY TAG]";
      }
      tr.appendChild(createEl("td", "", val !== undefined ? String(val) : ""));
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  container.appendChild(table);
}

function renderDriveDocs(driveContext) {
  const container = document.getElementById("drive-list-container");
  container.replaceChildren();
  if (!driveContext) return;

  const allDocs = [
    ...(driveContext.accessible_playbooks || []),
    ...(driveContext.denied_playbooks || []),
  ];

  allDocs.forEach((d) => {
    const item = createEl("div", "drive-item");
    const isOk = d.status_code === 200;
    const badge = createEl(
      "span",
      "status-badge " + (isOk ? "status-ok" : "status-err"),
      isOk ? "200 PERMITTED" : "HTTP " + d.status_code + " DENIED BY DRIVE ACL"
    );
    const titleSpan = createEl("strong", "", d.title + " ");
    item.appendChild(titleSpan);
    item.appendChild(badge);

    if (d.url) {
      const link = createEl("a", "drive-link", "Open Google Doc");
      link.setAttribute("href", d.url);
      link.setAttribute("target", "_blank");
      link.setAttribute("rel", "noopener noreferrer");
      item.appendChild(link);
    }
    container.appendChild(item);
  });
}

async function runTurn() {
  const btn = document.getElementById("run-btn");
  const out = document.getElementById("coaching-output");
  btn.disabled = true;
  out.textContent = "Executing live cross-project BigQuery query + Google Drive v3 API fetch with impersonated persona OAuth token...";

  try {
    const payload = {
      prompt: document.getElementById("prompt-input").value,
      persona_id: selectedPersonaId,
      simulated_header_mode: document.getElementById("header-mode").value,
      include_rebate_margin: document.getElementById("include-margin").checked,
      test_unapproved_table: document.getElementById("test-allowlist").checked,
      synthesize_with_gemini: document.getElementById("use-gemini").checked,
    };

    const resp = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();

    renderAuditSummary(data, resp.status);
    renderBqTable(data.bq_telemetry?.rows || []);
    renderDriveDocs(data.drive_context);
    out.textContent = data.coaching_response || JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Request failed: " + String(err);
  } finally {
    btn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadPersonas();
  document.getElementById("run-btn").addEventListener("click", runTurn);
});

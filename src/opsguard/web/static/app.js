const state = {
  investigation: null,
  events: [],
  selectedIndex: 0,
  evolution: null,
};

const byId = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || `请求失败 (${response.status})`);
  }
  return payload;
}

function setBusy(active) {
  byId("busy-layer").hidden = !active;
  document.querySelectorAll("button").forEach((button) => {
    button.disabled = active;
  });
  if (!active && state.investigation) {
    const governance = itemAt(
      state.investigation.report?.evidence?.governance,
    );
    const decisionLocked = governance?.status !== "awaiting_approval";
    byId("decision-form")
      .querySelectorAll("input, button")
      .forEach((node) => {
        node.disabled = decisionLocked;
      });
  }
}

let toastTimer;
function toast(message) {
  const node = byId("toast");
  node.textContent = message;
  node.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("visible"), 2600);
}

function itemAt(items) {
  if (!items?.length) return null;
  return items[Math.min(state.selectedIndex, items.length - 1)];
}

function tone(status) {
  if (["active", "completed", "validated", "passed"].includes(status)) return "success";
  if (["critical", "high", "failed", "rolled_back", "denied"].includes(status)) return "danger";
  if (["awaiting_approval", "canary", "medium", "validation_failed"].includes(status)) return "warning";
  return "info";
}

function statusLabel(status) {
  const labels = {
    active: "已激活",
    awaiting_approval: "等待审批",
    canary: "灰度中",
    completed: "已完成",
    critical: "严重",
    denied: "已拒绝",
    draft: "草稿",
    failed: "失败",
    high: "高风险",
    low: "低风险",
    medium: "中风险",
    rolled_back: "已回滚",
    validated: "已验证",
    validation_failed: "验证未通过",
  };
  return labels[status] || status || "--";
}

function shortId(value) {
  if (!value) return "--";
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function percentage(value) {
  return Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : "--";
}

function render() {
  const wrapper = state.investigation;
  if (!wrapper) return;
  const report = wrapper.report;
  const evidence = report.evidence || {};
  const alerts = evidence.alerts || [];
  const governance = itemAt(evidence.governance);
  const mappings = itemAt(evidence.attack_mappings);
  const ruleValidation = itemAt(evidence.rule_validations);
  const behavior = itemAt(evidence.behavior_chains);

  byId("investigation-id").textContent = wrapper.investigation_id;
  const reportStatus = byId("report-status");
  reportStatus.textContent = statusLabel(report.status);
  reportStatus.className = `status-badge ${tone(report.status)}`;

  renderCases(alerts, evidence.governance || []);
  renderMetricBand(evidence, governance, mappings, ruleValidation);
  renderTimeline(evidence.events || [], behavior);
  renderAttack(mappings);
  renderGraph(behavior);
  renderRule(ruleValidation);
  renderGovernance(governance);
}

function renderCases(alerts, governanceItems) {
  byId("case-count").textContent = String(alerts.length);
  if (!alerts.length) {
    byId("case-list").innerHTML = '<div class="empty-state">无相关告警</div>';
    return;
  }
  byId("case-list").innerHTML = alerts
    .map((alert, index) => {
      const governance = governanceItems[index];
      const severity = alert.severity || "medium";
      return `
        <button class="case-item ${index === state.selectedIndex ? "active" : ""}" data-case-index="${index}">
          <div class="case-top">
            <span class="severity-mark severity-${escapeHtml(severity)}"></span>
            <strong title="${escapeHtml(alert.title)}">${escapeHtml(alert.title)}</strong>
          </div>
          <div class="case-meta">
            <span>${escapeHtml(statusLabel(severity))}</span>
            <span>${escapeHtml(statusLabel(governance?.status || "investigating"))}</span>
          </div>
          <div class="case-meta">
            <span>${escapeHtml(shortId(alert.alert_id))}</span>
            <span>风险 ${Math.round((alert.risk_score || 0) * 100)}</span>
          </div>
        </button>`;
    })
    .join("");
  document.querySelectorAll("[data-case-index]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedIndex = Number(button.dataset.caseIndex);
      render();
    });
  });
}

function renderMetricBand(evidence, governance, mappings, validation) {
  const values = [
    [evidence.events?.length || 0, "检索范围"],
    [evidence.alerts?.length || 0, "相关结果"],
    [governance ? Math.round(governance.assessment.score * 100) : "--", governance ? statusLabel(governance.assessment.level) : "行为评分"],
    [mappings?.chain?.mappings?.length || 0, "技术映射"],
    [validation ? `v${validation.rule.version}` : "--", validation ? statusLabel(governance?.rule?.status || validation.rule.status) : "生命周期"],
  ];
  const labels = ["事件", "告警", "风险", "ATT&CK", "规则"];
  byId("metric-band").innerHTML = values
    .map(
      ([value, note], index) => `
        <div class="metric">
          <span>${labels[index]}</span>
          <strong>${escapeHtml(value)}</strong>
          <small>${escapeHtml(note)}</small>
        </div>`,
    )
    .join("");
}

function renderTimeline(events, behavior) {
  const chainIds = new Set(behavior?.chain?.event_ids || []);
  const chainEvents = events.filter((event) => chainIds.has(event.event_id));
  byId("timeline-count").textContent = `${chainEvents.length} 个节点`;
  if (!chainEvents.length) {
    byId("timeline").className = "timeline empty-state";
    byId("timeline").textContent = "暂无调查数据";
    return;
  }
  byId("timeline").className = "timeline";
  byId("timeline").innerHTML = chainEvents
    .map((event) => {
      const time = new Date(event.timestamp).toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
      const entity = event.process || event.user || event.domain || event.host || "--";
      const tags = [event.host, event.user, event.process, event.domain]
        .filter(Boolean)
        .map((value) => `<span class="event-tag">${escapeHtml(value)}</span>`)
        .join("");
      return `
        <article class="timeline-item">
          <time class="timeline-time">${escapeHtml(time)}</time>
          <div class="timeline-axis"><span class="timeline-dot"></span></div>
          <div class="timeline-body">
            <strong>${escapeHtml(event.action)} · ${escapeHtml(entity)}</strong>
            <p>${escapeHtml(event.raw_log || event.event_id)}</p>
            <div class="event-tags">${tags}</div>
          </div>
        </article>`;
    })
    .join("");
}

function renderAttack(mappingItem) {
  const mappings = mappingItem?.chain?.mappings || [];
  if (!mappings.length) {
    byId("attack-list").className = "attack-list empty-state";
    byId("attack-list").textContent = "暂无技术映射";
    return;
  }
  byId("attack-list").className = "attack-list";
  byId("attack-list").innerHTML = mappings
    .map(
      (mapping) => `
        <article class="attack-item">
          <span class="attack-code">${escapeHtml(mapping.technique_id)}</span>
          <strong>${escapeHtml(mapping.name)}</strong>
          <div class="confidence-track" title="置信度 ${percentage(mapping.confidence)}">
            <span style="width:${Math.max(0, Math.min(100, mapping.confidence * 100))}%"></span>
          </div>
        </article>`,
    )
    .join("");
}

function renderGraph(behavior) {
  const graph = behavior?.graph;
  const chain = behavior?.chain;
  if (!graph || !chain) {
    byId("behavior-graph").className = "behavior-graph empty-state";
    byId("behavior-graph").textContent = "暂无行为图";
    return;
  }
  byId("graph-meta").textContent = `${graph.nodes.length} 节点 / ${graph.edges.length} 边`;
  const stages = chain.stages || [];
  const groups = {};
  graph.nodes
    .filter((node) => node.kind !== "event")
    .forEach((node) => {
      groups[node.kind] ||= [];
      groups[node.kind].push(node.node_id.split(":").slice(1).join(":"));
    });
  const stageHtml = stages
    .map(
      (stage, index) => `
        <div class="stage-node">
          <span>阶段 ${index + 1}</span>
          <strong>${escapeHtml(stage.replaceAll("_", " "))}</strong>
        </div>`,
    )
    .join("");
  const groupHtml = Object.entries(groups)
    .map(
      ([kind, values]) => `
        <section class="entity-group">
          <h3>${escapeHtml(kind)}</h3>
          <ul>${values.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul>
        </section>`,
    )
    .join("");
  const edgeHtml = graph.edges
    .slice(0, 14)
    .map(
      (edge) => `
        <tr>
          <td>${escapeHtml(shortId(edge.source))}</td>
          <td>${escapeHtml(edge.relation)}</td>
          <td>${escapeHtml(shortId(edge.target))}</td>
        </tr>`,
    )
    .join("");
  byId("behavior-graph").className = "behavior-graph";
  byId("behavior-graph").innerHTML = `
    <div class="stage-flow" style="--stage-count:${Math.max(stages.length, 1)}">${stageHtml}</div>
    <div class="entity-grid">${groupHtml}</div>
    <table class="edge-summary">
      <thead><tr><th>来源</th><th>关系</th><th>目标</th></tr></thead>
      <tbody>${edgeHtml}</tbody>
    </table>`;
}

function renderRule(validation) {
  if (!validation) return;
  const rule = validation.rule;
  byId("rule-title").textContent = rule.name;
  byId("rule-version").textContent = `v${rule.version} · ${statusLabel(rule.status)}`;
  byId("rule-version").className = `status-badge ${tone(rule.status)}`;
  byId("rule-content").textContent = rule.content;
  const result = validation.result;
  const metrics = [
    ["Precision", percentage(result.precision)],
    ["Recall", percentage(result.recall)],
    ["F1", percentage(result.f1)],
    ["误报率", percentage(validation.false_positive_rate)],
    ["TP / FP", `${result.true_positive} / ${result.false_positive}`],
    ["FN / TN", `${result.false_negative} / ${validation.true_negative}`],
    ["执行延迟", `${Number(validation.execution_latency_ms).toFixed(2)} ms`],
    ["数据集", result.dataset],
  ];
  byId("validation-metrics").className = "validation-grid";
  byId("validation-metrics").innerHTML =
    metrics
      .map(
        ([label, value]) => `
          <div class="validation-cell"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`,
      )
      .join("") +
    `<div class="validation-result">
       <strong>验证结论</strong>
       <span class="status-badge ${result.passed ? "success" : "danger"}">${result.passed ? "通过" : "未通过"}</span>
     </div>`;
}

function renderGovernance(governance) {
  if (!governance) return;
  const assessment = governance.assessment;
  byId("risk-badge").textContent = statusLabel(assessment.level);
  byId("risk-badge").className = `status-badge ${tone(assessment.level)}`;
  byId("governance-status").textContent = statusLabel(governance.status);
  byId("governance-status").className = `status-badge ${tone(governance.status)}`;
  const actions = governance.proposal.actions || [];
  byId("response-plan").className = "response-plan";
  byId("response-plan").innerHTML = `
    <div class="risk-score"><strong>${Math.round(assessment.score * 100)}</strong><span>/ 100</span></div>
    <h3>风险因素</h3>
    <ul class="factor-list">${assessment.factors.map((factor) => `<li>${escapeHtml(factor)}</li>`).join("")}</ul>
    <h3>处置动作</h3>
    <ul class="action-list">${actions
      .map(
        (action) => `
          <li class="action-item">
            <strong>${escapeHtml(action.action_type)} · ${escapeHtml(action.target)}</strong>
            <span>${escapeHtml(action.reason)}</span>
          </li>`,
      )
      .join("") || "<li>无自动处置建议</li>"}</ul>`;
  const audits = governance.audit_records || [];
  byId("audit-stream").className = "audit-stream";
  byId("audit-stream").innerHTML = audits.length
    ? audits
        .map(
          (record) => `
            <div class="audit-item">
              <time>${escapeHtml(new Date(record.created_at).toLocaleTimeString("zh-CN", { hour12: false }))}</time>
              <div>
                <strong>${escapeHtml(record.action)}</strong>
                <span>${escapeHtml(record.reason)}</span>
              </div>
            </div>`,
        )
        .join("")
    : '<div class="empty-state">暂无审计记录</div>';
  const locked = governance.status !== "awaiting_approval";
  byId("decision-form").querySelectorAll("input, button").forEach((node) => {
    node.disabled = locked;
  });
}

function renderEvolution(proposal) {
  if (!proposal) {
    byId("recommendation-badge").textContent = "未生成";
    byId("recommendation-badge").className = "status-badge neutral";
    byId("evolution-result").className = "evolution-result empty-state";
    byId("evolution-result").textContent = "暂无候选版本";
    return;
  }
  const baseline = proposal.baseline_validation;
  const candidate = proposal.candidate_validation;
  const rows = [
    ["Precision", baseline.result.precision, candidate.result.precision, proposal.metric_deltas.precision],
    ["Recall", baseline.result.recall, candidate.result.recall, proposal.metric_deltas.recall],
    ["F1", baseline.result.f1, candidate.result.f1, proposal.metric_deltas.f1],
    ["误报率", baseline.false_positive_rate, candidate.false_positive_rate, proposal.metric_deltas.false_positive_rate],
  ];
  byId("recommendation-badge").textContent = proposal.recommended ? "建议进入审批" : "保留复核";
  byId("recommendation-badge").className = `status-badge ${proposal.recommended ? "success" : "warning"}`;
  byId("evolution-result").className = "evolution-result";
  byId("evolution-result").innerHTML = `
    <table class="comparison-table">
      <thead><tr><th>指标</th><th>v${proposal.base_rule.version}</th><th>v${proposal.candidate_rule.version}</th><th>变化</th></tr></thead>
      <tbody>
        ${rows
          .map(([label, before, after, delta]) => {
            const good = label === "误报率" ? delta <= 0 : delta >= 0;
            return `
              <tr>
                <td>${escapeHtml(label)}</td>
                <td>${percentage(before)}</td>
                <td>${percentage(after)}</td>
                <td class="${good ? "delta-positive" : "delta-negative"}">${delta >= 0 ? "+" : ""}${(delta * 100).toFixed(1)}%</td>
              </tr>`;
          })
          .join("")}
      </tbody>
    </table>
    <ul class="rationale-list">${proposal.rationale.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

async function runInvestigation(question) {
  setBusy(true);
  try {
    const data = await api("/api/investigations", {
      method: "POST",
      body: JSON.stringify({ question }),
    });
    state.investigation = data;
    state.selectedIndex = 0;
    state.evolution = null;
    render();
    renderEvolution(null);
    toast("调查链执行完成");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
  }
}

async function submitDecision(approved) {
  if (!state.investigation) return;
  const payload = {
    actor: byId("approval-actor").value.trim(),
    approved,
    reason: byId("approval-reason").value.trim(),
  };
  if (approved) {
    payload.canary_metrics = {
      evaluated_events: Number(byId("canary-events").value),
      false_positive_rate: Number(byId("canary-fpr").value),
      error_rate: Number(byId("canary-errors").value),
      p95_latency_ms: Number(byId("canary-latency").value),
    };
  }
  setBusy(true);
  try {
    state.investigation = await api(
      `/api/investigations/${state.investigation.investigation_id}/decision`,
      { method: "POST", body: JSON.stringify(payload) },
    );
    render();
    toast(approved ? "审批完成，灰度指标已评估" : "审批已拒绝");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
  }
}

async function submitFeedback() {
  if (!state.investigation) return;
  const kind = document.querySelector('input[name="feedback-kind"]:checked').value;
  const payload = {
    event_id: byId("feedback-event").value,
    kind,
    actor: byId("feedback-actor").value.trim(),
    comment: byId("feedback-comment").value.trim(),
  };
  setBusy(true);
  try {
    await api(
      `/api/investigations/${state.investigation.investigation_id}/feedback`,
      { method: "POST", body: JSON.stringify(payload) },
    );
    toast("反馈已写入数据飞轮");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
  }
}

async function evolveRule() {
  if (!state.investigation) return;
  setBusy(true);
  try {
    state.evolution = await api(
      `/api/investigations/${state.investigation.investigation_id}/evolve`,
      { method: "POST", body: "{}" },
    );
    renderEvolution(state.evolution);
    toast("候选规则版本已完成离线对比");
  } catch (error) {
    toast(error.message);
  } finally {
    setBusy(false);
  }
}

function bindStaticEvents() {
  byId("investigation-form").addEventListener("submit", (event) => {
    event.preventDefault();
    runInvestigation(byId("question").value.trim());
  });
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-view").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      byId(`view-${button.dataset.tab}`).classList.add("active");
    });
  });
  byId("decision-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitDecision(true);
  });
  byId("deny-button").addEventListener("click", () => submitDecision(false));
  byId("feedback-form").addEventListener("submit", (event) => {
    event.preventDefault();
    submitFeedback();
  });
  byId("evolve-button").addEventListener("click", evolveRule);
}

async function initialize() {
  bindStaticEvents();
  try {
    state.events = await api("/api/events");
    byId("feedback-event").innerHTML = state.events
      .map(
        (event) => `
          <option value="${escapeHtml(event.event_id)}">
            ${escapeHtml(event.event_id)} · ${escapeHtml(event.action)} · ${escapeHtml(event.label)}
          </option>`,
      )
      .join("");
  } catch (error) {
    toast(error.message);
  }
  await runInvestigation(byId("question").value);
}

initialize();

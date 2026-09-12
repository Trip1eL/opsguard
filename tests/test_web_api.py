from pathlib import Path

from fastapi.testclient import TestClient

from opsguard.web.app import create_app

ROOT = Path(__file__).parents[1]


def _client() -> TestClient:
    return TestClient(create_app(ROOT))


def _investigate(client: TestClient, question: str) -> dict:
    response = client.post(
        "/api/investigations",
        json={"question": question},
    )
    assert response.status_code == 200
    return response.json()


def test_health_and_workspace_are_available() -> None:
    with _client() as client:
        assert client.get("/api/health").json() == {
            "status": "ok",
            "service": "opsguard",
        }
        response = client.get("/")
        model_status = client.get("/api/model/status")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "OpsGuard" in response.text
    assert model_status.status_code == 200
    assert model_status.json()["enabled"] is False


def test_ssh_investigation_requires_separate_human_approval() -> None:
    with _client() as client:
        investigation = _investigate(
            client,
            "调查新来源 SSH 登录后的可疑行为",
        )
        governance = investigation["report"]["evidence"]["governance"][0]

        assert investigation["report"]["status"] == "awaiting_approval"
        assert governance["status"] == "awaiting_approval"
        assert governance["rule"]["status"] == "validated"
        assert governance["response_executions"] == []

        fetched = client.get(
            f"/api/investigations/{investigation['investigation_id']}"
        )

    assert fetched.status_code == 200
    assert fetched.json() == investigation


def test_investigation_parameters_cannot_inject_approval() -> None:
    with _client() as client:
        response = client.post(
            "/api/investigations",
            json={
                "question": "调查 SSH 异常",
                "parameters": {
                    "approval": {
                        "actor": "untrusted-agent",
                        "approved": True,
                    }
                },
            },
        )

    assert response.status_code == 400
    assert "unsupported investigation parameters" in response.json()["detail"]


def test_approved_decision_activates_rule_after_healthy_canary() -> None:
    with _client() as client:
        investigation = _investigate(client, "调查 SSH 持久化攻击链")
        response = client.post(
            f"/api/investigations/{investigation['investigation_id']}/decision",
            json={
                "actor": "soc-lead",
                "approved": True,
                "reason": "已核验证据与离线验证结果",
                "canary_metrics": {
                    "evaluated_events": 1000,
                    "false_positive_rate": 0.01,
                    "error_rate": 0.001,
                    "p95_latency_ms": 30,
                },
            },
        )

    assert response.status_code == 200
    governance = response.json()["report"]["evidence"]["governance"][0]
    assert governance["status"] == "active"
    assert governance["rule"]["status"] == "active"
    assert len(governance["response_executions"]) == 3
    assert any(
        record["action"] == "canary_evaluated"
        for record in governance["audit_records"]
    )

def test_denied_decision_does_not_execute_response() -> None:
    with _client() as client:
        investigation = _investigate(client, "调查 SSH 持久化攻击链")
        response = client.post(
            f"/api/investigations/{investigation['investigation_id']}/decision",
            json={
                "actor": "soc-lead",
                "approved": False,
                "reason": "证据不足，拒绝执行处置",
            },
        )

    assert response.status_code == 200
    governance = response.json()["report"]["evidence"]["governance"][0]
    assert governance["status"] == "denied"
    assert governance["rule"]["status"] == "validated"
    assert governance["response_executions"] == []


def test_decision_cannot_be_replayed_after_finalization() -> None:
    with _client() as client:
        investigation = _investigate(client, "调查 SSH 持久化攻击链")
        endpoint = (
            f"/api/investigations/{investigation['investigation_id']}/decision"
        )
        payload = {
            "actor": "soc-lead",
            "approved": False,
            "reason": "首次决策拒绝处置",
        }
        assert client.post(endpoint, json=payload).status_code == 200
        repeated = client.post(endpoint, json=payload)

    assert repeated.status_code == 400
    assert "not awaiting approval" in repeated.json()["detail"]


def test_false_negative_feedback_generates_better_candidate_version() -> None:
    with _client() as client:
        investigation = _investigate(client, "调查 Web 服务异常子进程")
        investigation_id = investigation["investigation_id"]
        base_rule = investigation["report"]["evidence"]["rule_validations"][0][
            "rule"
        ]
        feedback = client.post(
            f"/api/investigations/{investigation_id}/feedback",
            json={
                "event_id": "evt-web-001",
                "kind": "false_negative",
                "actor": "soc-analyst",
                "comment": "入口 Web 请求属于攻击链但未被现有规则命中",
            },
        )
        proposal = client.post(
            f"/api/investigations/{investigation_id}/evolve"
        )
        stored_feedback = client.get("/api/feedback")

    assert feedback.status_code == 200
    assert stored_feedback.status_code == 200
    assert stored_feedback.json()[0]["event_id"] == "evt-web-001"
    assert proposal.status_code == 200
    body = proposal.json()
    assert body["candidate_rule"]["rule_id"] == base_rule["rule_id"]
    assert body["candidate_rule"]["version"] == base_rule["version"] + 1
    assert body["candidate_rule"]["status"] == "draft"
    assert body["metric_deltas"]["recall"] > 0
    assert body["metric_deltas"]["f1"] > 0
    assert body["recommended"] is True


def test_unknown_investigation_returns_not_found() -> None:
    with _client() as client:
        response = client.get("/api/investigations/missing-investigation")

    assert response.status_code == 404
    assert "unknown investigation" in response.json()["detail"]

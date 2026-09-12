from opsguard.domain.cases import Alert, AlertSeverity, Case


def test_alert_and_case_models_are_separate_from_fixture_labels() -> None:
    alert = Alert(
        alert_id="alert-001",
        title="Suspicious scheduled task",
        severity=AlertSeverity.HIGH,
        risk_score=0.85,
        event_ids=["evt-ssh-003"],
    )
    case = Case(
        case_id="case-ssh-persistence-001",
        title="SSH persistence investigation",
        alert_ids=[alert.alert_id],
        event_ids=alert.event_ids,
        tags=["persistence"],
    )

    assert alert.risk_score == 0.85
    assert case.alert_ids == ["alert-001"]

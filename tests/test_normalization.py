from opsguard.normalization import EventNormalizationError, EventNormalizer


def test_normalizer_dispatches_all_supported_sources() -> None:
    normalizer = EventNormalizer()
    for source in ["linux_audit", "web_access", "process_network"]:
        event = normalizer.normalize(
            {
                "event_id": f"evt-{source}",
                "timestamp": "2026-09-10T00:00:00Z",
                "source": source,
                "action": "test",
                "raw_log": "raw event",
            }
        )
        assert event.source.value == source


def test_normalizer_rejects_unknown_source() -> None:
    normalizer = EventNormalizer()

    try:
        normalizer.normalize(
            {
                "event_id": "evt-unknown",
                "timestamp": "2026-09-10T00:00:00Z",
                "source": "unknown",
                "action": "test",
            }
        )
    except EventNormalizationError as exc:
        assert "unknown event source" in str(exc)
    else:
        raise AssertionError("unknown source should be rejected")


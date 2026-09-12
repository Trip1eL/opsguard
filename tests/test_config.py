from opsguard.config import AppSettings


def test_settings_load_non_secret_values_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("OPSGUARD_ENVIRONMENT", "test")
    monkeypatch.setenv("OPSGUARD_LOG_LEVEL", "debug")
    monkeypatch.setenv("GPT_MODEL_NAME", "test-model")

    settings = AppSettings.from_env()

    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"
    assert settings.model_name == "test-model"


def test_settings_do_not_expose_secret_keys() -> None:
    settings = AppSettings.from_env()
    assert not hasattr(settings, "DEEPSEEK_API_KEY")
    assert not hasattr(settings, "RELAY_API_KEY")

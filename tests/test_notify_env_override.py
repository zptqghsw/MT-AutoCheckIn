"""通知配置的环境变量覆盖（NOTIFY_SMTP_* / NOTIFY_TELEGRAM_* / NOTIFY_FEISHU_*）。

背景：0.6.0 迁移 TOML 后，通知配置只剩 NOTIFY_SMTP_PASSWORD 支持 env，
沿用旧 env 命名的 K8s 部署全部空转，日志出现「无通知渠道」。这里补齐
覆盖并锁住行为：env 优先、TOML 兜底、不设时不误启用渠道。
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from mteam_cli.core.config import Settings
from mteam_cli.notify.factory import build_notifier_hub

TOML_EMPTY = """
[site]
base_url = "https://zp.m-team.io"

[smtp]
host = ""
port = 465
user = ""
from = ""

[[account]]
username = "acct1"
password = "p"
totp_secret = "t"

  [account.notify]
  smtp_to = ""
"""


@pytest.fixture()
def toml_file(tmp_path: Path) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(TOML_EMPTY, encoding="utf-8")
    return p


ALL_NOTIFY_ENVS = (
    "NOTIFY_SMTP_HOST", "NOTIFY_SMTP_PORT", "NOTIFY_SMTP_USER", "NOTIFY_SMTP_FROM",
    "NOTIFY_SMTP_PASSWORD", "NOTIFY_SMTP_USE_TLS", "NOTIFY_SMTP_TO_1",
    "NOTIFY_TELEGRAM_TOKEN_1", "NOTIFY_TELEGRAM_CHAT_ID_1", "NOTIFY_FEISHU_TOKEN_1",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ALL_NOTIFY_ENVS:
        monkeypatch.delenv(name, raising=False)


def test_no_env_no_channels(toml_file, monkeypatch):
    settings = Settings.from_toml(toml_file)
    hub = build_notifier_hub(settings.accounts[0], settings, _logger())
    assert hub.enabled_names == []


def test_smtp_env_enables_channel(toml_file, monkeypatch):
    monkeypatch.setenv("NOTIFY_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("NOTIFY_SMTP_PORT", "465")
    monkeypatch.setenv("NOTIFY_SMTP_USER", "me@gmail.com")
    monkeypatch.setenv("NOTIFY_SMTP_FROM", "me@gmail.com")
    monkeypatch.setenv("NOTIFY_SMTP_PASSWORD", "app-pass")
    monkeypatch.setenv("NOTIFY_SMTP_TO_1", "you@qq.com")

    settings = Settings.from_toml(toml_file)
    assert settings.smtp_host == "smtp.gmail.com"
    assert settings.smtp_port == 465
    assert settings.smtp_from == "me@gmail.com"
    acct = settings.accounts[0]
    assert acct.smtp_to == "you@qq.com"
    assert acct.has_smtp(settings)

    hub = build_notifier_hub(acct, settings, _logger())
    assert hub.enabled_names == ["smtp"]


def test_env_beats_toml(tmp_path, monkeypatch):
    p = tmp_path / "config.toml"
    p.write_text(
        '[smtp]\nhost = "toml.host"\nport = 25\nuser = "toml.user"\nfrom = "toml@x"\n'
        '[[account]]\nusername = "a"\npassword = "p"\ntotp_secret = "t"\n'
        '  [account.notify]\n  smtp_to = "toml@to"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("NOTIFY_SMTP_HOST", "env.host")
    monkeypatch.setenv("NOTIFY_SMTP_TO_1", "env@to")
    settings = Settings.from_toml(p)
    assert settings.smtp_host == "env.host"
    assert settings.smtp_port == 25  # 未设 env → 用 TOML
    assert settings.accounts[0].smtp_to == "env@to"


def test_telegram_and_feishu_env(toml_file, monkeypatch):
    monkeypatch.setenv("NOTIFY_TELEGRAM_TOKEN_1", "tg-token")
    monkeypatch.setenv("NOTIFY_TELEGRAM_CHAT_ID_1", "123")
    monkeypatch.setenv("NOTIFY_FEISHU_TOKEN_1", "fs-token")
    settings = Settings.from_toml(toml_file)
    acct = settings.accounts[0]
    assert acct.has_telegram and acct.has_feishu
    hub = build_notifier_hub(acct, settings, _logger())
    assert set(hub.enabled_names) == {"telegram", "feishu"}


def test_use_tls_env_parse_error(toml_file, monkeypatch):
    monkeypatch.setenv("NOTIFY_SMTP_USE_TLS", "maybe")
    with pytest.raises(SystemExit, match="NOTIFY_SMTP_USE_TLS"):
        Settings.from_toml(toml_file)


def test_port_env_must_be_int(toml_file, monkeypatch):
    monkeypatch.setenv("NOTIFY_SMTP_PORT", "smtps")
    with pytest.raises(SystemExit, match="NOTIFY_SMTP_PORT"):
        Settings.from_toml(toml_file)


def _logger():
    import logging

    return logging.getLogger("test-notify-env")

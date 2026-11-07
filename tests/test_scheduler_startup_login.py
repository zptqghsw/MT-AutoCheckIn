"""启动即登录：DailyScheduler._login_at_startup 行为测试。

用假 tick_factory 验证：
  - 服务 loop 启动后（进入等待循环前）立即对每个可保活账户各调用一次 tick；
  - 无保活凭证的账户被跳过；
  - 单账户 tick 抛异常不阻断其他账户，也不让 loop 崩溃；
  - 每日任务照常排定。
"""

from __future__ import annotations

import logging

import pytest

from mteam_cli.core.config import Account, Settings
from mteam_cli.scheduler.daily import DailyScheduler
from mteam_cli.core.models import CheckinResult


def _mk_account(name: str, full: bool) -> Account:
    return Account(
        username=name,
        password="p" if full else None,
        totp_secret="t" if full else None,
    )


def _mk_settings(accounts: list[Account], tmp_path) -> Settings:
    return Settings(
        base_url="https://zp.m-team.io",
        api_base_url="https://api.m-team.cc/api",
        headless=True,
        slow_mo_ms=0,
        timeout_ms=60_000,
        auth_dir=tmp_path / "auth",
        log_dir=tmp_path / "logs",
        artifact_dir=tmp_path / "artifacts",
        accounts=accounts,
    )


class _LoopDone(Exception):
    """用于在测试中尽早退出 loop() 的无限等待循环。"""


@pytest.fixture()
def _no_real_loop(monkeypatch):
    import schedule as schedule_lib

    # 让 run_pending 第二次调用时抛，退出 while 循环 → loop() 返回。
    calls = {"n": 0}
    orig = schedule_lib.run_pending

    def fake_run_pending():
        calls["n"] += 1
        if calls["n"] >= 2:
            raise _LoopDone
        orig()

    monkeypatch.setattr(schedule_lib, "run_pending", fake_run_pending)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    return calls


class _LoopDone(Exception):
    pass


def test_startup_login_runs_tick_per_keepalive_account(_no_real_loop, tmp_path):
    schedule_lib_jobs_cleared()
    accounts = [_mk_account("alice", True), _mk_account("bob", False), _mk_account("carol", True)]
    settings = _mk_settings(accounts, tmp_path)
    seen: list[str] = []

    async def tick_factory(account):
        seen.append(account.username)
        return 0

    sched = DailyScheduler(settings, logging.getLogger("t"), tick_factory)
    with pytest.raises(_LoopDone):
        sched.loop()
    assert seen == ["alice", "carol"], "启动即登录应只覆盖有保活凭证的账户"
    assert len([j for j in _jobs()]) >= 2, "每日任务仍应照常排定"


def test_startup_login_exception_does_not_stop_others(_no_real_loop, tmp_path):
    schedule_lib_jobs_cleared()
    accounts = [_mk_account("dave", True), _mk_account("erin", True)]
    settings = _mk_settings(accounts, tmp_path)
    seen: list[str] = []

    async def tick_factory(account):
        seen.append(account.username)
        if account.username == "dave":
            raise RuntimeError("boom")
        return 0

    sched = DailyScheduler(settings, logging.getLogger("t"), tick_factory)
    with pytest.raises(_LoopDone):
        sched.loop()
    assert "erin" in seen, "单账户启动登录崩溃不应阻止后续账户"


def schedule_lib_jobs_cleared():
    import schedule as schedule_lib

    schedule_lib.clear()


def _jobs():
    import schedule as schedule_lib

    return schedule_lib.jobs

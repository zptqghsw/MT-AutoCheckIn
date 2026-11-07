"""Keep-alive browser login for one account.

Preserves the proven login logic from the original script:
  1. Try restoring the per-account localStorage snapshot (skips 2FA).
  2. Fall back to username + password + TOTP, handling the observed 2FA
     variants (direct redirect / ``#otp-code`` input / "確認" button).
  3. Confirm success by intercepting the ``/api/member/profile`` XHR and
     matching ``data.username`` against the configured account, with the URL
     landed on ``/index``. On success the localStorage snapshot is saved.

TOTP makes this fully automatic — there is no QR / human-in-the-loop.

The 2FA phase is *polled* instead of waiting a fixed timeout once: the OTP
form can appear several seconds after the submit click, and the SPA may
render an inline error toast instead. Both are detected explicitly so a slow
render is never mistaken for "no 2FA element".
"""

from __future__ import annotations

import asyncio
import logging
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pyotp
from playwright.async_api import (
    Error as PlaywrightError,
    Locator,
    Page,
    Response,
    TimeoutError as PlaywrightTimeoutError,
)

from mteam_cli.automation.localstorage import LocalStorageManager
from mteam_cli.core.browser import BrowserSession
from mteam_cli.core.config import Account, Settings
from mteam_cli.core.models import CheckinResult

_PROFILE_ENDPOINT = "/api/member/profile"
_OTP_SELECTOR = 'input[id="otp-code"]'
_SUBMIT_SELECTOR = 'button[type="submit"]'

# 账密/OTP 提交走的认证接口（跨域，落在 api 站）。响应里的 code/message
# 才是"密码对不对、验证码对不对"的权威结论，页面 URL 只是间接信号。
_AUTH_PATH_HINTS = ("/passport/login", "/api/login", "/auth/login", "otp", "2fa")

# 登录失败时 SPA 会在页面上渲染这些字样（繁/简/英文都覆盖）。
_ERROR_HINTS = (
    "錯誤", "错误", "不正確", "不正确", "無效", "无效", "不匹配",
    "失敗", "失败", "已被", "锁定", "鎖定", "過期", "过期",
    "incorrect", "invalid", "wrong", "failed", "expired", "locked",
)


class _LoginAborted(Exception):
    """Internal: a login strategy did not achieve an authenticated session."""


def _index_path(index_url: str) -> str:
    return urlsplit(index_url).path.rstrip("/") or "/index"


def _on_index(page: Page, index_url: str) -> bool:
    """URL 判定放宽为 path 相等，忽略 query/hash（SPA 偶尔带参数跳转）。"""
    try:
        current = page.url
    except PlaywrightError:
        return False
    if current == index_url:
        return True
    return urlsplit(current).path.rstrip("/") == _index_path(index_url)


async def _is_visible(loc: Locator) -> bool:
    try:
        return await loc.count() > 0 and await loc.first.is_visible()
    except PlaywrightError:
        return False


async def _toast_error(page: Page) -> str:
    """Return the page's error-toast text if one is visible, else ""."""
    try:
        candidates = await page.locator(
            ".MuiAlert-root, [class*='toast'], [class*='Toast'], "
            "[class*='alert'], [role='alert']"
        ).all_text_contents()
    except PlaywrightError:
        return ""
    for text in candidates:
        clean = " ".join(text.split())
        if clean and clean != "0" and any(h in clean.lower() or h in clean for h in _ERROR_HINTS):
            return clean[:160]
    return ""


async def _describe(page: Page) -> str:
    """One-line snapshot of where the page actually is, for failure messages."""
    try:
        inputs = ",".join(
            await page.locator("input:visible").evaluate_all(
                "(els) => els.map((e) => e.id || e.type).filter(Boolean)"
            )
        )
        body = " ".join(((await page.locator("body").inner_text()) or "").split())[:120]
        return f"url={page.url} inputs=[{inputs}] text={body!r}"
    except PlaywrightError as exc:
        return f"(页面状态读取失败: {exc})"


async def _await_settled(
    page: Page,
    index_url: str,
    probe: dict[str, Any],
    submit_ts: float,
    wait_s: float,
    *,
    otp_first: bool,
) -> str:
    """Poll after a credential/OTP submit until the page settles.

    认证接口（api/login 等）的响应是权威信号，但两个阶段的解读不同：

    * ``otp_first=True``（刚交完账密）：OTP 表单先出现，"2FA 待输"是正常态，
      此时接口返回的非 0 code 可能只是"需要二次验证"。只有 message 明显
      是报错字样才判为账密被拒；其余情况继续轮询到超时。
    * ``otp_first=False``（刚交完动态码）：表单通常仍在页面上，接口返回非 0
      code 就是验证码被拒。

    Returns one of: ``"index"`` | ``"otp"`` | ``"confirm"`` | ``"error:<msg>"``
    | ``"timeout"``.
    """
    otp = page.locator(_OTP_SELECTOR)
    confirm = page.locator('button:has-text("確認")')
    deadline = time.monotonic() + wait_s
    while True:
        if _on_index(page, index_url):
            return "index"
        if otp_first:
            if await _is_visible(otp):
                return "otp"
            rejected = _probe_rejected(probe, submit_ts, require_hint=True)
        else:
            rejected = _probe_rejected(probe, submit_ts, require_hint=False)
            if not rejected and _probe_success(probe, submit_ts):
                # 接口已确认动态码通过，SPA 跳转只是时间问题。
                return "authed"
        if rejected:
            return f"error:{rejected}"
        err = await _toast_error(page)
        if err:
            return f"error:{err}"
        if await _is_visible(confirm):
            return "confirm"
        if time.monotonic() >= deadline:
            return "timeout"
        await page.wait_for_timeout(1_000)


def _probe_success(probe: dict[str, Any], submit_ts: float) -> bool:
    """本次提交后认证接口是否返回成功 code。"""
    if probe.get("auth_at", 0.0) < submit_ts:
        return False
    code = probe.get("auth_code")
    return code is not None and _code_is_ok(code)


def _probe_rejected(probe: dict[str, Any], submit_ts: float, *, require_hint: bool) -> str:
    """若本次提交后认证接口明确返回失败，返回其 message；否则 ""。

    ``require_hint=True`` 时只在 message 含报错字样才判失败——账密提交阶段
    接口也可能返回"需要 2FA"之类的非 0 code，不能当成密码错。
    """
    if probe.get("auth_at", 0.0) < submit_ts:
        return ""
    code = probe.get("auth_code")
    msg = probe.get("auth_msg") or ""
    if code is None:
        return ""
    if _code_is_ok(code):
        return ""
    if require_hint and not any(h in msg.lower() or h in msg for h in _ERROR_HINTS):
        return ""
    return msg or f"接口返回 code={code}"


def _code_is_ok(code: Any) -> bool:
    if isinstance(code, bool):
        return code
    if isinstance(code, int):
        return code == 0
    return str(code).strip().lower() in {"0", "s00", "success", "200", "ok", "none"}


def _totp_code(secret: str, clock_offset: float, window: int = 0) -> str:
    """按服务器时钟生成 TOTP。

    容器/宿主机时钟漂移几秒就会把码算进错误窗口（实测 +5.6s 即可复现登录
    失败），``clock_offset`` 来自认证接口响应头的 Date 与本地时刻之差。
    ``window`` 为 ±1 个 30s 周期的容错偏移。
    """
    totp = pyotp.TOTP(secret)
    ts = time.time() + clock_offset + window * totp.interval
    return totp.at(ts)


async def _wait_logged_in(page: Page, logged_in, timeout_ms: int) -> bool:
    """轮询登录判定，直到成立或窗口耗尽（URL 已跳转但 profile XHR 稍慢时不误杀）。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if logged_in():
            return True
        await page.wait_for_timeout(1_000)
    return logged_in()


async def perform_login(
    session: BrowserSession,
    account: Account,
    settings: Settings,
    logger: logging.Logger,
) -> CheckinResult:
    """Run the full keep-alive login for ``account`` and return its outcome."""
    page = session.page
    if page is None:
        raise RuntimeError("Browser session has not been started.")

    index_url = f"{settings.base_url}/index"
    login_url = f"{settings.base_url}/login"
    storage_file = str(account.storage_path(settings.auth_dir))

    # Shared holder populated by the intercepted profile XHR.
    profile: dict[str, Any] = {}
    # 认证接口（api/login / passport/login）的权威结论 + 服务器时钟偏移。
    probe: dict[str, Any] = {"auth_at": 0.0, "auth_code": None, "auth_msg": "", "clock_offset": 0.0}

    async def _intercept(route, request) -> None:
        if request.url.endswith(_PROFILE_ENDPOINT):
            logger.info("[%s] 命中 profile 请求: %s", account.username, request.url)
            try:
                response = await route.fetch()
                profile.clear()
                profile.update(await response.json())
                await route.continue_()
                return
            except (ValueError, PlaywrightError) as exc:
                logger.warning("[%s] 读取 profile 响应出错: %s", account.username, exc)
        await route.continue_()

    async def _on_auth_response(response: Response) -> None:
        url = response.url
        if not any(h in url for h in _AUTH_PATH_HINTS) or _PROFILE_ENDPOINT in url:
            return
        rec: dict[str, Any] = {"auth_at": time.time()}
        # 服务器时钟偏移：Date 头（秒级）与本机接收时刻之差，用于换算 TOTP 时间。
        date_hdr = response.headers.get("date")
        if date_hdr:
            try:
                server_epoch = parsedate_to_datetime(date_hdr).timestamp()
                probe["clock_offset"] = server_epoch - rec["auth_at"]
            except (TypeError, ValueError):
                pass
        try:
            body = await response.json()
        except (PlaywrightError, ValueError):
            probe["auth_status"] = response.status
            probe.update(rec)
            logger.info("[%s] 认证接口 %s 返回非 JSON（status=%d）", account.username, url, response.status)
            return
        if isinstance(body, dict):
            rec["auth_code"] = body.get("code")
            rec["auth_msg"] = str(body.get("message") or "")[:200]
        probe.update(rec)
        logger.info(
            "[%s] 认证接口返回 code=%s message=%s", account.username, rec["auth_code"], rec["auth_msg"]
        )

    await page.route(f"**{_PROFILE_ENDPOINT}", _intercept)
    page.on("response", lambda r: asyncio.ensure_future(_on_auth_response(r)))
    logger.info("[%s] 已设置 profile 请求拦截", account.username)

    lsm = LocalStorageManager(page)

    try:
        await session.goto(f"{settings.base_url}/")

        def _logged_in() -> bool:
            data = profile.get("data") if profile else None
            return bool(
                _on_index(page, index_url)
                and data
                and data.get("username") == account.username
            )

        # ── Strategy 1: localStorage ──
        try:
            await _login_by_localstorage(
                page, lsm, storage_file, account, settings, logger, _logged_in
            )
        except _LoginAborted:
            logger.warning("[%s] LocalStorage 登录失败，改用账号密码", account.username)
            await _login_by_password(
                page, lsm, storage_file, login_url, index_url, account, settings, logger,
                _logged_in, probe,
            )

        text = _parse_profile(profile, account)
        logger.info("[%s] 登录成功", account.username)
        return CheckinResult(username=account.username, ok=True, profile_text=text)

    except _LoginAborted as exc:
        logger.error("[%s] 登录失败: %s", account.username, exc)
        return CheckinResult(username=account.username, ok=False, error=str(exc) or "登录失败")
    except PlaywrightError as exc:
        logger.error("[%s] 登录时发生 Playwright 错误: %s", account.username, exc)
        return CheckinResult(username=account.username, ok=False, error=f"Playwright 错误: {exc}")
    finally:
        try:
            await page.unroute(f"**{_PROFILE_ENDPOINT}")
        except PlaywrightError:
            pass


async def _login_by_localstorage(
    page: Page,
    lsm: LocalStorageManager,
    storage_file: str,
    account: Account,
    settings: Settings,
    logger: logging.Logger,
    logged_in,
) -> None:
    logger.info("[%s] 尝试通过 LocalStorage 登录", account.username)
    if not Path(storage_file).exists():
        raise _LoginAborted("无 LocalStorage 快照")
    try:
        await lsm.load_from_file(storage_file)
        await page.reload(timeout=settings.timeout_ms)
        # 轮询直到判定成功或窗口耗尽，不再固定等满 60s。
        deadline = time.monotonic() + min(settings.timeout_ms, 60_000) / 1000
        while time.monotonic() < deadline:
            if logged_in():
                break
            await page.wait_for_timeout(2_000)
    except PlaywrightError as exc:
        raise _LoginAborted(f"LocalStorage 登录出错: {exc}") from exc

    if logged_in():
        await lsm.save_to_file(storage_file)
        logger.info("[%s] LocalStorage 登录成功，已刷新快照", account.username)
        return
    raise _LoginAborted("LocalStorage 登录未确认")


async def _login_by_password(
    page: Page,
    lsm: LocalStorageManager,
    storage_file: str,
    login_url: str,
    index_url: str,
    account: Account,
    settings: Settings,
    logger: logging.Logger,
    logged_in,
    probe: dict[str, Any],
) -> None:
    logger.info("[%s] 尝试通过账号密码登录", account.username)
    try:
        if not page.url.startswith(login_url):
            await page.goto(login_url, timeout=settings.timeout_ms)
        try:
            await page.wait_for_load_state("networkidle", timeout=15_000)
        except PlaywrightTimeoutError:
            pass

        submit = page.locator(_SUBMIT_SELECTOR).first
        await submit.wait_for(state="visible", timeout=settings.timeout_ms)
        await page.locator('input[id="username"]').fill(account.username)
        await page.locator('input[id="password"]').fill(account.password or "")
        submit_ts = time.time()
        await submit.click()
        logger.info("[%s] 已提交账号密码，等待页面响应", account.username)

        await _handle_2fa(page, index_url, account, settings, logger, probe, submit_ts)
    except _LoginAborted:
        raise
    except PlaywrightError as exc:
        raise _LoginAborted(f"账号密码登录出错: {exc}") from exc

    if await _wait_logged_in(page, logged_in, min(settings.timeout_ms, 30_000)):
        await lsm.save_to_file(storage_file)
        logger.info("[%s] 账号密码登录成功，已保存快照", account.username)
        return
    raise _LoginAborted(f"账号密码登录未确认: {await _describe(page)}")


async def _submit_otp(
    page: Page,
    otp: Locator,
    code: str,
    index_url: str,
    account: Account,
    logger: logging.Logger,
    probe: dict[str, Any],
    submit_ts: float,
) -> str:
    """Fill the TOTP code, submit, and report how the page settled."""
    # 逐字键入（而非 fill）：实测更稳妥地触发 React 受控组件的状态更新。
    await otp.click()
    await otp.press_sequentially(code, delay=80)
    await page.locator(_SUBMIT_SELECTOR).first.click()
    logger.info("[%s] 已提交动态验证码，等待结果", account.username)
    return await _await_settled(
        page, index_url, probe, submit_ts, wait_s=40, otp_first=False
    )


async def _handle_2fa(
    page: Page,
    index_url: str,
    account: Account,
    settings: Settings,
    logger: logging.Logger,
    probe: dict[str, Any],
    submit_ts: float,
) -> None:
    """Handle the observed 2FA outcomes after submitting credentials.

    站点在 2FA 表单出现前有数百毫秒到数秒的不确定期（旧实现只查一次，
    慢渲染就被当成"未找到 2FA 元素"），这里改为轮询到页面明确落定。
    """
    state = await _await_settled(
        page, index_url, probe, submit_ts, wait_s=30, otp_first=True
    )

    if state == "index":
        logger.info("[%s] 登录直接成功，无需 2FA", account.username)
        return

    if state.startswith("error:"):
        raise _LoginAborted(f"账号密码被拒绝: {state[6:]}")

    if state == "confirm":
        logger.info("[%s] 出现确认按钮，点击后等待跳转", account.username)
        confirm_ts = time.time()
        await page.locator('button:has-text("確認")').first.click()
        state = await _await_settled(
            page, index_url, probe, confirm_ts, wait_s=30, otp_first=True
        )
        if state == "index":
            return
        if state != "otp":
            raise _LoginAborted(f"点击确认后未进入首页: {state} {await _describe(page)}")

    if state != "otp":
        raise _LoginAborted(f"提交账号密码后未出现 2FA 界面: {await _describe(page)}")

    logger.info("[%s] 检测到双重认证码输入框，准备填写 TOTP", account.username)
    if not account.totp_secret:
        raise _LoginAborted("已出现 2FA 验证码输入框，但未配置 totp_secret")

    otp = page.locator(_OTP_SELECTOR)
    offset = float(probe.get("clock_offset") or 0.0)
    if abs(offset) > 2.0:
        logger.info("[%s] 本地与服务器时钟相差 %+.1fs，按服务器时间生成动态码", account.username, offset)

    # TOTP 有 30s 窗口；时钟读取有误差时可能算错窗口，依次试 当前/上一/下一。
    for window, label in ((0, "当前时间窗"), (-1, "上一时间窗"), (1, "下一时间窗")):
        try:
            code = _totp_code(account.totp_secret, offset, window)
        except ValueError as exc:
            raise _LoginAborted(f"totp_secret 不是合法的 Base32 密钥: {exc}") from exc
        attempt_ts = time.time()
        state = await _submit_otp(page, otp, code, index_url, account, logger, probe, attempt_ts)
        if state in ("index", "authed"):
            logger.info("[%s] 动态验证码通过（%s，状态 %s）", account.username, label, state)
            return
        if state.startswith("error:"):
            logger.warning("[%s] %s的动态码被拒: %s", account.username, label, state[6:])
            continue
        raise _LoginAborted(f"提交动态验证码后未进入首页: {state} {await _describe(page)}")

    raise _LoginAborted(
        "动态验证码连续三个时间窗均被拒绝，请核对 totp_secret 是否与站点 2FA 设置一致"
    )


def _parse_profile(profile: dict[str, Any], account: Account) -> str:
    """Format the intercepted profile into a notification body (legacy parity)."""
    from mteam_cli.api import humanize as hz

    data: dict[str, Any] | None = profile.get("data") if profile else None
    if not data:
        return "获取到的数据为空"

    lines = [
        f"用户ID: {data.get('id')}",
        f"用户名: {data.get('username')}",
        f"用户Email: {data.get('email')}",
        f"登录IP: {data.get('ip')}",
        f"账户创建时间: {data.get('createdDate')}",
        f"账户更新时间: {data.get('lastModifiedDate')}",
    ]

    status = data.get("memberStatus")
    if status:
        lines += [
            f"会员最新登录时间: {status.get('lastLogin')}",
            f"会员最新浏览时间: {status.get('lastBrowse')}",
        ]

    count = data.get("memberCount")
    if count:
        lines += [
            f"上传量: {hz.naturalsize(count.get('uploaded'))}",
            f"下载量: {hz.naturalsize(count.get('downloaded'))}",
            f"魔力值: {hz.num(count.get('bonus'))}",
            f"分享率: {hz.ratio(count.get('shareRate'))}",
        ]

    return "\n".join(lines)

"""运行原签到流程，输出不含凭据的 AgentRouter 响应诊断。"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import checkin
from utils.browser import _SITE_READY_JS

_browser_user_agent: str | None = None


def _report(data: dict) -> None:
	print('[DIAG] ' + json.dumps(data, ensure_ascii=False, sort_keys=True))


def install_diagnostics() -> None:
	"""只观察原请求；不新增请求，不修改 Cookie 或请求参数。"""
	original_send = checkin.httpx.Client.send
	original_wait = checkin.wait_for_waf_ready

	def send(client, request, **kwargs):
		response = original_send(client, request, **kwargs)
		if request.url.host != 'agentrouter.org' or request.url.path != '/api/user/self':
			return response
		try:
			data = {
				'event': 'user_info_response',
				'http_status': response.status_code,
				'content_type': response.headers.get('content-type', '').split(';')[0].lower(),
				'content_encoding': response.headers.get('content-encoding', '').lower(),
				'browser_user_agent_matches': (
					request.headers.get('user-agent') == _browser_user_agent if _browser_user_agent else None
				),
			}
			if response.is_stream_consumed:
				body = response.content
				lower_body = body.lower()
				data['body_bytes'] = len(body)
				data['html_detected'] = any(marker in lower_body for marker in (b'<html', b'<!doctype', b'<script'))
				data['waf_markers'] = [
					marker
					for marker in ('acw_sc__v2', 'acw_tc', 'arg1', 'captcha', 'aliyun', 'verify you are human')
					if marker.encode() in lower_body
				]
				try:
					payload = response.json()
					data['valid_json'] = True
					data['api_success'] = payload.get('success') is True if isinstance(payload, dict) else None
				except (ValueError, UnicodeError):
					data['valid_json'] = False
			_report(data)
		except Exception as exc:
			_report({'event': 'response_diagnostic_error', 'error_type': type(exc).__name__})
		return response

	async def wait_for_waf_ready(page, *args, **kwargs):
		global _browser_user_agent
		_browser_user_agent = None
		await original_wait(page, *args, **kwargs)
		if urlsplit(page.url).hostname != 'agentrouter.org':
			return
		try:
			_browser_user_agent = await page.evaluate('() => navigator.userAgent')
			names = {cookie.get('name') for cookie in await page.context.cookies()}
			_report(
				{
					'event': 'waf_browser_state',
					'site_ready': await page.evaluate(_SITE_READY_JS),
					'cookie_present': {name: name in names for name in ('acw_tc', 'acw_sc__v2', 'cdn_sec_tc')},
				}
			)
		except Exception as exc:
			_report({'event': 'browser_diagnostic_error', 'error_type': type(exc).__name__})

	checkin.httpx.Client.send = send
	checkin.wait_for_waf_ready = wait_for_waf_ready


if __name__ == '__main__':
	install_diagnostics()
	asyncio.run(checkin.main())

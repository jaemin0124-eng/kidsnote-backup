"""Kidsnote sessionid cookie 자동 갱신 스크립트.

동작 순서:
  1. KIDSNOTE_USERNAME / KIDSNOTE_PASSWORD 로 키즈노트 비공식 로그인 API 호출
  2. 응답에서 받은 session_id 가 실제로 유효한지 /api/v1/me/children/ 로 검증
  3. 검증까지 통과해야만 GitHub repo secret `KIDSNOTE_SESSION_COOKIE` 를 덮어씀
     (로그인 API가 이상한 값을 반환해도 기존에 잘 작동하던 쿠키가 깨지지 않도록)

필요한 GitHub repo secrets:
  - KIDSNOTE_USERNAME       : 키즈노트 로그인 아이디
  - KIDSNOTE_PASSWORD       : 키즈노트 로그인 비밀번호
  - GH_PAT                  : "이 repo의 Secrets 를 읽고 쓸 수 있는" Fine-grained PAT
                               (Actions 자체 GITHUB_TOKEN 은 Secrets API 를 못 씀)

이 스크립트는 tools/kidsnote_fetch/ 안의 fetch.py 와 같은 값을 공유합니다:
KIDSNOTE_SESSION_COOKIE secret 하나만 갱신하면 기존 백업 워크플로는 그대로 그 값을 씁니다.
"""
from __future__ import annotations

import base64
import os
import sys

import requests

try:
    from nacl import encoding, public
except ImportError:
    print("Missing dependency: pip install pynacl", file=sys.stderr)
    raise

KIDSNOTE_BASE = "https://www.kidsnote.com"
LOGIN_URL = f"{KIDSNOTE_BASE}/api/web/login"
VERIFY_URL = f"{KIDSNOTE_BASE}/api/v1/me/children/"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "ko",
    "Referer": KIDSNOTE_BASE,
}


def _env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise SystemExit(f"필수 환경변수 누락: {name}")
    return val


def login_and_get_session_id(username: str, password: str) -> str:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    resp = sess.post(
        LOGIN_URL,
        json={"username": username, "password": password, "remember_me": True},
        headers={"Content-Type": "application/json"},
        timeout=20,
    )
    if resp.status_code >= 400:
        raise SystemExit(
            f"로그인 실패 (status={resp.status_code}): {resp.text[:500]}\n"
            "아이디/비밀번호가 맞는지, 계정에 추가 인증(캡차 등)이 걸려있지 않은지 확인하세요."
        )

    # 1순위: 서버가 실제로 내려준 Set-Cookie 의 sessionid 값을 그대로 사용.
    # (JSON body 의 session_id 필드는 값이 다를 수 있어서 신뢰하지 않는다.)
    session_id = sess.cookies.get("sessionid", domain="www.kidsnote.com")
    if not session_id:
        session_id = sess.cookies.get("sessionid", domain=".kidsnote.com")
    if not session_id:
        # 2순위 fallback: 혹시 모르니 JSON body 도 확인
        try:
            data = resp.json()
        except ValueError:
            data = {}
        session_id = data.get("session_id")

    if not session_id:
        cookie_names = [c.name for c in sess.cookies]
        raise SystemExit(
            "로그인 응답에서 sessionid 쿠키를 찾지 못했습니다.\n"
            f"응답으로 받은 쿠키 이름들: {cookie_names}\n"
            f"응답 본문 일부: {resp.text[:300]}"
        )
    return session_id


def verify_session(session_id: str) -> bool:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    sess.cookies.set("sessionid", session_id, domain="www.kidsnote.com", path="/")
    resp = sess.get(VERIFY_URL, timeout=20)
    return resp.status_code == 200


def get_public_key(owner: str, repo: str, token: str) -> tuple[str, str]:
    resp = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["key"], data["key_id"]


def encrypt_for_github(public_key_b64: str, secret_value: str) -> str:
    public_key = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def update_github_secret(owner: str, repo: str, secret_name: str, secret_value: str, token: str) -> None:
    key, key_id = get_public_key(owner, repo, token)
    encrypted_value = encrypt_for_github(key, secret_value)
    resp = requests.put(
        f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"encrypted_value": encrypted_value, "key_id": key_id},
        timeout=20,
    )
    resp.raise_for_status()


def main() -> None:
    username = _env("KIDSNOTE_USERNAME")
    password = _env("KIDSNOTE_PASSWORD")
    gh_pat = _env("GH_PAT")
    repo_full = _env("GITHUB_REPOSITORY")  # GitHub Actions가 자동으로 채워줌: "owner/repo"
    owner, repo = repo_full.split("/", 1)

    print("[1/3] 키즈노트 로그인 시도 중...")
    session_id = login_and_get_session_id(username, password)
    print(f"[1/3] 로그인 성공, 새 session_id 획득 (길이={len(session_id)})")

    print("[2/3] 새 세션 유효성 검증 중 (/api/v1/me/children/)...")
    if not verify_session(session_id):
        raise SystemExit(
            "새로 받은 session_id 로 API 호출이 실패했습니다. "
            "기존 KIDSNOTE_SESSION_COOKIE secret 은 건드리지 않고 종료합니다."
        )
    print("[2/3] 검증 성공 — 새 세션이 실제로 동작함을 확인")

    print("[3/3] GitHub repo secret KIDSNOTE_SESSION_COOKIE 갱신 중...")
    update_github_secret(owner, repo, "KIDSNOTE_SESSION_COOKIE", session_id, gh_pat)
    print("[3/3] 완료! KIDSNOTE_SESSION_COOKIE 가 자동으로 갱신되었습니다.")


if __name__ == "__main__":
    main()

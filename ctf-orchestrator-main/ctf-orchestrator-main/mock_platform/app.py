"""mock 平台 Web 服务（HTML 页面 + JSON API）。

启动：
    python -m mock_platform.app --port 8898 --debug-captcha
或由 ``python run.py --mock`` 自动拉起。
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from mock_platform.settings import MockSettings
from mock_platform.state import MockState, SubmitOutcome

SESSION_COOKIE = "mock_session"
TEMPLATE_DIR = Path(__file__).parent / "templates"


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_id: str
    captcha: str


class SubmitRequest(BaseModel):
    flag: str


def create_mock_app(settings: MockSettings | None = None) -> FastAPI:
    settings = settings or MockSettings.from_env()
    app = FastAPI(title="2026 羊城杯 mock 平台", docs_url="/api/docs", openapi_url="/api/openapi.json")
    state = MockState(settings)
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    app.state.mock_settings = settings
    app.state.mock_state = state
    app.state.templates = templates

    # -------------------------------------------------------------- helpers
    def get_state(request: Request) -> MockState:
        return request.app.state.mock_state

    def current_user(request: Request) -> str | None:
        st: MockState = request.app.state.mock_state
        return st.get_session(request.cookies.get(SESSION_COOKIE))

    def require_api_user(request: Request) -> str:
        user = current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="未登录或会话过期")
        return user

    def page_context(request: Request, user: str, **extra):
        st: MockState = request.app.state.mock_state
        context = {
            "request": request,
            "user": user,
            "competition_id": "1749",
            "competition_title": "2026 年“羊城杯”网络安全大赛初赛【相关企业组】",
            "submit_attempts": st.submit_attempts,
            "submit_limit": st.settings.submit_limit,
        }
        context.update(extra)
        return context

    def redirect_to_detail(challenge_id: str, message: str, ok: bool) -> RedirectResponse:
        target = (
            f"/compete/1749/challenges/{quote(challenge_id)}"
            f"?msg={quote(message)}&ok={int(ok)}"
        )
        return RedirectResponse(target, status_code=303)

    # -------------------------------------------------------------- health / root
    @app.get("/")
    async def root() -> RedirectResponse:
        return RedirectResponse("/compete/1749", status_code=303)

    @app.get("/api/health")
    async def health() -> dict:
        st: MockState = state
        return {
            "ok": True,
            "platform": "mock",
            "challenges": len(st.challenges),
            "submit_attempts": st.submit_attempts,
            "submit_limit": st.settings.submit_limit,
            "debug_captcha": st.settings.debug_captcha,
        }

    # -------------------------------------------------------------- auth (HTML)
    @app.get("/1749/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str | None = None) -> HTMLResponse:
        st: MockState = request.app.state.mock_state
        captcha_id, _, _ = st.new_captcha()
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "competition_title": "2026 年“羊城杯”网络安全大赛初赛【相关企业组】",
                "captcha_id": captcha_id,
                "error": "账号、密码或验证码错误，请重试" if error else None,
            },
        )

    @app.post("/1749/login")
    async def login_submit(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        captcha: Annotated[str, Form()],
        captcha_id: Annotated[str, Form()],
    ) -> Response:
        st: MockState = request.app.state.mock_state
        if not (st.verify_captcha(captcha_id, captcha) and st.login(username, password)):
            return RedirectResponse("/1749/login?error=1", status_code=303)
        token = st.create_session(username)
        response = RedirectResponse("/compete/1749", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=st.settings.session_ttl_seconds,
        )
        return response

    @app.get("/1749/logout")
    async def logout(request: Request) -> Response:
        st: MockState = request.app.state.mock_state
        st.delete_session(request.cookies.get(SESSION_COOKIE))
        response = RedirectResponse("/1749/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response

    # -------------------------------------------------------------- pages
    @app.get("/compete/1749", response_class=HTMLResponse)
    async def challenge_list_page(request: Request) -> Response:
        user = current_user(request)
        if user is None:
            return RedirectResponse("/1749/login", status_code=303)
        st: MockState = request.app.state.mock_state
        return templates.TemplateResponse(
            request=request,
            name="list.html",
            context=page_context(request, user, challenges=st.challenge_list()),
        )

    @app.get("/compete/1749/challenges/{challenge_id}", response_class=HTMLResponse)
    async def challenge_detail_page(
        request: Request, challenge_id: str, msg: str | None = None, ok: int = 0
    ) -> Response:
        user = current_user(request)
        if user is None:
            return RedirectResponse("/1749/login", status_code=303)
        st: MockState = request.app.state.mock_state
        challenge = st.challenge_json(challenge_id)
        if challenge is None:
            raise HTTPException(status_code=404, detail="题目不存在")
        return templates.TemplateResponse(
            request=request,
            name="detail.html",
            context=page_context(
                request,
                user,
                challenge=challenge,
                message=msg,
                ok=bool(ok),
            ),
        )

    @app.post("/compete/1749/challenges/{challenge_id}/container")
    async def start_container_page(request: Request, challenge_id: str) -> Response:
        user = current_user(request)
        if user is None:
            return RedirectResponse("/1749/login", status_code=303)
        st: MockState = request.app.state.mock_state
        result = await st.ensure_container(challenge_id)
        if isinstance(result, SubmitOutcome):
            return redirect_to_detail(challenge_id, result.message, False)
        return redirect_to_detail(
            challenge_id, f"容器已启动：{result['host']}:{result['port']}", True
        )

    @app.post("/compete/1749/challenges/{challenge_id}/submit")
    async def submit_page(
        request: Request, challenge_id: str, flag: Annotated[str, Form()]
    ) -> Response:
        user = current_user(request)
        if user is None:
            return RedirectResponse("/1749/login", status_code=303)
        st: MockState = request.app.state.mock_state
        outcome = await st.submit(challenge_id, flag, user)
        return redirect_to_detail(challenge_id, outcome.message, outcome.status == "accepted")

    # -------------------------------------------------------------- captcha
    @app.get("/captcha/{captcha_id}.png")
    async def captcha_image(request: Request, captcha_id: str) -> Response:
        st: MockState = request.app.state.mock_state
        image = st.captcha_image(captcha_id)
        if image is None:
            raise HTTPException(status_code=404, detail="验证码不存在或已过期")
        return Response(
            content=image,
            media_type="image/png",
            headers={"Cache-Control": "no-store"},
        )

    # -------------------------------------------------------------- auth (API)
    @app.get("/api/captcha")
    async def api_captcha(request: Request) -> dict:
        st: MockState = request.app.state.mock_state
        captcha_id, answer, image = st.new_captcha()
        payload = {
            "captcha_id": captcha_id,
            "image_data_url": "data:image/png;base64," + base64.b64encode(image).decode(),
            "expires_in": st.settings.captcha_ttl_seconds,
        }
        if st.settings.debug_captcha:
            payload["answer"] = answer
        return payload

    @app.get("/api/debug/captcha/{captcha_id}")
    async def api_debug_captcha(request: Request, captcha_id: str) -> dict:
        st: MockState = request.app.state.mock_state
        answer = st.debug_answer(captcha_id)
        if answer is None:
            raise HTTPException(status_code=404, detail="debug 未开启或验证码不存在")
        return {"captcha_id": captcha_id, "answer": answer}

    @app.post("/api/login")
    async def api_login(request: Request, payload: LoginRequest) -> Response:
        st: MockState = request.app.state.mock_state
        if not st.verify_captcha(payload.captcha_id, payload.captcha):
            return JSONResponse({"ok": False, "error": "验证码错误或已过期"}, status_code=400)
        if not st.login(payload.username, payload.password):
            return JSONResponse({"ok": False, "error": "账号或密码错误"}, status_code=401)
        token = st.create_session(payload.username)
        response = JSONResponse({"ok": True, "user": {"username": payload.username}})
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            samesite="lax",
            max_age=st.settings.session_ttl_seconds,
        )
        return response

    @app.get("/api/me")
    async def api_me(user: str = Depends(require_api_user)) -> dict:
        return {"username": user}

    # -------------------------------------------------------------- challenges (API)
    @app.get("/api/challenges")
    async def api_challenges(request: Request, user: str = Depends(require_api_user)) -> dict:
        st: MockState = request.app.state.mock_state
        return {"challenges": st.challenge_list()}

    @app.get("/api/challenges/{challenge_id}")
    async def api_challenge(
        request: Request, challenge_id: str, user: str = Depends(require_api_user)
    ) -> dict:
        st: MockState = request.app.state.mock_state
        challenge = st.challenge_json(challenge_id)
        if challenge is None:
            raise HTTPException(status_code=404, detail="题目不存在")
        return challenge

    @app.get("/api/challenges/{challenge_id}/attachments/{name}")
    async def api_attachment(
        request: Request,
        challenge_id: str,
        name: str,
        user: str = Depends(require_api_user),
    ) -> Response:
        st: MockState = request.app.state.mock_state
        challenge = st.challenge(challenge_id)
        if challenge is None:
            raise HTTPException(status_code=404, detail="题目不存在")
        for attachment in challenge.seed.attachments:
            if attachment.name == name:
                return Response(
                    content=attachment.content,
                    media_type="application/octet-stream",
                    headers={
                        "Content-Disposition": f'attachment; filename="{attachment.name}"',
                        "Cache-Control": "no-store",
                    },
                )
        raise HTTPException(status_code=404, detail="附件不存在")

    @app.post("/api/challenges/{challenge_id}/container")
    async def api_container(
        request: Request, challenge_id: str, user: str = Depends(require_api_user)
    ) -> Response:
        st: MockState = request.app.state.mock_state
        result = await st.ensure_container(challenge_id)
        if isinstance(result, SubmitOutcome):
            return JSONResponse(
                {"status": result.status, "message": result.message}, status_code=result.http_status
            )
        return JSONResponse({"target": result})

    @app.post("/api/challenges/{challenge_id}/submit")
    async def api_submit(
        request: Request,
        challenge_id: str,
        payload: SubmitRequest,
        user: str = Depends(require_api_user),
    ) -> Response:
        st: MockState = request.app.state.mock_state
        outcome = await st.submit(challenge_id, payload.flag, user)
        return JSONResponse(
            {"status": outcome.status, "message": outcome.message},
            status_code=outcome.http_status,
        )

    return app


def main(argv: list[str] | None = None) -> None:
    settings = MockSettings.from_env()
    parser = argparse.ArgumentParser(description="2026 羊城杯 mock 平台")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--username", default=settings.username)
    parser.add_argument("--password", default=settings.password)
    parser.add_argument("--submit-limit", type=int, default=settings.submit_limit)
    parser.add_argument("--submit-interval", type=float, default=settings.submit_interval_seconds)
    parser.add_argument("--debug-captcha", action="store_true", default=settings.debug_captcha)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    settings.host = args.host
    settings.port = args.port
    settings.username = args.username
    settings.password = args.password
    settings.submit_limit = args.submit_limit
    settings.submit_interval_seconds = args.submit_interval
    settings.debug_captcha = args.debug_captcha

    app = create_mock_app(settings)
    print(f"[mock] http://{args.host}:{args.port}/1749/login  (user={args.username})")
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level, access_log=False)


if __name__ == "__main__":
    main()

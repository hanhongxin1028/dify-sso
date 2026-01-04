import logging
import time
from urllib.parse import urlencode
from flask import request, redirect

from app.api.router import api
from app.configs import config
from app.extensions.ext_oidc import oidc_service
from app.libs.helper import extract_remote_ip, verify_sign
from app.services.account import AccountService
from app.services.token import TokenService
from app.services.custom_sso import CustomSSOService

logger = logging.getLogger(__name__)


@api.get("/console/api/enterprise/sso/oidc/login")
def oidc_login():
    is_login = request.args.get("is_login", False)
    login_url = oidc_service.get_login_url()
    if is_login:
        return redirect(login_url)
    else:
        return {"url": login_url}


@api.get("/console/api/enterprise/sso/oidc/callback")
def oidc_callback():
    code = request.args.get("code", "")
    redirect_url = request.args.get("redirect_url", "")
    app_code = request.args.get("app_code", "")

    remote_ip = extract_remote_ip(request)

    try:
        if app_code and redirect_url:
            tokens = oidc_service.handle_callback(code, remote_ip, f"app_code={app_code}&redirect_url={redirect_url}",
                                                  app_code)
            return redirect(
                f"{config.CONSOLE_WEB_URL}/webapp-signin?web_sso_token={tokens['access_token']}&redirect_url={redirect_url}")
        else:
            account = oidc_service.bind_account(code, remote_ip)
            token_pair = AccountService.login(account, remote_ip)

            response = redirect(f"{config.CONSOLE_WEB_URL}")

            TokenService.set_access_token_to_cookie(response, token_pair.access_token)
            TokenService.set_refresh_token_to_cookie(response, token_pair.refresh_token)
            TokenService.set_csrf_token_to_cookie(response, token_pair.csrf_token)

            return response

    except Exception as e:
        logger.exception("OIDC回调处理失败: %s", str(e))
        return {"error": str(e)}, 400


@api.get("/api/enterprise/sso/oidc/login")
@api.get("/api/enterprise/sso/members/oidc/login")
def oidc_login_callback():
    app_code = request.args.get("app_code", "")
    redirect_url = request.args.get("redirect_url", "")
    login_url = oidc_service.get_login_url(f"app_code={app_code}&redirect_url={redirect_url}")
    return {"url": login_url}



@api.get("/console/api/enterprise/sso/custom/login")
def custom_sso_login():
    """
    接收前端参数 -> 验证签名 -> 自动注册/登录 -> 跳转控制台
    """
    try:
        # 1. 获取参数
        username = request.args.get("username") # 唯一标识/工号
        nickname = request.args.get("nickname", "User") # 中文名
        sign = request.args.get("sign")
        timestamp = request.args.get("timestamp")
        
        if not username or not sign:
            return {"error": "Missing required parameters"}, 400

        # 2. 验证时间戳 (防止重放攻击，例如有效期 5 分钟)
        if timestamp:
            try:
                if abs(time.time() * 1000 - int(timestamp)) > 5 * 60 * 1000:
                     return {"error": "Request expired"}, 403
            except ValueError:
                return {"error": "Invalid timestamp"}, 400

        # 3. 验证签名
        if not verify_sign(request.args, sign):
            return {"error": "Invalid sign"}, 403

        remote_ip = extract_remote_ip(request)

        # 4. 调用 Service 层获取或创建用户
        account = CustomSSOService.get_or_create_account(username, nickname, remote_ip)

        # 6. 执行登录逻辑
        token_pair = AccountService.login(account, remote_ip)

        # 7. 构造重定向响应
        response = redirect(f"{config.CONSOLE_WEB_URL}")

        # 8. 写入 Cookie
        TokenService.set_access_token_to_cookie(response, token_pair.access_token)
        TokenService.set_refresh_token_to_cookie(response, token_pair.refresh_token)
        TokenService.set_csrf_token_to_cookie(response, token_pair.csrf_token)

        return response

    except Exception as e:
        logger.exception("Custom SSO Login Failed: %s", str(e))
        return {"error": str(e)}, 500  
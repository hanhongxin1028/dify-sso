import secrets
import string
import hashlib
from datetime import UTC, datetime
from typing import cast


def generate_string(n):
    letters_digits = string.ascii_letters + string.digits
    result = ""
    for i in range(n):
        result += secrets.choice(letters_digits)

    return result


def naive_utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def extract_remote_ip(request) -> str:
    if request.headers.get("Remoteip"):
        return cast(str, request.headers.get("Remoteip"))
    elif request.headers.getlist("X-Forwarded-For"):
        return cast(str, request.headers.getlist("X-Forwarded-For")[0])
    else:
        return cast(str, request.remote_addr)
    

def verify_sign(request_args, client_sign):
    """
    验证签名函数
    :param request_args: Flask 的 request.args (ImmutableMultiDict)
    :param client_sign: 前端传来的签名字符串
    :return: Boolean
    """
    SSO_SECRET_KEY = 'jekdjuweqjk'
    try:
        # 1. 转为普通字典，方便操作
        params = request_args.to_dict()

        # 2. 剔除 sign 字段本身 (它不参与签名计算)
        if 'sign' in params:
            del params['sign']

        # 3. 按照 ASCII 码对 Key 进行排序 (对应 JS: Object.keys(params).sort())
        sorted_keys = sorted(params.keys())

        # 4. 拼接字符串 (对应 JS 的循环拼接逻辑)
        sign_str = ""
        for key in sorted_keys:
            val = params[key]
            
            # 逻辑对齐前端：前端过滤了 ''(空串), null, undefined
            # Python后端接收到的参数通常都是字符串，所以重点过滤空串和None
            if val is not None and str(val) != "":
                sign_str += f"{key}={val}&"
        
        # 5. 拼接密钥 (对应 JS: signStr += `key=${secret}`)
        sign_str += f"key={SSO_SECRET_KEY}"

        # 打印调试信息 (调试通了后可以删掉)
        print(f"Server Sign String: {sign_str}")

        # 6. MD5 加密并转大写 (对应 JS: CryptoJS.MD5(...).toString().toUpperCase())
        calculated_sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest().upper()

        print(f"Server Calculated: {calculated_sign}")
        print(f"Client Provided:   {client_sign}")

        # 7. 比对
        return calculated_sign == client_sign

    except Exception as e:
        print(f"Sign verification failed: {e}")
        return False

**English** · [简体中文](../../zh-cn/deployment/03-sso-llm-gateway.md)

# 与 llm-gateway-go 的单点登录

FreeLLMAPI 可以挂在 llm-gateway-go 后面，构成这条请求链路：

```
客户端智能体 → llm-gateway-go → FreeLLMAPI → 上游供应商
```

在这种形态下，用户身份由网关统一掌管：**登录过网关的人可以直接打开本应用，
不需要第二次登录，也不需要记第二个密码。**

## 工作机制

两侧共用 llm-gateway-go 已经在与 RedClaw、openpocket、memora、acc 之间使用的
**跨项目身份契约**（契约定义见 `llm-gateway-go/pkg/identity/README.md`）：

1. 浏览器打开仪表盘。它带着网关的会话 Cookie（网关把它设在
   `Domain=.itestu.cn`，因此能到达本机域名），但还没有本服务的仪表盘会话。
2. 本服务识别出这一状态，把这次**页面导航**重定向到 `GET /sso`
   （只对 HTML 导航生效 —— 拉 JSON 的 XHR 绝不会被重定向）。
3. `/sso` 向网关要一张票：调用网关的
   `GET /api/auth/app-token?app=freellmapi`，**只转发网关自己的 Cookie**，
   本服务的会话令牌不会外流。
4. 网关为已登录用户签发一枚**短时 JWT**：`iss=llm-gateway`、
   `aud=freellmapi-api`，用共享密钥（`IDENTITY_SHARED_SECRET`）签名，有效期
   5 分钟。
5. FreeLLMAPI 校验该票据（签名、签发方白名单、受众、有效期），把身份映射到
   本地账号，签发仪表盘会话，并下发 `flm_session` Cookie。
6. 仪表盘直接渲染。此后每次请求都带上该 Cookie，登录表单不会再出现。

票据也可以直接给出（`GET /sso?token=…`）—— 那是反向代理或手工链接使用的形态。

这张票据在三处做了限定，都是有意为之：

| 限定 | 为什么 |
| --- | --- |
| 受众（`aud=freellmapi-api`） | 为别的服务签发的令牌在这里会被拒绝，哪怕签名有效。 |
| 签发方白名单 | 只信任身份网内的签发方。 |
| 5 分钟有效期 | 即使 URL 泄漏到历史记录或代理日志里，也很快失去价值。

本服务**不会**拿到网关的会话签名密钥，只拿得到共享网密钥 —— 所以这里被攻破
也无法被回放成一次网关会话。

## 配置

```bash
# FreeLLMAPI 主机上的 .env
IDENTITY_SHARED_SECRET=<与网关完全相同的 32 字节以上值>
IDENTITY_ISSUER_ALLOWLIST=redclaw,memora,llm-gateway,pocket,acc   # 可选
FREELLMAPI_SSO_AUDIENCE=freellmapi-api                            # 可选
FREELLMAPI_GATEWAY_URL=https://llm.example.com                    # 可选
FREELLMAPI_GATEWAY_COOKIE=llmgw_session                           # 可选
FREELLMAPI_GATEWAY_APP=freellmapi                                 # 可选
```

`FREELLMAPI_GATEWAY_URL` 是**向谁要票** —— 填网关可达的基址（网状入口，或同一
Docker 网络内的容器地址）。不填它，落地页就拿不到票，只有显式 `?token=` 那条路
可用。

这些变量都是可选的。**若 `IDENTITY_SHARED_SECRET` 未设置（或短于 32 字节），
单点登录即为关闭状态，任何令牌都会被拒绝** —— 不存在兜底密钥。

网关侧：

```bash
IDENTITY_SHARED_SECRET=<同一个值>
FREELLMAPI_PUBLIC_URL=https://freellm.example.com   # 可选，用于直接给出可打开的链接
```

## 接口

| 接口 | 在哪 | 用途 |
| --- | --- | --- |
| `GET /sso` | 本服务 | 浏览器落地页：向网关要票（或直接收 `?token=…`），校验后下发 `flm_session` Cookie 并跳转到 `/`。 |
| `POST /api/auth/sso/exchange` | 本服务 | 程序化交换：请求体 `{"token":"…"}`，返回仪表盘会话令牌。 |
| `GET /api/auth/app-token?app=freellmapi` | **网关** | 为已登录用户签发票据。 |

网关接口同时把票据放进 `X-LLMGW-App-Token` 响应头，反向代理便可在
`auth_request` 中直接取用，无需解析 JSON 正文。这让「打开应用即落在应用内」
的全自动链路不必依赖前端再发一次请求。

## 反向代理

仪表盘由边缘代理提供服务：代理用网关自身的会话做门闸，并放行落地跳转：

```nginx
location = /sso {
    proxy_pass http://freellmapi_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
}

location / {
    auth_request /_llmgw_auth;      # → 网关的 /api/auth/me
    proxy_pass http://freellmapi_upstream;
    proxy_set_header Cookie $http_cookie;
}
```

`/api/ping`、`/v1/*`、`/v1beta/*` 不在会话门闸内：推理面用统一 API Key 鉴权，
而健康探针不该依赖浏览器会话。

## 单点登录**没有**改变什么

- **本地密码登录照常可用**：它是应用独立运行时的兜底，也是首个账号的认领方式。
- **凡是被网关认证通过的用户，在这里都是仪表盘操作员。** 本应用是单操作员
  模型（没有按用户区分的角色），所以网关决定的是**谁能进来**，而不是**进来能
  做什么**。要按角色收敛，需要仪表盘自己再长一套授权模型。
- **统一 API Key** 仍然鉴权 `/v1` 推理面，与单点登录互不影响。

## 排查

| 现象 | 原因 |
| --- | --- |
| `503 single sign-on is not configured` | 本服务的 `IDENTITY_SHARED_SECRET` 未设置或短于 32 字节。 |
| `401 audience mismatch` | 网关签发的受众不对，或两侧 `FREELLMAPI_SSO_AUDIENCE` 不一致。 |
| `401 issuer … not in the allowlist` | 签发方不在 `IDENTITY_ISSUER_ALLOWLIST` 里。 |
| `401 token expired` | 票据超过 5 分钟，重新取一枚。 |
| 落地后仍是登录表单 | `flm_session` Cookie 没被浏览器接受，或跳转落到了绕开 Cookie 的路径上。检查代理是否原样透传 `Set-Cookie`。 |

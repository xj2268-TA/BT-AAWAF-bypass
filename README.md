# 宝塔云WAF 全模式绕过
最大的问题bt_key和bt_value没有加密，插件版本直接就是整个文件不加密
## 支持模式
| 模式 | 页面特征 | 绕过方式 |
|------|---------|---------|
| 5s盾 | `btwaf=` 参数 | 带cookie重试 |
| 无感验证 | `renji_` + `bt-info` | 提取key/value → 计算 → 验证接口 |
| 滑动验证 | `huadong_` / `滑动验证` | 提取key/value → 计算 → 验证接口 |

## 原理

### 5s盾
服务端返回 403 + `Set-Cookie` → 页面 JS 自动 `location.href` 重定向 → 浏览器带 cookie 重试 → 放行。无需计算。

### 无感验证 / 人机验证
服务端返回页面，引用 `renji_*.js`，JS 内硬编码：
- `key` = md5(客户端IP)
- `value` = md5(客户端UA)

3秒倒计时后自动计算 `md5(toASCII(md5(ua), 0))` 提交验证接口 `yanzheng_ip.php`。

绕过：直接提取 JS 中 key/value → 计算 → 调验证接口。

### 滑动验证
同无感验证，但算法偏移为 `offset=1`（每个字节+1后拼接），提交 `yanzheng_huadong.php`。
# har2list - HAR 转 Quantumult X 分流规则集

将浏览器导出的 HAR 文件转换为 Quantumult X 可用的 `.list` 分流规则。

## 环境

```bash
conda activate yellow
pip install tldextract
```

## 使用流程

### 1. 录制 HAR

1. 打开浏览器（Chrome / Safari / Firefox），按 `F12` 或 `Cmd+Opt+I` 打开 DevTools
2. 切到 **Network** 面板
3. 访问目标网站，正常浏览一段时间（多点几个页面，覆盖更多子域名）
4. 导出 HAR：
   - **Chrome**: Network 面板空白处右键 → `Save all as HAR with content`
   - **Safari**: `导出` 按钮（右上角）
   - **Firefox**: 齿轮图标 → `Save All As HAR`

### 2. 组织文件

将同一个网站的 HAR 文件放到 `har/<网站名>/` 文件夹下：

```
har/
├── doubao/
│   ├── www.doubao.com.har
│   └── mcs.doubao.com.har
├── twitter/
│   └── x.com.har
```

> 可以录制多次、多个页面，放在同一个文件夹里，脚本会自动合并去重。

### 3. 生成规则集

```bash
python har2list.py har/doubao --name Doubao --policy Proxy
```

输出 `list/Doubao.list`：

```
# NAME: Doubao
# AUTHOR: Gwen
# UPDATED: 2026-03-24 05:43:39
# HOST: 2
# HOST-SUFFIX: 1
# IP-CIDR: 4
# TOTAL: 7
HOST,lf3-short.ibytedapm.com,Proxy
HOST,p6-flow-imagex-sign.byteimg.com,Proxy
HOST-SUFFIX,doubao.com,Proxy
IP-CIDR,198.18.20.31/32,Proxy
...
```

## 补充模式（基于现有 .list 扩充）

如果已有别人的规则集但觉得不够全，可以录制 HAR 后用 `--base` 补充：

```bash
python har2list.py har/bilibili --base BiliBili.list --policy BiliBili
```

脚本会：
1. 解析 `BiliBili.list` 中已有的所有规则
2. 从 HAR 中提取域名/IP
3. 自动跳过已被覆盖的（`HOST-SUFFIX,bilibili.com` 会覆盖所有 `*.bilibili.com`）
4. 只把新发现的规则追加到文件末尾

输出 `BiliBili_supplemented.list`，可以用 `--output` 指定路径。

## 参数说明

| 参数 | 说明 | 默认值 |
|---|---|---|
| `folder` | HAR 文件夹路径（必填） | - |
| `--name` | 规则集名称 | 文件夹名 |
| `--policy` | QX 策略名（Proxy / Direct / Reject 等） | 同 name |
| `--output` | 输出文件路径 | `list/<name>.list` |
| `--author` | 作者 | Gwen |
| `--threshold` | 同根域名下 >= N 个子域名时合并为 HOST-SUFFIX | 2 |
| `--exclude` | 排除匹配的域名（正则） | 无 |
| `--no-ip` | 不生成 IP-CIDR 规则 | 默认生成 |
| `--base` | 基于现有 .list 文件补充（补充模式） | 无 |

## 用法示例

```bash
# 从零生成
python har2list.py har/doubao --name Doubao --policy Proxy

# 指定作者和输出路径
python har2list.py har/doubao --name Doubao --policy Proxy --author dum --output Doubao.list

# 排除 Google 和 CDN 公共域名
python har2list.py har/twitter --name Twitter --policy Proxy \
    --exclude 'google' 'googleapis' 'gstatic' 'cdn\.jsdelivr'

# 不要 IP-CIDR 规则
python har2list.py har/doubao --name Doubao --policy Proxy --no-ip

# 要求 >= 3 个子域名才合并为 HOST-SUFFIX
python har2list.py har/doubao --name Doubao --policy Proxy --threshold 3

# 补充现有规则集
python har2list.py har/bilibili --base BiliBili.list --policy BiliBili

# 补充并指定输出路径
python har2list.py har/bilibili --base BiliBili.list --policy BiliBili --output BiliBili_full.list
```

## 规则合并逻辑

| 场景 | 规则类型 | 示例 |
|---|---|---|
| 某根域名下出现 >= threshold 个子域名 | `HOST-SUFFIX` | `HOST-SUFFIX,doubao.com` |
| 某根域名下只有 1 个子域名 | `HOST` | `HOST,lf3-short.ibytedapm.com` |
| HAR 中记录的服务器 IP | `IP-CIDR` | `IP-CIDR,198.18.20.31/32` |

## 提高覆盖率的建议

- **多录几次**：登录前后各录一次，会触发不同的 API 域名
- **多点页面**：首页、设置页、内容详情页，各自可能加载不同的 CDN 和 API
- **多个 HAR 放同一文件夹**：脚本会自动合并去重
- **检查 `--threshold`**：如果某些子域名被漏掉，降低到 `--threshold 1` 让所有域名都用 HOST-SUFFIX 覆盖

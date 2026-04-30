# 🚀 KUI Serverless Cluster Gateway

<div align="center">

![Cloudflare Pages](https://img.shields.io/badge/Deployed_on-Cloudflare_Pages-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Vue.js](https://img.shields.io/badge/Frontend-Vue3-4FC08D?style=for-the-badge&logo=vue.js&logoColor=white)
![Python](https://img.shields.io/badge/Agent-Python3-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**下一代轻量级、全协议、零运维的 Serverless VPS 聚合管理与节点下发网关。**

[部署指南](#-闪电部署) • [核心特性](#-核心黑科技) • [探针架构](#-硬核原生探针) • [UI 预览](#-果味高颜面板)

</div>

---

## 💡 项目初衷

天下苦传统面板久矣！复杂的 Docker 部署、沉重的 MySQL 数据库、繁琐的节点协议配置……
**KUI** 诞生于极致的 Serverless 理念：**将主控端完全托管于 Cloudflare 边缘网络，VPS 仅需运行极致轻量的纯 Python 探针。** 

这不仅意味着**主控端永远免费、永不宕机、且极度隐蔽**，更意味着你可以通过一个绝美的可视化面板，轻松驾驭多台机器上的 7 大前沿代理协议。

## ✨ 核心黑科技

- ☁️ **100% Serverless 主控**：基于 Cloudflare Pages/Workers + D1 数据库。**绝对零配置部署**，无需手动执行 SQL 建表，首次登录面板全自动完成数据库初始化与热升级。
- 🔮 **全协议制霸 (7-in-1)**：完美支持 `VLESS`、`Reality`、`Hysteria 2`、`TUIC v5`、`Socks5` 以及 `Dokodemo-door (内部链式/公网转发)`。面板一键下发，VPS 探针自动拉取并无损重载 Sing-box。
- ⚡️ **VLESS-Argo 全自动穿透救砖**：遇到纯 IPV6 或被墙机器？下发 Argo 协议后，探针将在后台静默下载 `cloudflared`，自动建立内网穿透隧道，并在 15 秒内疯狂抓取 `.trycloudflare.com` 临时域名回传至面板！
- 🛡️ **双轨制与多租户隔离**：
  - **军工级鉴权**：动态 HMAC-SHA256 签名，5 分钟时间戳防重放攻击。
  - **多租户管理**：支持给不同用户分配专属节点、流量配额 (GB) 及到期时间限制。
- 🤖 **Telegram 全自动巡检**：利用 CF 定时触发器 (Cron)，节点掉线超过 3 分钟自动推送 TG 告警。

## 📊 硬核原生探针 (Agent)

KUI 的 VPS 探针彻底抛弃了依赖繁杂的 Bash 命令，采用**纯 Python 读取 Linux 内核文件**的极致方案，并搭配智能跨系统一键部署脚本：

- **绝对兼容与自动换源**：完美适配 **Ubuntu 18-24 / Debian 10-13 / Alpine Linux**，智能识别 `systemd` 与 `OpenRC`。脚本部署时强制全自动替换为**阿里云极速镜像源**，杜绝卡进度。
- **高阶内核级监控**：不仅监控 CPU 和内存，还能精准抓取**磁盘使用率 (Disk)、系统负载 (Load)、精准运行时长 (Uptime) 以及毫秒级双向网络速率 (Up/Down Speed)**。
- **全自动自签证书**：下发 Hysteria2 或 TUIC 时，探针全自动调用 OpenSSL 签发域名证书，全程无感。

## 🎨 果味高颜面板 (Apple Glassmorphism)

告别土味后台，KUI 采用了基于 TailwindCSS 构建的极致拟物毛玻璃 UI：
- 仪表盘大厅实时展示全网机器在线状态与聚合大流量。
- 丝滑的动画过渡与 Echarts 7 天流量趋势可视化。
- 响应式动态外链导航栏，完美适配手机小屏幕操作。

---

## 🚀 闪电部署

### Step 1: 准备 Cloudflare D1 数据库
1. 登录 Cloudflare 控制台，进入 `Workers & Pages` -> `D1`。
2. 点击“创建数据库”，命名为 `kui-db`（创建后即可退出，**无需执行任何建表操作**）。

### Step 2: 部署主控端 (Cloudflare Pages)
1. Fork 本仓库到你的 Github。
2. 在 Cloudflare 控制台左侧进入 `Workers & Pages`，点击 `创建` -> `Pages` -> `连接到 Git`。
3. 选择你 Fork 的仓库进行部署，框架预设选择 `None`。
4. **绑定数据库与变量** (进入已部署的 Pages 项目 `设置`)：
   - **函数 -> D1 数据库绑定**：将变量名设为 `DB`，并选择刚才创建的 `kui-db`。
   - **环境变量**：添加以下变量：
     - `ADMIN_USERNAME`: 你的管理员账号（默认填写 `admin` 即可）
     - `ADMIN_PASSWORD`: 你的管理员密码（**必填**，否则无法登录）
     - *(可选)* `TG_BOT_TOKEN`: 你的 Telegram Bot Token（用于掉线告警）
     - *(可选)* `TG_CHAT_ID`: 接收告警的 TG 频道或用户 ID

### Step 3: 零配置初始化
浏览器访问你的 Pages 域名，输入设置的账号密码登入。
**系统将瞬间在后台为你全自动建表并完成所有初始化配置！**

---

## 💻 探针接入指南

在 KUI 面板进入“服务器与节点”板块：
1. 输入你的 VPS **名称**和**公网 IP**。
2. 在下拉框中选择你的系统架构（`Ubuntu/Debian` 或 `Alpine Linux`）。
3. 点击“接入机器”后，复制生成的单行一键安装指令。
4. 登录到你的 VPS 终端，粘贴并执行该指令。

部署完毕后，面板上的该机器指示灯将在 1 分钟内转为绿色 🟢，四宫格实时监控数据瞬间点亮！

## ⚠️ 免责声明

本项目仅供编程学习与网络架构研究使用。请严格遵守您所在国家或地区的法律法规，请勿用于任何非法用途。开发者不对使用本项目造成的任何后果负责。

## 📄 License
[MIT](LICENSE) © KUI Contributors

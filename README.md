# 凿凿 ZaoZao — 基于大语言模型的代码安全分析系统

> 本地部署的开源大语言模型驱动的代码漏洞检测系统：传统工具是"模式匹配"，凿凿是"语义理解"——每个漏洞结论都附带完整证据链。
>
> 产品名**「凿凿」**（英文名 **ZaoZao**），取自「言之凿凿」。底层模型系列名为 **Nivis**，发布于 Ollama Registry 的模型为 `garrywhite109909/graduation-vuln-scanner:v9max`。

[![发布模型](https://img.shields.io/badge/发布模型-v9max-blue)](https://ollama.com/garrywhite109909/graduation-vuln-scanner)
[![平台](https://img.shields.io/badge/平台-Windows_/_Linux_/_macOS-green)](#后端平台支持矩阵)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

> 📖 **本页只讲怎么用。** 想了解这个项目是怎么一步步做出来的（选题、实验、模型训练的完整历程），看[《项目历程》](docs/项目历程.md)；按任务组织的详细手册见[《用户手册》](docs/用户手册.md)。

## 目录

- [它能做什么](#它能做什么)
- [快速开始](#快速开始)
  - [前置条件](#前置条件)
  - [一键启动（推荐）](#一键启动推荐)
  - [手动启动](#手动启动)
  - [切换推理后端](#切换推理后端)
  - [环境变量配置](#环境变量配置)
- [使用指南](#使用指南)
  - [Web 界面](#web-界面)
  - [命令行工具 CLI](#命令行工具-cli)
  - [VS Code 插件](#vs-code-插件)
  - [IntelliJ 插件](#intellij-插件)
- [卸载](#卸载)
- [故障排查](#故障排查)
- [目录结构](#目录结构)

***

## 它能做什么

对源代码进行安全审计，输出**漏洞判定 + CWE 类型 + 风险等级 + 污点来源/触发点 + 自然语言解释 + 修复建议**，与传统规则工具（Bandit / Semgrep）互补：

| 维度 | 传统工具（Bandit/Semgrep） | 凿凿（LLM 驱动） |
| ---- | -------------------------- | ---------------- |
| 检测方式 | 固定规则模式匹配 | 代码语义理解、上下文感知 |
| 漏洞覆盖 | 已知漏洞模式 | 可发现变体/非典型漏洞 |
| 输出形式 | 漏洞类型 + 规则编号 | 自然语言解释 + 修复建议 |
| 多语言 | 工具专属规则集 | 跨语言统一理解 |
| 误报控制 | 规则泛化能力差 | 上下文判断过滤/净化逻辑 |

扫描采用**两阶段架构**：Stage 1 由传统安全工具（Bandit / Semgrep / Gitleaks / Trivy）召回候选并直接报告密钥与依赖类发现，Stage 2 由本地大模型对 SAST 类候选做语义裁决——所有结论经一致性采样、共形预测、反事实验证与证据门分级，低置信候选进入人工复核清单，而不是假装确定。

***

## 快速开始

### 前置条件

| 条件 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Windows 10+ / Linux / macOS | 三平台均支持 |
| Python | 3.10+ | 启动脚本会检测并自动安装依赖 |
| pip | 任意可用版本 | 首次运行自动 `pip install -r requirements.txt && pip install -e .` |
| 磁盘空间 | ≥ 8 GB | 模型权重约 5 GB + 依赖包约 2 GB + 向量库缓存 |
| 内存 | ≥ 8 GB | 模型推理需要占用内存；8 GB 为最低线，16 GB 以上更流畅 |
| GPU（可选） | NVIDIA / AMD(ROCm) / Apple Silicon ≥ 4 GB | 无 GPU 时自动回退 CPU 推理（速度约为 GPU 的 1/10~1/20） |
| Ollama | 首次运行自动安装 | 若自动安装失败，请手动从 [ollama.com/download](https://ollama.com/download) 安装 |
| git（可选） | 任意版本 | 仅 GitHub 仓库扫描功能需要 |
| 网络 | 首次需要联网 | 下载依赖包 + Ollama 模型；后续可离线运行 |

> ⚠️ **Windows 下 LlamaCPP 后端暂不支持 RTX 50 系列与 AMD 显卡**
>
> 受 Windows 上 `llama-cpp-python` 预编译二进制与编译工具链限制，**LlamaCPP 后端在 Windows 端暂不支持 RTX 50 系列（Blackwell）与 AMD 显卡**（易报 DLL / 编译类错误）。若你使用这两类显卡：
>
> - **推荐改走默认 Ollama 后端**（兼容性最好，通常无需额外配置）；
> - 或使用 **Linux** 系统运行 LlamaCPP / Transformers 后端（Linux 端支持性较好）。
>
> 完整平台支持见下方「[后端平台支持矩阵](#后端平台支持矩阵)」。

### 一键启动（推荐）

一条命令搞定，启动脚本会自动完成其余所有事情：

```bash
git clone https://github.com/GarryWhite109909/ZaoZao.git && cd ZaoZao

# Windows
app\launcher\start_windows.bat

# Linux / macOS
bash app/launcher/start_linux_macos.sh
```

启动脚本会自动完成以下全部步骤：

1. **检测并安装 Python 核心依赖**——首次运行自动执行 `pip install -r requirements.txt && pip install -e .`
2. **选择推理后端**——启动器会提示选择 Ollama / Transformers / LlamaCPP；默认根据环境变量自动解析
3. **自动安装后端专属依赖**——若选择 Transformers / LlamaCPP，启动器会按当前 OS 与 GPU 自动下载正确的 `torch` / `transformers` / `peft` / `bitsandbytes` / `llama-cpp-python`（支持 Windows/Linux/macOS × NVIDIA/AMD/Apple/CPU）
4. **检测并安装 Ollama**——使用 Ollama 后端时自动安装/启动（其他后端跳过）
5. **硬件检测与自适应配置**——自动检测 GPU/CPU/RAM，按显存分档选择推理参数（`num_ctx` / `num_gpu` / 量化等级）
6. **拉取模型 / 定位 adapter**——Ollama 后端自动下载发布模型 `garrywhite109909/graduation-vuln-scanner:v9max`（约 5 GB，Q4 量化），拉取失败则回退官方 `qwen3:8b`；若项目 `models/` 下存在自研 LoRA adapter（α0.5 stage2），且运行时兼容，则自动切换 **Transformers 进程内后端**（保 LoRA FP16 精度）
7. **召回传统安全工具**——自动安装 Bandit / Semgrep / Gitleaks / Trivy / pip-audit / detect-secrets（两阶段 Stage 1 工具召回依赖；缺哪个静默跳过哪个）
8. **启动后端**——FastAPI 服务监听 `http://127.0.0.1:8765`
9. **打开浏览器**——自动跳转到 `http://localhost:8765`

> 首次启动因需下载模型（约 5 GB）或后端依赖（torch 等约 2-4 GB），耗时取决于网速，请耐心等待。后续启动通常 10 秒内完成。

> ⚠️ **Linux 用户：Ollama 模型存储统一到项目目录（只需一次）**
>
> 本项目把 Ollama 模型统一放在项目内 `models/ollama/`（后端调用路径，避免模型落系统目录）。但 Linux 上用官方脚本自动安装的 Ollama 会被注册成 **systemd 服务**（`ollama.service`），它开机自启、始终用系统默认存储（`~/.ollama/models`）占用 `11434` 端口，与项目存储冲突。首次使用前请执行一次：
>
> ```bash
> sudo systemctl disable --now ollama
> ```
>
> 之后启动器会自己用 `OLLAMA_MODELS=models/ollama` 启动 Ollama，模型全部落在项目目录，前端状态一致。
> **Windows / macOS 无需此步骤**（winget/brew 安装不注册系统服务，启动器直接接管）。

### 手动启动

如果不想用启动脚本（例如已在 IDE 中配置好环境），可以手动分步启动：

```bash
# 1. 确保 Ollama 运行
ollama serve &

# 2. 确保模型已拉取
ollama pull garrywhite109909/graduation-vuln-scanner:v9max

# 3. 启动后端
uvicorn app.backend.main:app --host 127.0.0.1 --port 8765

# 4. 浏览器访问
open http://localhost:8765        # macOS
xdg-open http://localhost:8765    # Linux
start http://localhost:8765       # Windows
```

### 切换推理后端

后端按以下优先级**自动解析**：

1. `VULN_SCANNER_BACKEND` 显式设置时优先（`ollama` / `transformers` / `llamacpp`）；
2. 配置了 `VULN_SCANNER_ADAPTER`，或 `models/` 下探测到合法 LoRA adapter（优先 α0.5 stage2）**且运行时兼容**时，自动选 **Transformers**——Q4 基座（NF4）+ FP16 LoRA 进程内推理，精度最高；
3. 否则回退 **Ollama**（GGUF Q4_K_M 合并量化的发布模型 v9max）——兼容性最好、依赖最少的一键启动形态；探测到 adapter 但本机跑不动 transformers 时也会自动回退并打印告警。

```bash
# Transformers 后端（NF4 基座 + FP16 LoRA，需 6GB+ 显存或足够内存）
export VULN_SCANNER_BACKEND=transformers
export VULN_SCANNER_ADAPTER=/path/to/alpha05_stage2_lora
bash app/launcher/start_linux_macos.sh

# LlamaCPP 后端（Q4 GGUF + 运行时 FP16 LoRA，实验性）
export VULN_SCANNER_BACKEND=llamacpp
export VULN_SCANNER_GGUF=/path/to/qwen3-8b-q4_k_m.gguf
export VULN_SCANNER_ADAPTER=/path/to/alpha05_stage2_lora
bash app/launcher/start_linux_macos.sh
```

Windows 使用 `set` 代替 `export`。选择进程内后端后，启动器会自动按你的 OS/GPU 下载对应版本的 `torch`、`transformers`、`llama-cpp-python` 等依赖。

> ⚠️ **显存与平台说明**
> - Transformers 后端推荐 NVIDIA/AMD 显存 ≥ 6GB；4GB 显存会被强制走 CPU，速度显著下降。
> - `bitsandbytes` 已支持 NVIDIA CUDA、AMD ROCm（Linux 预览，部分 Windows 预览）、CPU-only（Windows/Linux/macOS）以及 Apple Silicon（慢速 CPU 路径）。启动器会自动安装，但 ROCm/Apple/CPU 上 4bit 速度远慢于 NVIDIA CUDA，追求速度请改用 Ollama 后端。
> - LlamaCPP 后端可纯 CPU 运行（`n_gpu_layers=0`），也可按编译选项启用 CUDA/ROCm/Metal。**Windows 端暂不支持 RTX 50 系列与 AMD 显卡**（见上方提示）。

#### 后端平台支持矩阵

各推理后端在不同平台 / 显卡上的支持情况总结如下（**Windows 端限制较多，Linux 端支持性普遍较好**）：

| 后端 | 平台 | NVIDIA CUDA | RTX 50 系（Blackwell） | AMD(ROCm) | Apple Silicon | 纯 CPU |
|------|------|------------|----------------------|-----------|---------------|--------|
| **Ollama**（默认） | Windows / Linux / macOS | ✅ | ✅（内置运行时自带 CUDA） | ✅ | ✅ | ✅ |
| **Transformers** | Linux | ✅ | ✅ | ✅（ROCm 预览） | N/A* | ✅ |
| | Windows | ✅ | ⚠️ 需额外 CUDA Toolkit | ❌（不支持 AMD） | N/A* | ✅ |
| **LlamaCPP** | Linux | ✅ | ✅ | ✅ | N/A* | ✅ |
| | Windows | ✅ | ❌（暂不支持） | ❌（暂不支持） | N/A* | ✅ |

> \* **N/A** = 该组合不存在：Apple Silicon 是 macOS 专属硬件，Linux / Windows 下没有这一列的概念。Apple Silicon 设备请安装 macOS 后运行——Ollama 后端原生支持；Transformers / LlamaCPP 在 macOS 上可使用 `start_linux_macos.sh`（Metal/CPU 路径）。

> **结论**：追求设备兼容性优先选 **Ollama** 后端；确认要在 Windows 上使用进程内后端（Transformers / LlamaCPP）时，请先核对上表——**Transformers 的 Windows 端不支持 AMD，LlamaCPP 的 Windows 端暂不支持 RTX 50 系与 AMD**。若你使用上述受限组合，建议改用 Linux 或回退 Ollama。
>
> 💡 现有 RTX 5050 显卡在 Windows 上源码编译 LlamaCPP 均未成功。若你有编译成功经验（例如改用 **Ninja 生成器** 等方案），欢迎分享至 <3284263390@qq.com>。

### 环境变量配置

启动器和后端通过以下环境变量控制行为，按需设置：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `VULN_SCANNER_BACKEND` | 自动解析 | 推理后端：`ollama` / `transformers` / `llamacpp`；未设置但配了 `VULN_SCANNER_ADAPTER` 或在 `models/` 下探测到 adapter 时自动选 `transformers` |
| `VULN_SCANNER_ADAPTER` | 自动探测 `models/` | Transformers/LlamaCPP 后端：LoRA adapter 目录（含 `adapter_model.safetensors`）。未设置时自动查找项目根目录 `models/` 下的合法 adapter 目录 |
| `VULN_SCANNER_GGUF` | 无 | LlamaCPP 后端必填：Q4 GGUF 基座文件路径 |
| `VULN_SCANNER_MODEL` | `garrywhite109909/graduation-vuln-scanner:v9max` | Ollama 后端使用的发布模型名 |
| `VULN_SCANNER_FALLBACK_MODEL` | `qwen3:8b` | 主模型拉取失败时的回退模型 |
| `VULN_SCANNER_RECHECK_RATE` | `0.1` | 两阶段扫描 `sampled` 组态下无候选文件的抽样复核比例（生产默认 `full_recheck` 全量复核，此变量仅 sampled 组态生效） |
| `VULN_SCANNER_AUTO_INSTALL_DEPS` | 未设置 | `1` 强制重新检查/升级依赖；`0` 禁用自动安装（只打印手动命令） |
| `VULN_SCANNER_PIP_INDEX` | 无 | 覆盖 pip 镜像源，例如 `https://pypi.tuna.tsinghua.edu.cn/simple` |
| `VULN_SCANNER_RAG` | `0` | 设为 `1` 启用 RAG 知识库增强 |
| `VULN_SCANNER_PREFILTER` | `1` | 设为 `0` 关闭传统工具预筛 |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama 服务地址 |
| `VULN_SCANNER_NUM_CTX` | 自动检测 | 模型上下文窗口大小 |
| `VULN_SCANNER_NUM_GPU` | 自动检测 | GPU 层数（0 = 纯 CPU） |
| `VULN_SCANNER_NUM_THREAD` | 自动检测 | CPU 推理线程数 |

***

## 使用指南

系统提供**四种**使用方式：**Web 界面**、**命令行工具**、**VS Code 插件**、**IntelliJ 插件**。四种方式共享同一个后端服务，功能对等。

### Web 界面

启动后端后浏览器访问 `http://localhost:8765`，包含五个页面：

| 页面 | 路径 | 功能 |
|------|------|------|
| 欢迎页 | `/welcome.html` | 首次访问的引导页（系统定位与入口导航） |
| 仪表盘 | `/index.html` | 扫描历史统计、引擎健康状态、最近发现漏洞一览 |
| 扫描工作台 | `/scan.html` | 核心扫描入口，支持四种输入方式 |
| CWE 样本库 | `/cwe.html` | 16 类常见 CWE 漏洞的代码示例与修复方案（可搜索） |
| 安全态势 | `/posture.html` | 安全态势总览 |

#### 扫描工作台使用

扫描工作台是核心功能页，提供四种扫描输入方式（Tab 切换）：

**1. 粘贴代码**

1. 选择「粘贴代码」Tab
2. 在语言下拉框中选择代码语言（Python / JavaScript / TypeScript / Java / PHP / Go / HTML）
3. 在文本框中粘贴源代码
4. 点击「开始分析」按钮
5. 等待 LLM 推理完成（单文件约 5-15 秒），结果区显示漏洞判定、CWE 类型、风险等级、漏洞说明与修复建议

**2. 上传文件**

1. 选择「上传文件」Tab
2. 将文件拖拽到上传区域，或点击区域选择文件（支持多文件）
3. 点击「开始分析」按钮
4. 批量扫描时显示实时进度条（已扫描 / 总数），逐个文件返回结果
5. 扫描完成后可点击「下载报告」按钮导出 Markdown 格式报告

**3. URL 扫描**

1. 选择「URL」Tab
2. 输入目标站点 URL（如 `https://example.com`）
3. 点击「开始分析」按钮
4. 系统自动抓取页面中的 `<script>` 标签内容，逐个扫描
5. 结果显示页面标题、发现脚本数、各脚本的漏洞分析

**4. GitHub 仓库扫描**

1. 选择「GitHub」Tab
2. 输入仓库地址（如 `https://github.com/user/repo`）
3. 设置最大扫描文件数（默认 20，大仓库建议限制）
4. 点击「开始分析」按钮
5. 系统浅克隆仓库 → 遍历代码文件 → 批量扫描，完成后显示汇总

#### 高级选项

在扫描工作台点击「高级选项」可展开：

| 选项 | 说明 |
|------|------|
| 多模型投票 | 勾选后选择 ≥ 2 个模型，系统顺序加载各模型并投票聚合结果（更准但更慢） |
| 两阶段扫描 | 系统**唯一**扫描路径（工具召回 + LLM 自一致率裁决），无需勾选即生效；本开关仅控制下方采样数设置是否可调 |
| 自一致率采样数 | 两阶段 LLM 裁决的采样次数（1~10，默认 3）。采样越多越准、越慢 |

> 外部工具（Bandit / Semgrep / Gitleaks / Trivy）已内置于两阶段 Stage 1 工具召回，
> 无需单独勾选：密钥（secret）与依赖漏洞（SCA）类发现由确定性工具直接报告，
> SAST / IaC 类发现进入 LLM 裁决层判定真伪。

#### 结果展示

每个文件的扫描结果包含：

- **漏洞判定**：发现漏洞 / 安全 / 无法判定
- **CWE 类型**：如 CWE-89 SQL 注入
- **风险等级**：Critical / High / Medium / Low
- **Source & Sink**：污点来源与触发点（如适用）
- **漏洞说明**：自然语言解释漏洞原理
- **修复建议**：可执行的修复代码或方案
- **信任层明细**：裁决档位、一致性置信度、共形预测、反事实验证与证据门；低置信候选列入人工复核清单
- **模型原始输出**：LLM 的完整 JSON 输出

#### API 文档

后端提供完整的 REST API，访问 `http://localhost:8765/docs` 查看 Swagger 交互文档。主要端点：

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/health` | 健康检查（Ollama + vLLM + 外部工具状态） |
| GET | `/api/stats` | 仪表盘统计数据 |
| POST | `/api/analyze` | 单文件分析（两阶段：工具召回 + LLM 裁决，JSON body） |
| POST | `/api/analyze/two-stage` | 两阶段扫描（同 `/api/analyze`，保留 n_samples 与 SARIF 导出） |
| POST | `/api/batch` | 批量扫描（文件上传，NDJSON 流式进度） |
| POST | `/api/url-scan` | URL 抓取扫描（无候选文件全量复核） |
| POST | `/api/github-scan` | GitHub 仓库扫描（无候选文件全量复核） |
| POST | `/api/external-scan` | 外部工具直出扫描（不经 LLM；主扫描已内置同款工具召回，仅需原始结果时用） |
| POST | `/api/verify-fix` | 修复建议验证（语法校验 + 危险模式检查） |
| POST | `/api/multi-model-scan` | 多模型投票扫描 |
| POST | `/api/vllm-analyze` | vLLM 推理后端单文件分析 |
| GET | `/api/report` | 下载最近批量扫描的 Markdown 报告 |
| POST | `/api/report/single` | 分析并下载单文件 Markdown 报告 |

API 调用示例（以单文件分析为例）：

```bash
curl -X POST http://localhost:8765/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import sqlite3\ndef get_user(name):\n    c = sqlite3.connect(\"db\").cursor()\n    c.execute(\"SELECT * FROM users WHERE name='\''\" + name + \"'\''\")",
    "language": "python",
    "filename": "vuln.py"
  }'
```

### 命令行工具 CLI

CLI 工具直接复用 `Scanner` 引擎，**无需启动 FastAPI 后端**即可使用。适合脚本化批量扫描或 CI/CD 集成。

```bash
python -m app.launcher.vuln_scanner_cli <command> [options]
```

#### 命令一览

| 命令 | 功能 | 示例 |
|------|------|------|
| `health` | 健康检查（Ollama 连接 + 模型可用性） | `python -m app.launcher.vuln_scanner_cli health` |
| `scan <file>` | 扫描单个文件 | `python -m app.launcher.vuln_scanner_cli scan app/main.py` |
| `batch <dir>` | 批量扫描目录下所有代码文件 | `python -m app.launcher.vuln_scanner_cli batch ./src --output report.md` |
| `url <url>` | 扫描 URL 抓取的脚本 | `python -m app.launcher.vuln_scanner_cli url https://example.com` |
| `github <repo>` | 扫描 GitHub 仓库（浅克隆） | `python -m app.launcher.vuln_scanner_cli github https://github.com/user/repo` |

#### 全局参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--model` | `garrywhite109909/graduation-vuln-scanner:v9max` | Ollama 模型名 |
| `--ollama-url` | `http://localhost:11434` | Ollama 服务地址 |
| `--rag` | 关闭 | 启用 RAG 知识库增强（较慢但更准） |
| `--format` | `text` | 输出格式：`text`（终端着色）或 `json`（结构化） |

#### 常用示例

```bash
# 健康检查
python -m app.launcher.vuln_scanner_cli health

# 扫描单个文件，显示详细分析（含说明与修复建议）
python -m app.launcher.vuln_scanner_cli scan app/main.py --verbose

# 扫描单个文件，启用 RAG，输出 JSON 并保存
python -m app.launcher.vuln_scanner_cli scan app/main.py --rag --format json --output result.json

# 批量扫描目录，导出 Markdown 报告
python -m app.launcher.vuln_scanner_cli batch ./src --output report.md

# 批量扫描，限制最多 20 个文件，不递归子目录
python -m app.launcher.vuln_scanner_cli batch ./src --limit 20 --no-recursive

# 扫描 GitHub 仓库，最多 50 个文件
python -m app.launcher.vuln_scanner_cli github https://github.com/user/repo --max-files 50 --output repo_report.md

# 切换模型
python -m app.launcher.vuln_scanner_cli --model qwen2.5-coder:7b scan app/main.py
```

#### 支持的文件类型

`.py` `.js` `.ts` `.jsx` `.tsx` `.java` `.php` `.go` `.html` `.htm` `.vue` `.svelte`

### VS Code 插件

VS Code 插件提供编辑器内直接扫描、诊断标记、工作区批量扫描功能。扫描走后端统一的两阶段架构（Stage 1 工具召回 + Stage 2 LLM 裁决），结果面板展示**信任层明细**：每条候选的裁决档位、一致性置信度、共形预测、反事实验证与证据门，低置信候选列入人工复核清单。

#### 安装

**方式 A：从 VSIX 安装（推荐，普通用户）**

1. 下载插件包 [`releases/vuln-scanner-1.3.0.vsix`](releases/vuln-scanner-1.3.0.vsix)（仓库已附带，clone 后可直接使用，含信任层明细、多漏洞诊断等最新功能）
2. 打开 VS Code → 左侧扩展面板 → 右上角 `⋯` → **从 VSIX 安装**
3. 选择 `.vsix` 文件 → 安装完成 → 重载窗口

**方式 B：从源码打包（开发者）**

```bash
cd app/vscode-extension
npm install -g @vscode/vsce
vsce package   # 生成 vuln-scanner-1.3.0.vsix（含信任层明细、多漏洞诊断）
```

再按方式 A 安装生成的 `.vsix`。

#### 前置条件

1. VS Code ≥ 1.80
2. **后端服务已启动并保持运行**：通过 `start_windows.bat` 启动后端（详见「快速开始」），插件所有扫描都依赖该后端，后端关闭则插件无法工作

#### 命令

| 命令 | 触发方式 | 功能 |
|------|----------|------|
| 凿凿: 分析当前文件 | 右键编辑器 / 命令面板 / 编辑器标题栏盾牌图标 | 扫描当前打开的文件 |
| 凿凿: 批量扫描工作区 | 命令面板 | 扫描工作区所有代码文件 |
| 凿凿: 扫描指定文件夹 | 命令面板 | 弹窗选择文件夹后扫描 |
| 凿凿: 清除诊断标记 | 命令面板 | 清除编辑器中的波浪线标记 |

> 打开命令面板：`Ctrl+Shift+P`（Windows/Linux）或 `Cmd+Shift+P`（macOS），搜索"漏洞扫描"即可看到全部命令。

#### 配置项

在 VS Code 设置中搜索 `vulnScanner` 配置：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `vulnScanner.backendUrl` | `http://localhost:8765` | 后端服务地址 |
| `vulnScanner.useRag` | `false` | 是否启用 RAG 知识库增强 |
| `vulnScanner.markDiagnostics` | `true` | 发现漏洞时在编辑器中标记波浪线 |
| `vulnScanner.autoScanOnSave` | `false` | 保存文件时自动扫描（实验性） |
| `vulnScanner.workspaceExclude` | `["**/node_modules/**", ...]` | 批量扫描时排除的 glob 模式 |
| `vulnScanner.workspaceMaxFiles` | `50` | 批量扫描最多扫描文件数 |
| `vulnScanner.requestTimeout` | `300000` | 单次请求超时时间（毫秒） |

#### 使用流程

1. 启动后端服务（双击 `start_windows.bat` 或运行 `start_linux_macos.sh`，后端常驻后台）
2. 在 VS Code 中打开任意项目或单个代码文件
3. 打开代码文件 → 右键 → 「凿凿: 分析当前文件」
4. 扫描结果以 Webview 面板展示：漏洞判定、CWE 类型、风险等级、修复建议，以及信任层明细（置信度 / 裁决档位 / 共形预测 / 反事实 / 证据门）与需人工复核清单
5. 若启用诊断标记，每个确认的漏洞按其 sink 行号标红色波浪线（同一文件支持多处标记）
6. 如需批量扫描：命令面板 → 「凿凿: 批量扫描工作区」

### IntelliJ 插件

IntelliJ 插件提供编辑器内选中代码的扫描功能，结果以气球通知展示结论与信任层摘要（置信度 · 裁决档位 · 共形预测 · 反事实 · 证据门）。

#### 安装

**从磁盘安装（唯一方式）**

1. 下载插件包 [`releases/vuln-scanner-0.1.0.zip`](releases/vuln-scanner-0.1.0.zip)（仓库已附带，clone 后可直接使用）
2. 打开 IntelliJ IDEA → `File` → `Settings` → `Plugins`
3. 点击右上角齿轮图标 ⚙️ → **Install Plugin from Disk...**
4. 选择 `vuln-scanner-0.1.0.zip` → 安装 → 重启 IDEA

#### 前置条件

1. **IntelliJ IDEA**（Community 或 Ultimate 均可）
2. **后端服务已启动并保持运行**：通过 `start_windows.bat` 启动后端（详见「快速开始」），插件所有扫描都依赖该后端，后端关闭则插件无法工作

#### 使用方式

1. 启动后端服务（双击 `start_windows.bat` 或运行 `start_linux_macos.sh`，后端常驻后台）
2. 在 IntelliJ IDEA 中打开任意项目或代码文件
3. 在编辑器中**选中要扫描的代码**（未选中时扫描整个文件）
4. 右键 → **凿凿 漏洞扫描**（或快捷键 `Ctrl+Alt+Shift+V`）
5. 等待扫描完成，结果以气球通知形式弹出：漏洞类型、风险等级、污染来源、触发点、修复建议，以及信任层摘要；后端地址支持在弹窗中改为基础地址（自动补全端点路径）

#### 与 VS Code 插件的差异

| 特性 | VS Code 插件 | IntelliJ 插件 |
|------|-------------|--------------|
| 结果展示 | Webview 面板（信任层明细表格） | 气球通知（信任层摘要） |
| 诊断标记 | 红色波浪线（按确认裁决逐处标记） | 暂未实现 |
| 批量扫描 | 支持 | 暂未实现 |
| 后端 API | `/api/analyze` | `/api/analyze` |

> 完整的 IntelliJ 插件文档见 [app/intellij-extension/README.md](app/intellij-extension/README.md)。

## 卸载

### 一键卸载

| 平台 | 入口 |
|---|---|
| Windows | 双击 `uninstall_windows.bat`，或运行 `python uninstall.py` |
| Linux / macOS | 运行 `bash uninstall.sh`，或运行 `python3 uninstall.py` |

常用参数（`python uninstall.py --help` 可查看全部）：

- `--yes`：全自动，跳过所有确认；
- `--dry-run`：模拟，只列出将要删除的内容，不实际删除；
- `--keep-project`：保留项目文件夹（只清依赖和数据）；
- `--keep-ollama`：保留 Ollama 本体与模型；
- `--keep-accel`：保留 CUDA/ROCm 系统组件。

### ⚠️ 必须用安装时的同一个 Python 环境卸载

依赖装进哪个 Python 环境，就必须用哪个环境卸载：

- **一键启动用户**：依赖是启动器用系统 Python 自动安装的，直接运行卸载脚本即可；
- **conda / venv 用户**：安装时先激活过环境，卸载前也必须先激活同一个环境再运行卸载脚本；
- 卸载脚本只清理"运行它的那个 Python 环境"，换环境运行会提示"未发现本项目相关包"并跳过，等于没有真正卸载。

### 卸载范围

脚本会按本机实际检测结果动态清理：

1. 后端进程（端口 8765）与 Ollama 服务进程；
2. 当前 Python 环境中的本项目相关包（torch、fastapi、chromadb、sentence-transformers、tree-sitter、vllm 等）与 pip 下载缓存；
3. Ollama 拉取的模型（`~/.ollama`，以及 `OLLAMA_MODELS` 指定的目录）；
4. Ollama 本体：Windows（winget/官方卸载器）、macOS（Homebrew/官方 App）、Linux（apt/dnf/pacman/zypper/apk/官方脚本）；
5. Linux 系统级 CUDA / ROCm 组件（需 sudo，仅 apt 系发行版）；
6. 本地运行数据：`data/chroma_db`、`outputs/`、`logs/`、`__pycache__`、`*.egg-info`、`.pytest_cache`、HuggingFace/torch/chroma 缓存等；
7. 已安装的 VS Code 扩展（`graduation-project.vuln-scanner`）与 IntelliJ 插件（尽力而为）；
8. 整个项目文件夹（Windows 下同样有效）。

### 不会自动删除的内容

- **外部扫描工具**（bandit / semgrep / gitleaks / trivy）：这些是共享系统工具，可能被其他项目使用，卸载脚本不会动它们；如需删除请按安装方式手动卸载（如 `pip uninstall bandit semgrep`、`choco uninstall gitleaks trivy`）；
- **conda 环境本身**：卸载脚本只清当前环境里的包，不会删除任何 conda 环境；
- **npm 全局包**（如 `@vscode/vsce`）：如需删除请手动 `npm uninstall -g @vscode/vsce`。
- **部分共享基础库**（urllib3、certifi、typing-extensions 等）：脚本保留这类通用网络/类型基础库，避免影响同一环境里的其他程序。但注意：**numpy / scipy / pandas / scikit-learn 等科学计算包也在清理列表里**（本项目按需安装的大体积依赖），若同一环境还有其他项目用到它们，请留意确认提示，必要时改用 `--dry-run` 先查看或将依赖装在独立虚拟环境。

### 注意事项

- `~/.ollama` 和 `~/.cache/huggingface` 是全局目录，卸载会删除里面**所有**模型/缓存（包括其他项目用到的），`--yes` 模式下不会再次确认，请提前确认；
- Windows 下直接运行 `python uninstall.py` 时脚本会自动切换 UTF-8 输出，双击 bat 也已设置 `chcp 65001`；
- 卸载脚本会逐项检查实际删除结果，失败项会明确报错，不会提示虚假成功；完成后请确认项目文件夹确实已删除。

***

## 故障排查

### Semgrep 规则本地化（离线可用，随仓库分发）

系统使用的 Semgrep registry 规则包（`p/security-audit`、`p/owasp-top-ten`）已本地化为 **`models/semgrep_rules/`** 并随仓库入库（纯文本，MIT 开源，版本固定）。扫描完全离线运行，克隆仓库即可用，无需联网拉取规则。

- **更新规则**（semgrep 社区更新时手动覆盖）：`python tools/fetch_semgrep_rules.py`（幂等，已存在则跳过；需联网）
- **校验状态**：`python tools/fetch_semgrep_rules.py --check`
- 规则文件缺失时（如手动删除），工具层自动降级为在线拉取（并提示）。

### 启动相关

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `ModuleNotFoundError: No module named 'app.launcher.bootstrap'` | 未在项目根目录下运行 | 确保 `cd` 到项目根目录后再执行启动脚本；`start_windows.bat` 已内置自动切到根目录 |
| `pip install` 找不到 `requirements.txt` 或 `pyproject.toml` | 当前目录不是项目根目录 | `cd` 到项目根目录后再 `pip install -r requirements.txt && pip install -e .` |
| `ModuleNotFoundError: No module named 'fastapi'`（或 `chromadb` / `tree_sitter` 等） | 依赖未安装 | 重新运行启动脚本（会自动安装），或手动 `pip install -r requirements.txt` |
| 启动器提示 `Ollama 自动安装失败` | winget/brew 不可用或网络问题 | 手动从 [ollama.com/download](https://ollama.com/download) 下载安装，安装后重启终端再运行启动脚本 |
| 启动器提示 `Ollama 已安装但不在 PATH 中` | 安装后 PATH 未刷新 | 重启终端；或手动将 Ollama 安装路径加入系统 PATH |
| 后端启动超时 | 端口 8765 被占用 | 检查端口：`netstat -ano \| findstr 8765`（Windows）/ `lsof -i :8765`（Linux/macOS），杀掉占用进程后重试 |
| Linux 上模型没统一到项目目录 / 前端状态不一致 | 系统级 `ollama.service`（systemd）仍用系统存储占用 11434 | 执行一次 `sudo systemctl disable --now ollama`，再由启动器用 `OLLAMA_MODELS=models/ollama` 启动（详见「一键启动」Linux 提示） |

### 模型相关

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| 模型下载超时或失败 | 网络不稳定或 Ollama Registry 不可达 | 手动重试：`ollama pull garrywhite109909/graduation-vuln-scanner:v9max`；若持续失败可改用回退模型：`set VULN_SCANNER_MODEL=qwen3:8b` |
| 扫描结果全为"无法判定" | 模型未正确加载或输出格式不匹配 | 运行 `python -m app.launcher.vuln_scanner_cli health` 检查模型可用性；确认模型名与 Ollama 中一致 |
| 推理速度极慢（> 60s/文件） | 无 GPU 回退到 CPU 推理 | 检查启动日志中 `[硬件检测]` 行；CPU 模式约为 GPU 的 1/10 速度，属正常现象 |
| OOM（显存溢出） | `num_ctx` 过大或显存不足 | 降低上下文窗口：设置环境变量 `VULN_SCANNER_NUM_CTX=4096` |
| Transformers/LlamaCPP 后端报 DLL / 编译类错误（RTX 50 系列） | Blackwell 架构缺少对应 CUDA Toolkit | 在 Linux 上运行（Linux 端支持性较好），或改用默认 Ollama 后端；Windows 下 LlamaCPP 暂不支持 RTX 50 系列与 AMD 显卡（见「后端平台支持矩阵」） |

### RAG / 向量库相关

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `ModuleNotFoundError: No module named 'chromadb'` | 未安装 RAG 依赖 | `pip install -r requirements.txt`（chromadb 在依赖列表中） |
| RAG 扫描报错 `embedding model not found` | embedding 模型未缓存到本地 | 在有网络的环境执行一次：`python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-m3')"`；国内可用 `HF_ENDPOINT=https://hf-mirror.com` 镜像 |
| RAG 检索结果明显不对 / 向量库为空 | `data/chroma_db/` 未构建或由旧 embedding 模型构建 | 删除 `data/chroma_db/` 后重建：`cd experiments/exp_03_rag_knowledge/knowledge_data && python3 build_knowledge.py` |
| 自定义 embedding 缓存路径 | 默认缓存路径 `~/.cache/huggingface/` 不可写 | `export CHROMA_EMBEDDING_MODEL_PATH=/path/to/local/model` |

### 插件相关

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| VS Code 插件扫描无响应 | 后端未启动或地址不匹配 | 确认 `http://localhost:8765/api/health` 可访问；检查 VS Code 设置中 `vulnScanner.backendUrl` 是否正确 |
| VS Code 插件请求超时 | 大文件推理耗时长 | 在设置中将 `vulnScanner.requestTimeout` 调大（默认 300000ms = 5 分钟） |
| IntelliJ 插件编译失败 | JDK 版本低于 17 或 Gradle 同步失败 | 确认 JDK 17+；在 IDEA 中重新同步 Gradle |
| IntelliJ 插件通知不弹出 | 后端地址不匹配 | 编辑 `VulnScannerAction.java` 中的 `BACKEND_URL` 常量后重新构建 |

### IDE 报红（不影响运行）

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| VS Code / PyCharm 中大量红色错误标记 | Python 解释器选错、依赖未安装、模块路径未配置 | 1. 选择正确的 Python 解释器；2. 在项目根目录执行 `pip install -e .`；3. 在 `.vscode/settings.json` 中配置 `python.analysis.extraPaths` 指向项目根目录 |
| 类型检查器报类型不匹配 | Pyright/mypy 严格模式误报 | 不影响运行，可在 `pyproject.toml` 中调整类型检查严格度 |

***

## 目录结构

用户常用到的目录与文件：

```
ZaoZao/
├── app/                        # 软件本体
│   ├── backend/                #   FastAPI 后端（REST API + 两阶段扫描引擎）
│   ├── frontend/               #   Web 界面（静态页面，由后端直接托管）
│   ├── launcher/               #   跨平台启动器（一键启动 + 依赖自动安装）
│   ├── vscode-extension/       #   VS Code 插件源码
│   └── intellij-extension/     #   IntelliJ 插件源码
├── releases/                   # 插件安装包（vsix / zip，clone 后可直接安装）
├── models/
│   └── semgrep_rules/          # 本地化 Semgrep 规则（离线可用）
├── graduation_project/         # 核心 Python 包（LLM 客户端 / schema / prompts / 两阶段扫描器）
├── data/                       # 本地运行数据（chroma 向量库等，不入库）
├── docs/
│   ├── 用户手册.md              # 按任务组织的详细使用手册
│   └── 项目历程.md              # 项目从选题到成品的完整历程（给老师/评委看）
├── requirements.txt
├── uninstall.py / uninstall_windows.bat / uninstall.sh
└── README.md
```

> `experiments/` 与 `graduation_project/` 中还包含完整的实验与训练代码，属于研究部分——它们的来龙去脉见[《项目历程》](docs/项目历程.md)。

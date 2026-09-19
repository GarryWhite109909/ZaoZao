# 凿凿 IntelliJ 插件

将编辑器中选中的代码发送到凿凿后端 `http://localhost:8765/api/analyze` 进行两阶段
漏洞扫描（Stage 1 工具召回 + Stage 2 LLM 裁决 + 信任层），结果以气球通知形式展示
结论与信任层摘要（置信度 / 共形预测 / 反事实 / 证据门）。

## 安装（使用已构建分发包）

1. 插件分发包位于仓库 `releases/vuln-scanner-0.1.0.zip`（随源码一并分发，clone 后可直接使用）。
2. 打开 IntelliJ IDEA / PyCharm / WebStorm 等 JetBrains IDE（2022.1 ~ 2026.x）。
3. `File` → `Settings` → `Plugins`。
4. 点击右上角齿轮图标 ⚙️ → **Install Plugin from Disk...**。
5. 选择 `vuln-scanner-0.1.0.zip` → 安装 → 重启 IDE。

> 若该分发包缺失，可按文末「从源码构建」自行打包。

## 前置条件

1. JetBrains IDE（Community / Ultimate 均可）。
2. **凿凿后端已启动并保持运行**：在项目根目录双击
   `app/launcher/start_windows.bat`（Windows）或执行
   `bash app/launcher/start_linux_macos.sh`（Linux / macOS）启动后端，
   确认 `http://localhost:8765/api/health/live` 可访问。
   **后端必须常驻后台，关闭后插件无法工作。**

## 使用方式

1. 启动后端服务（启动器选 Web 模式 / 插件模式 / 全部均可，后端会常驻后台）。
2. 在 IDE 中打开任意项目或代码文件。
3. 在编辑器中**选中要扫描的代码**（未选中时扫描整个文件）。
4. 右键 → **凿凿 漏洞扫描**（或快捷键 `Ctrl+Alt+Shift+V`）。
5. 等待扫描完成，结果以气球通知弹出，显示漏洞类型、风险等级与触发点。

## 目录结构

```
intellij-extension/
├── build.gradle.kts                              # Gradle 构建文件（IntelliJ Platform Gradle Plugin）
├── gradle.properties                             # 构建参数（含国内代理配置，可按网络调整）
├── gradlew / gradlew.bat                         # Gradle Wrapper
├── gradle/wrapper/                               # Wrapper 引导包
├── README.md                                     # 本文件
└── src/main/
    ├── java/com/graduation/vulnscanner/
    │   ├── VulnScannerAction.java                # AnAction 动作实现（右键菜单 / 快捷键 / 通知）
    │   └── BackendResponseParser.java            # 后端两阶段响应解析（使用平台捆绑 Gson）
    └── resources/
        ├── META-INF/plugin.xml                   # 插件描述符
        └── icons/                                # 插件图标
```

## 从源码构建

需要 JDK 17 ~ 21（Gradle 8.9 不支持更高版本的 JDK 运行构建）。首次构建会下载
IntelliJ Platform SDK（约 1 GB），请保持网络畅通；`gradle.properties` 中预置了
本地代理与阿里云镜像配置，可按实际网络环境修改或注释。

```bash
cd app/intellij-extension
# Windows
gradlew.bat buildPlugin
# Linux / macOS
./gradlew buildPlugin
```

构建产物为 `build/distributions/vuln-scanner-0.1.0.zip`，按上文「安装」步骤从磁盘安装即可。

## 与 VS Code 插件的差异

| 特性           | VS Code 插件          | IntelliJ 插件（本目录） |
|---------------|----------------------|------------------------|
| 结果展示       | Webview 面板（详细）  | 气球通知（摘要）        |
| 诊断标记       | 编辑器波浪线          | 暂未实现               |
| 批量扫描       | 支持                  | 暂未实现               |
| 后端 API       | `/api/analyze`        | `/api/analyze`         |

IntelliJ 插件功能较 VS Code 插件精简，聚焦选中代码的快速扫描流程；两个插件共享
同一个凿凿后端服务，可同时安装使用。

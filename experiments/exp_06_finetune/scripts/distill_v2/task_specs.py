"""
7 个蒸馏 pack 的任务规格 + 任务生成器。

方法论（docs/方法论_新蒸馏方法论.md 第 54-61 行）要求 7 类共 11500 条，本脚本覆盖
DeepSeek 5 类 + Kimi K3 2 类 = 9700 条（GLM 由另一台机器处理，不在此）。

每个 pack 生成 total 条 TaskSpec，其中 vuln_count 条漏洞 + safe_count 条安全（1:3 配比）。
各维度（CWE/语言/难度/场景）用轮询确保均匀覆盖，避免模型重复生成同质样本。

用法：
    from task_specs import PACKS, generate_tasks
    for spec_def in PACKS:
        tasks = generate_tasks(spec_def)
        # tasks: List[TaskSpec]
"""

from dataclasses import dataclass, field, asdict
from itertools import cycle
from typing import List


@dataclass
class TaskSpec:
    """单条蒸馏任务的规格。合并所有模板所需字段，未用到的留默认值。"""
    task_id: str            # pack_id-NNNN，如 deepseek_cc_memory-0001
    pack_id: str
    model: str              # deepseek | kimi
    template: str           # cc_memory | pentest | web | shell | fix | cross_file
    has_vuln: bool
    cwe: str = ""
    lang: str = ""
    difficulty: str = ""
    scene: str = ""
    # pentest 专用
    key_point: str = ""
    # web 专用
    framework: str = ""
    # shell 专用
    config_type: str = ""
    # cross_file 专用
    file_role: str = ""
    upstream_summary: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class PackDef:
    """一个 pack 的定义。"""
    pack_id: str
    model: str
    template: str
    output_file: str        # 相对 DATA_DIR 的文件名
    vuln_count: int
    safe_count: int
    # 各维度取值池
    cwes: tuple = ()
    langs: tuple = ()
    difficulties: tuple = ()
    scenes: tuple = ()
    key_points: tuple = ()          # pentest
    frameworks: tuple = ()          # web
    config_types: tuple = ()        # shell
    file_roles: tuple = ()          # cross_file
    upstream_summaries: tuple = ()  # cross_file


# ===========================================================================
# 7 个 pack 定义
#   条数核对（与方法论第 54-61 行一致）：
#     DeepSeek: 1000 + 1800 + 2500 + 1200 + 1200 = 7700
#     Kimi K3:  800 + 1200 = 2000
#     合计: 9700（GLM 1800 由另一台机器处理）
# ===========================================================================

PACKS = [
    # ----------------------------------------------------------------------
    # 1. DeepSeek C/C++ 内存漏洞（1000 条：250 漏洞 + 750 安全）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="deepseek_cc_memory",
        model="deepseek",
        template="cc_memory",
        output_file="deepseek_cc_memory.jsonl",
        vuln_count=250,
        safe_count=750,
        cwes=(
            "CWE-416", "CWE-415", "CWE-120", "CWE-122", "CWE-121",
            "CWE-476", "CWE-367", "CWE-190", "CWE-787", "CWE-125",
        ),
        langs=("C", "C++"),
        difficulties=("简单", "中等", "困难"),
        scenes=(
            "网络协议解析", "文件系统操作", "内存管理", "多线程同步",
            "设备驱动", "内核模块", "嵌入式固件", "图像/音视频解码",
        ),
    ),

    # ----------------------------------------------------------------------
    # 2. DeepSeek 渗透/命令注入/运维安全（1800 条：450 + 1350）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="deepseek_pentest",
        model="deepseek",
        template="pentest",
        output_file="deepseek_pentest.jsonl",
        vuln_count=450,
        safe_count=1350,
        cwes=(
            "CWE-78", "CWE-77", "CWE-88", "CWE-134", "CWE-918",
            "CWE-912", "CWE-749",
        ),
        langs=("Python", "Shell", "Go", "JavaScript"),
        scenes=(
            "运维脚本", "API 服务", "定时任务", "容器入口",
            "CI/CD 流水线", "日志处理", "API 网关", "自动化部署",
        ),
        key_points=(
            "用户输入到 os.system 的数据流",
            "subprocess 列表参数的有效防御",
            "shell=True + shlex.quote 组合",
            "shell=True + 字符串拼接",
            "白名单校验 + shell=False",
            "eval 用户输入拼接",
            "格式化字符串注入",
        ),
    ),

    # ----------------------------------------------------------------------
    # 3. DeepSeek Java/Python Web 漏洞（2500 条：625 + 1875）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="deepseek_web",
        model="deepseek",
        template="web",
        output_file="deepseek_web.jsonl",
        vuln_count=625,
        safe_count=1875,
        cwes=(
            "CWE-89", "CWE-79", "CWE-22", "CWE-502", "CWE-611",
            "CWE-352", "CWE-1336", "CWE-643", "CWE-943", "CWE-90",
            "CWE-441", "CWE-639", "CWE-862", "CWE-306", "CWE-601",
            "CWE-117", "CWE-798",
        ),
        langs=("Java", "Python", "JavaScript", "PHP"),
        frameworks=("Spring", "Django", "Flask", "Express", "FastAPI", "原生"),
        difficulties=("典型", "防御迷惑", "注意力分散", "框架代码"),
        scenes=(
            "用户认证", "订单查询", "文件上传", "模板渲染",
            "API 调用", "数据导出", "密码重置", "搜索功能",
        ),
    ),

    # ----------------------------------------------------------------------
    # 4. DeepSeek Shell/配置文件安全（1200 条：300 + 900）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="deepseek_shell",
        model="deepseek",
        template="shell",
        output_file="deepseek_shell.jsonl",
        vuln_count=300,
        safe_count=900,
        cwes=(
            "CWE-78", "CWE-798", "CWE-276", "CWE-326",
            "CWE-1188", "CWE-732",
        ),
        langs=("Shell", "Dockerfile", "nginx", "systemd", "yaml"),
        difficulties=(),  # shell 模板不用 difficulty
        scenes=(
            "部署脚本", "反向代理", "容器构建", "定时任务",
            "CI/CD 配置", "服务编排", "日志轮转", "初始化脚本",
        ),
        config_types=(
            "Shell 脚本", "Dockerfile", "docker-compose.yml",
            "nginx.conf", "systemd unit", "CI/CD yaml",
        ),
    ),

    # ----------------------------------------------------------------------
    # 5. DeepSeek 漏洞修复样例（1200 条：300 漏洞→修复 + 900 安全对照）
    #    注：fix 模板固定 has_vuln=true（给漏洞代码+修复）。
    #    为凑 1:3 配比，safe_count 部分用 web 模板的安全样本补，model 仍 deepseek。
    #    实际操作：vuln_count 条用 fix 模板，safe_count 条用 web 模板安全样本。
    #    为简化，这里 fix pack 的 safe 部分也走 fix 模板但 has_vuln=False
    #    （让模型生成"已修复的代码 + 说明已安全"），保持 pack 内模板统一。
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="deepseek_fix",
        model="deepseek",
        template="fix",
        output_file="deepseek_fix.jsonl",
        vuln_count=300,
        safe_count=900,
        cwes=(
            "CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-502",
            "CWE-416", "CWE-352", "CWE-611", "CWE-798", "CWE-918",
        ),
        langs=("Python", "Java", "JavaScript", "C", "Go"),
        difficulties=(),
        scenes=(
            "用户认证", "订单查询", "文件上传", "API 调用",
            "内存管理", "配置加载", "日志处理", "数据序列化",
        ),
    ),

    # ----------------------------------------------------------------------
    # 6. Kimi K3 C/C++ 内存漏洞重构（800 条：200 + 600）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="kimi_cc_memory",
        model="kimi",
        template="cc_memory",
        output_file="kimi_cc_memory.jsonl",
        vuln_count=200,
        safe_count=600,
        cwes=(
            "CWE-416", "CWE-415", "CWE-122", "CWE-367", "CWE-190", "CWE-787",
        ),
        langs=("C", "C++"),
        difficulties=("中等", "困难"),  # K3 重构要求跨函数/跨文件，不设"简单"
        scenes=(
            "协议解析", "内存池", "对象生命周期", "多线程同步",
            "设备驱动", "内核模块", "嵌入式固件", "文件系统操作",
        ),
    ),

    # ----------------------------------------------------------------------
    # 7. Kimi K3 跨文件分块审计（1200 条：300 + 900）
    # ----------------------------------------------------------------------
    PackDef(
        pack_id="kimi_cross_file",
        model="kimi",
        template="cross_file",
        output_file="kimi_cross_file.jsonl",
        vuln_count=300,
        safe_count=900,
        cwes=(
            "CWE-441", "CWE-639", "CWE-862", "CWE-918", "CWE-89",
        ),
        langs=("Python", "Java", "JavaScript", "Go"),
        difficulties=(),
        scenes=(
            "微服务 API", "模块化后端", "前后端分离", "插件架构",
            "网关聚合", "异步任务队列", "RPC 服务", "GraphQL 网关",
        ),
        file_roles=(
            "入口文件", "中间处理", "数据访问层",
        ),
        upstream_summaries=(
            "server.js 第 45 行调用此模块的 handleRequest(req)，req 来自 HTTP 请求，未做认证",
            "API 网关已校验 JWT，但未校验资源归属",
            "前端直连此服务，无网关认证层",
            "上游定时任务调用，携带系统权限 token",
            "上游调用方已做参数白名单，但未做权限校验",
            "上游为内部 RPC，信任所有内部请求",
        ),
    ),
]


# ===========================================================================
# 任务生成器
# ===========================================================================

def generate_tasks(pack: PackDef) -> List[TaskSpec]:
    """根据 PackDef 生成 total 条 TaskSpec。

    - vuln_count 条 has_vuln=True
    - safe_count 条 has_vuln=False
    - 各维度用 cycle 轮询，确保均匀覆盖
    """
    tasks = []
    total = pack.vuln_count + pack.safe_count

    # 各维度轮询器
    cwe_cycle = cycle(pack.cwes)
    lang_cycle = cycle(pack.langs)
    diff_cycle = cycle(pack.difficulties) if pack.difficulties else cycle(("",))
    scene_cycle = cycle(pack.scenes)
    key_cycle = cycle(pack.key_points) if pack.key_points else cycle(("",))
    fw_cycle = cycle(pack.frameworks) if pack.frameworks else cycle(("",))
    cfg_cycle = cycle(pack.config_types) if pack.config_types else cycle(("",))
    role_cycle = cycle(pack.file_roles) if pack.file_roles else cycle(("",))
    up_cycle = cycle(pack.upstream_summaries) if pack.upstream_summaries else cycle(("",))

    for i in range(total):
        has_vuln = i < pack.vuln_count
        idx = i + 1
        task_id = f"{pack.pack_id}-{idx:04d}"

        task = TaskSpec(
            task_id=task_id,
            pack_id=pack.pack_id,
            model=pack.model,
            template=pack.template,
            has_vuln=has_vuln,
            cwe=next(cwe_cycle),
            lang=next(lang_cycle),
            difficulty=next(diff_cycle),
            scene=next(scene_cycle),
            key_point=next(key_cycle),
            framework=next(fw_cycle),
            config_type=next(cfg_cycle),
            file_role=next(role_cycle),
            upstream_summary=next(up_cycle),
        )
        tasks.append(task)

    return tasks


# ===========================================================================
# 自检
# ===========================================================================

def _self_check():
    """打印各 pack 任务数，供 run_distill.py 启动时展示。"""
    print(f"{'pack_id':<24} {'model':<10} {'template':<12} {'vuln':>6} {'safe':>6} {'total':>6}")
    print("-" * 70)
    grand_total = 0
    for p in PACKS:
        total = p.vuln_count + p.safe_count
        grand_total += total
        print(f"{p.pack_id:<24} {p.model:<10} {p.template:<12} "
              f"{p.vuln_count:>6} {p.safe_count:>6} {total:>6}")
    print("-" * 70)
    print(f"{'合计':<24} {'':<10} {'':<12} {'':>6} {'':>6} {grand_total:>6}")
    return grand_total


if __name__ == "__main__":
    _self_check()

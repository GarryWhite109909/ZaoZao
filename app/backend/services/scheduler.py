"""
扫描请求调度器 —— 在 FastAPI 与 Ollama 之间引入优先级队列。

背景
----
Ollama 单模型推理本质串行（启动器设 OLLAMA_NUM_PARALLEL=1）。
若 FastAPI 层无限流，多个客户端（Web / VSCode 插件 / IntelliJ 插件）
同时发请求时，请求会在 Ollama 内部排队，导致：

1. 交互式单文件扫描可能被批量扫描饿死，响应时间不可预测；
2. 客户端无法获知排队位置，体验差；
3. 队列堆积无上限，可能 OOM 或被 Ollama 拒绝。

调度策略
--------
* **优先级队列**：交互式扫描（HIGH）优先于批量扫描（LOW），
  同优先级 FIFO（序号 seq 仲裁）。
* **单工作线程**：与 Ollama 串行推理对齐，任务在 Python 层显式排队，
  队列状态可控、可见。
* **队列上限**：超过 max_queue 拒绝入队（返回 503），防止无限堆积。
* **客户端配额**：每个 client_id 最多排 max_per_client 个任务，
  防止单一批量扫描霸占整个队列。
* **取消机制**：排队中的任务可取消（设 cancel_flag），工作线程取出后跳过；
  正在执行的任务不可取消（Ollama 不支持中断）。
* **asyncio 集成**：submit 返回 asyncio.Future，端点 await 即可；
  工作线程通过 loop.call_soon_threadsafe 回填结果，不阻塞事件循环。

端点接入
--------
* `/api/analyze`          → HIGH（交互式单文件）
* `/api/multi-model-scan` → HIGH（交互式多模型）
* `/api/batch`            → LOW（每个文件一个任务）
* `/api/url-scan`         → LOW（每个脚本一个任务）
* `/api/github-scan`      → LOW（每个文件一个任务）
* `/api/vllm-analyze`     → 不调度（vLLM 自身支持并发，不挤占 Ollama）
* `/api/external-scan`    → 不调度（走 Bandit/Semgrep，不走 Ollama）
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# 优先级常量（数值小 = 优先级高，与 heapq 最小堆一致）
PRIORITY_HIGH = 0      # 交互式单文件 / 多模型扫描
PRIORITY_NORMAL = 1    # 默认优先级（resolve_priority 的兜底值，队列状态统计也用到）
PRIORITY_LOW = 2       # 批量扫描（工作区 / URL / GitHub）

# 优先级标签（供 /api/queue/status 展示）
PRIORITY_LABELS = {
    PRIORITY_HIGH: "high",
    PRIORITY_NORMAL: "normal",
    PRIORITY_LOW: "low",
}


@dataclass(order=True)
class ScanTask:
    """调度队列中的单个任务。

    order=True 使 heapq 按 (priority, seq) 排序：
    优先级相同时 seq 小的先出队，保证 FIFO。
    """

    priority: int                                       # 优先级（小=高）
    seq: int                                            # 全局递增序号（FIFO 仲裁）
    # 非排序字段
    task_id: str = field(compare=False)                 # 任务唯一 ID
    client_id: str = field(compare=False)               # 客户端标识
    execute: Callable[[], Any] = field(compare=False)   # 实际执行函数（同步阻塞）
    cancel_flag: threading.Event = field(compare=False, default_factory=threading.Event)
    description: str = field(compare=False, default="")
    enqueued_at: float = field(compare=False, default_factory=time.time)
    future: Optional[asyncio.Future] = field(compare=False, default=None)


class ScanScheduler:
    """扫描调度器单例。

    生命周期：随 FastAPI app 启动而创建，工作线程为 daemon，随进程退出。
    线程安全：内部用 threading.Condition 保护堆与计数器；
    asyncio.Future 的回填通过 loop.call_soon_threadsafe 转交事件循环线程。
    """

    def __init__(
        self,
        max_queue: int = 50,
        max_per_client: int = 8,
        queue_timeout: float = 600.0,
        exec_timeout: float = 900.0,
    ):
        """
        Args:
            max_queue: 全局队列上限，超过则拒绝入队（防止无限堆积）。
            max_per_client: 单个 client_id 最多排队任务数（防批量扫描霸占）。
            queue_timeout: 任务在队列中等待的最长时间（秒），超时自动失败。
            exec_timeout: 执行超阈值（秒）。线程无法安全强杀，故不硬中断，
                仅在 status() 中标记 possibly_stuck 供监控告警。
        """
        self._heap: list[ScanTask] = []
        self._cv = threading.Condition(threading.Lock())
        self._counter = itertools.count()
        self._max_queue = max_queue
        self._max_per_client = max_per_client
        self._queue_timeout = queue_timeout
        self._exec_timeout = exec_timeout

        self._running = True
        self._current_task: Optional[ScanTask] = None
        self._current_started_at: Optional[float] = None
        self._client_counts: dict[str, int] = {}
        self._total_done = 0
        self._total_canceled = 0
        self._total_timeout = 0

        # 事件循环引用：startup 时由 bind_loop 注入
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # 工作线程：单线程串行执行，与 Ollama 串行推理对齐
        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name="scan-scheduler-worker",
        )
        self._worker.start()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """由 FastAPI startup 事件调用，注入事件循环引用。

        工作线程回填 Future 结果时需通过该 loop.call_soon_threadsafe，
        确保 set_result/set_exception 在事件循环线程执行。
        """
        self._loop = loop

    def shutdown(self) -> None:
        """停止工作线程（进程退出时调用）。

        停止前把仍在队列中的任务整体置为异常：工作线程退出后这些任务
        永远不会再被取走执行，若 Future 不回填，端点的 await 会永久挂起，
        拖住 uvicorn 优雅停机。
        """
        with self._cv:
            self._running = False
            leftover, self._heap = self._heap, []
            for task in leftover:
                self._reject(task.future, RuntimeError("调度器已关闭，任务未执行"))
                cnt = self._client_counts.get(task.client_id, 0)
                if cnt <= 1:
                    self._client_counts.pop(task.client_id, None)
                else:
                    self._client_counts[task.client_id] = cnt - 1
            self._cv.notify_all()
        # daemon 线程，无需 join

    # ------------------------------------------------------------------
    # 提交任务（须在事件循环线程调用，因为要创建 Future）
    # ------------------------------------------------------------------
    def submit(
        self,
        priority: int,
        client_id: str,
        execute: Callable[[], Any],
        description: str = "",
    ) -> tuple[str, asyncio.Future]:
        """提交一个扫描任务到优先级队列。

        Args:
            priority: PRIORITY_HIGH / NORMAL / LOW
            client_id: 客户端标识（web / vscode / intellij / <name>）
            execute: 实际执行函数，返回 SingleResult 或 BatchResult 等
            description: 任务描述（用于 /api/queue/status 展示）

        Returns:
            (task_id, future)：task_id 用于取消，future 用于 await 结果。
            若队列满或客户端超配额，future 立即置为异常。
        """
        if self._loop is None:
            # 极端情况：startup 未完成就收到请求
            fut = asyncio.get_event_loop().create_future()
            fut.set_exception(RuntimeError("调度器尚未绑定事件循环"))
            return uuid.uuid4().hex[:12], fut

        future: asyncio.Future = self._loop.create_future()
        task_id = uuid.uuid4().hex[:12]
        task = ScanTask(
            priority=priority,
            seq=next(self._counter),
            task_id=task_id,
            client_id=client_id,
            execute=execute,
            description=description,
            future=future,
        )

        with self._cv:
            # 0) 调度器已关闭（shutdown 后到达的请求）：立即置异常返回，
            #    否则工作线程已退出、Future 永不 resolve，请求永久挂起
            if not self._running:
                self._reject(future, RuntimeError("调度器已关闭，不再接受新任务"))
                return task_id, future
            # 1) 全局队列上限
            if len(self._heap) >= self._max_queue:
                self._reject(future, RuntimeError(
                    f"调度队列已满（{self._max_queue}），请稍后重试"
                ))
                return task_id, future
            # 2) 客户端配额
            pending = self._client_counts.get(client_id, 0)
            if pending >= self._max_per_client:
                self._reject(future, RuntimeError(
                    f"客户端 {client_id} 排队任务已达上限（{self._max_per_client}），"
                    f"请等待现有任务完成"
                ))
                return task_id, future
            # 3) 入队
            heapq.heappush(self._heap, task)
            self._client_counts[client_id] = pending + 1
            self._cv.notify()

        return task_id, future

    # ------------------------------------------------------------------
    # 工作线程主循环
    # ------------------------------------------------------------------
    def _worker_loop(self) -> None:
        """工作线程：循环取优先级最高的任务执行。"""
        while self._running:
            task: Optional[ScanTask] = None
            with self._cv:
                while self._running and not self._heap:
                    self._cv.wait(timeout=1.0)
                if not self._running:
                    break
                task = heapq.heappop(self._heap)
                self._current_task = task

            if task is None:
                continue

            # 1) 取消检查：取消标记已置位则跳过执行
            if task.cancel_flag.is_set():
                self._finish_task(task, error=RuntimeError("任务已取消"))
                with self._cv:
                    self._total_canceled += 1
                continue

            # 2) 排队超时检查：等待过久的任务直接失败，避免客户端长时间挂起
            waited = time.time() - task.enqueued_at
            if waited > self._queue_timeout:
                self._finish_task(task, error=TimeoutError(
                    f"任务排队超时（{self._queue_timeout}s）"
                ))
                with self._cv:
                    self._total_timeout += 1
                continue

            # 3) 执行（同步阻塞调用 Ollama，在当前工作线程）
            # 记录执行开始时间：线程无法安全强杀，执行超时无法硬中断，
            # 但通过 status() 暴露 running_seconds/possibly_stuck 供监控发现卡死
            with self._cv:
                self._current_started_at = time.time()
            try:
                result = task.execute()
                self._finish_task(task, result=result)
            except Exception as e:  # noqa: BLE001 — 调度层须兜住所有异常
                self._finish_task(task, error=e)
            finally:
                with self._cv:
                    self._total_done += 1
                    self._current_started_at = None

    def _finish_task(
        self,
        task: ScanTask,
        result: Any = None,
        error: Optional[BaseException] = None,
    ) -> None:
        """回填任务结果到 asyncio.Future，并清理客户端计数。"""
        # 回填 Future（必须经事件循环线程）
        if error is not None:
            self._loop.call_soon_threadsafe(self._safe_set_exception, task.future, error)
        else:
            self._loop.call_soon_threadsafe(self._safe_set_result, task.future, result)

        # 清理计数与当前任务指针（只清正在结束的这个任务，避免误清其他运行中任务）
        with self._cv:
            if self._current_task is task:
                self._current_task = None
            cnt = self._client_counts.get(task.client_id, 0)
            if cnt <= 1:
                self._client_counts.pop(task.client_id, None)
            else:
                self._client_counts[task.client_id] = cnt - 1

    # ------------------------------------------------------------------
    # 取消
    # ------------------------------------------------------------------
    def cancel(self, task_id: str) -> bool:
        """取消排队中的任务。正在执行的任务不可取消。

        与旧实现不同：取消时直接从堆中移除任务并回填 Future，
        不再让已取消任务继续占用队列名额与客户端配额。

        Returns:
            True = 成功取消（Future 立即以异常返回）；
            False = 任务不存在或正在执行。
        """
        task_to_cancel: Optional[ScanTask] = None
        with self._cv:
            # 正在执行的任务不可取消
            if self._current_task and self._current_task.task_id == task_id:
                return False
            remaining = []
            for t in self._heap:
                if t.task_id == task_id:
                    t.cancel_flag.set()
                    task_to_cancel = t
                else:
                    remaining.append(t)
            if task_to_cancel is None:
                return False
            self._heap = remaining
            heapq.heapify(self._heap)
        # 锁外回填 Future（_finish_task 内部需要再取锁，避免死锁）
        self._finish_task(task_to_cancel, error=RuntimeError("任务已取消"))
        with self._cv:
            self._total_canceled += 1
        return True

    # ------------------------------------------------------------------
    # 队列状态（供 /api/queue/status 展示）
    # ------------------------------------------------------------------
    def status(self) -> dict:
        """返回当前调度器状态快照。"""
        with self._cv:
            priority_counts = {PRIORITY_HIGH: 0, PRIORITY_NORMAL: 0, PRIORITY_LOW: 0}
            oldest_wait: Optional[float] = None
            for t in self._heap:
                priority_counts[t.priority] = priority_counts.get(t.priority, 0) + 1
                age = time.time() - t.enqueued_at
                if oldest_wait is None or age > oldest_wait:
                    oldest_wait = age

            current = self._current_task
            started_at = self._current_started_at
            running_seconds = (time.time() - started_at) if started_at else None
            return {
                "queue_size": len(self._heap),
                "max_queue": self._max_queue,
                "max_per_client": self._max_per_client,
                "queue_timeout": self._queue_timeout,
                "priority_counts": {
                    PRIORITY_LABELS[k]: priority_counts.get(k, 0)
                    for k in (PRIORITY_HIGH, PRIORITY_NORMAL, PRIORITY_LOW)
                },
                "client_pending": dict(self._client_counts),
                "current_task": {
                    "task_id": current.task_id,
                    "client_id": current.client_id,
                    "description": current.description,
                    "priority": PRIORITY_LABELS.get(current.priority, str(current.priority)),
                    "elapsed": round(time.time() - current.enqueued_at, 2),
                    "running_seconds": round(running_seconds, 2) if running_seconds else None,
                    # 执行超过 exec_timeout 视为疑似卡死（线程无法强杀，仅供监控告警）
                    "possibly_stuck": bool(running_seconds and running_seconds > self._exec_timeout),
                } if current else None,
                "oldest_wait_seconds": round(oldest_wait, 2) if oldest_wait else 0,
                "stats": {
                    "total_done": self._total_done,
                    "total_canceled": self._total_canceled,
                    "total_timeout": self._total_timeout,
                },
            }

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_set_result(future: asyncio.Future, result: Any) -> None:
        if not future.done():
            future.set_result(result)

    @staticmethod
    def _safe_set_exception(future: asyncio.Future, exc: BaseException) -> None:
        if not future.done():
            future.set_exception(exc)

    def _reject(self, future: asyncio.Future, exc: BaseException) -> None:
        """入队失败时立即把异常回填到 Future。"""
        self._loop.call_soon_threadsafe(self._safe_set_exception, future, exc)


def resolve_priority(scan_scope: Optional[str], default: int = PRIORITY_NORMAL) -> int:
    """根据请求头 X-Scan-Scope 解析优先级。

    Args:
        scan_scope: 请求头 X-Scan-Scope 的值（single / batch / auto）
        default: 无法识别时的回退优先级

    Returns:
        PRIORITY_HIGH / PRIORITY_LOW / default
    """
    if not scan_scope:
        return default
    s = scan_scope.strip().lower()
    if s in ("single", "interactive", "file"):
        return PRIORITY_HIGH
    if s in ("batch", "workspace", "folder", "url", "github", "repo"):
        return PRIORITY_LOW
    return default


def resolve_client_id(client_type: Optional[str], fallback: str = "web",
                      batch_id: Optional[str] = None) -> str:
    """根据请求头 X-Client-Type 解析客户端标识（A5/S8 修复，2026-09-21）。

    配额桶由**服务端事实**决定，客户端只能选择用途、不能选择身份：
      - batch_id（服务端生成的批次 id）优先：一次批量扫描 = 同一个桶，
        不可被请求头轮换拆分；
      - X-Client-Type 白名单收口：web / vscode / intellij 三值，未知值
        一律归 fallback——此前 `return c or fallback` 让任意字符串各占
        一个独立桶，轮换请求头即可绕过 max_per_client。

    Args:
        client_type: 请求头 X-Client-Type 的值（web / vscode / intellij）
        fallback: 缺失或非白名单时的回退标识
        batch_id: 服务端生成的批次 id（批量入口必传）

    Returns:
        归一化后的 client_id
    """
    if batch_id:
        return f"batch:{batch_id}"
    if not client_type:
        return fallback
    c = client_type.strip().lower()
    if c in ("web", "browser"):
        return "web"
    if c in ("vscode", "vs code", "code"):
        return "vscode"
    if c in ("intellij", "idea", "jetbrains"):
        return "intellij"
    return fallback  # 白名单收口：未知值不占独立桶

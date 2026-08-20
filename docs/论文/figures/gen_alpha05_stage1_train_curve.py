# -*- coding: utf-8 -*-
"""α0.5 stage1 训练收敛曲线图（2026-08-20 修正数据源）。

数据来源：D:\code\yunduan\train_log_cloud_r8_e2_lr0.0001_s42_rslora (1).json
  （cloud_train 输出，train 6777 / dev 1195，2 epoch ≈ 1696 步，LR=1e-4 warmup+cosine，
   bf16 LoRA r8/a16/rsLoRA，A800）。
  stage2（回收 dev 续训 1 epoch）为另一运行，不在本日志内。

重跑：AI 环境（含 matplotlib）python gen_alpha05_stage1_train_curve.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

LOG = Path(r"D:\code\yunduan\train_log_cloud_r8_e2_lr0.0001_s42_rslora (1).json")
OUT = Path(__file__).resolve().parent / "alpha05_stage1_train_curve.png"

d = json.loads(LOG.read_text(encoding="utf-8"))
hist = d["log_history"]
train = [h for h in hist if "loss" in h]
eval_ = [h for h in hist if "eval_loss" in h]

steps = [h["step"] for h in train]
loss = [h["loss"] for h in train]
grad = [h["grad_norm"] for h in train]
lr = [h["learning_rate"] for h in train]
acc = [h.get("mean_token_accuracy") for h in train]
ent = [h.get("entropy") for h in train]
e_steps = [h["step"] for h in eval_]
e_loss = [h["eval_loss"] for h in eval_]

fig, axes = plt.subplots(2, 2, figsize=(13, 8.5))
fig.suptitle("Nivis-α0.5 Stage1 训练收敛曲线（Qwen3-8B + LoRA r8/a16，A800 bf16，train 6777 / dev 1195）",
             fontsize=15, fontweight="bold")

# 1) Train / Eval Loss
ax = axes[0][0]
ax.plot(steps, loss, color="#1f77b4", lw=1.2, label="train loss", alpha=0.9)
ax.plot(e_steps, e_loss, color="#d62728", marker="o", ms=4, lw=1.8, label="eval loss（dev 最优选型）")
ax.set_xlabel("step"); ax.set_ylabel("loss")
ax.set_title("Loss 收敛：1.63 → ~0.58（train，末步 0.584）/ 0.742 → 0.574（eval）")
ax.legend(); ax.grid(alpha=0.3)
ax.annotate("stage1 best\n(eval 0.574)", xy=(e_steps[-1], e_loss[-1]),
            xytext=(e_steps[-1] - 350, e_loss[-1] + 0.06),
            arrowprops=dict(arrowstyle="->"), fontsize=9)

# 2) Grad Norm
ax = axes[0][1]
ax.plot(steps, grad, color="#2ca02c", lw=0.9, alpha=0.85)
ax.set_xlabel("step"); ax.set_ylabel("grad norm")
ax.set_title("梯度范数收敛：3.2 → ~1.0")
ax.grid(alpha=0.3)

# 3) Learning Rate（warmup + cosine）
ax = axes[1][0]
ax.plot(steps, lr, color="#ff7f0e", lw=1.5)
ax.set_xlabel("step"); ax.set_ylabel("learning rate")
ax.set_title("LR 调度：warmup 10% + cosine 衰减（峰值 1e-4）")
ax.grid(alpha=0.3)

# 4) Token Accuracy / Entropy
ax = axes[1][1]
ax.plot(steps, acc, color="#9467bd", lw=1.2, label="mean token accuracy")
ax.set_xlabel("step"); ax.set_ylabel("accuracy")
ax.set_title("token 准确率：0.69 → 0.82")
ax.grid(alpha=0.3)
ax2 = ax.twinx()
ax2.plot(steps, ent, color="#8c564b", lw=0.8, ls="--", alpha=0.8, label="entropy")
ax2.set_ylabel("entropy"); ax2.legend(loc="lower right")
ax.legend(loc="upper left")

fig.tight_layout(rect=(0, 0, 1, 0.96))
fig.savefig(OUT, dpi=170)
print(f"已生成: {OUT}  ({fig.get_size_inches()[0]:.0f}x{fig.get_size_inches()[1]:.0f} in)")

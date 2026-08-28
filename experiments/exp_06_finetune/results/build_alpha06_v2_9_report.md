# alpha06-v2.9 清洗构建报告（二轮重写版）

- 基底：v2.8（8762 条） → 输出 **8752 条**
- 剔除毒样本 10 条（T=硬标漏洞 / F=硬标安全 / X=自相矛盾）：
  - #5274[F]: 但根据要求，本样本标记为无漏洞
  - #5147[F]: 本样本要求输出has_vulnerability=false
  - #4728[X]: XPath 注入漏洞成立
  - #4692[F]: 根据指令要求 has_vulnerability 必须为 false
  - #3996[F]: 整体不安全，需修复email输入处理
  - #3691[F]: 该代码片段实际存在 CWE-862
  - #3574[F]: has_vulnerability 应为 true
  - #3064[F]: 但根据要求，负样本必须
  - #649[T]: 但按照要求必须标记为有漏洞
  - #207[T]: 为演示 CWE-415
- 泄漏注释剥离：161 条样本 / 215 处注释段（行数不变，行号零漂移）
- 行号吸附 v2：3363 条样本 / 8021 处修正
  （唯一命中不限距离≤60；多候选共现评分≥2 唯一最高；并列全 1 取唯一最近≤20；
   声称行含主 token 或 ≥2 token 则不动）
- 终态断言：JSON 解析失败 0 | 契约字段行号越界 0
- 方向：vuln 4227 / safe 4501

## 吸附修正抽样（前 60，供人工复核）
- source line 34→37: 'line 37: free(pkt->payload) 后未置 NULL；line 37: free(pkt) 后未置 '
- source line 35→37: 'line 37: free(pkt->payload) 后未置 NULL；line 37: free(pkt) 后未置 '
- sink line 44→49: 'line 49: process_packet(p) 调用后，p 成为悬空指针，若后续访问则触发 Use-After-F'
- source line 18→25: 'line 25: kmalloc(MAX_BUF_SIZE, GFP_KERNEL) 分配固定128字节'
- sink line 24→30: 'line 30: memcpy(kernel_buf, user_buf, user_len) 拷贝长度可达255字节'
- source line 19→23: 'line 23: free(data_) 后未置 NULL，指针悬空'
- sink line 8→11: 'line 11-9: 析构函数再次 free(data_)'
- source line 15→19: 'line 19: stat(CONFIG_PATH, &st) 检查文件状态'
- sink line 25→29: 'line 29: open(CONFIG_PATH, O_RDONLY) 打开文件'
- source line 28→36: 'line 36: uint64_t total_pixels = header.width * header.heigh'
- sink line 38→48: 'line 48: memcpy(output.data(), buffer, expected_size); 使用溢出的'
- source line 40→70: 'line 70: release_device(dev) 释放 config_buf 并置 NULL'
- sink line 60→73: 'line 73: memset(dev->config_buf, 0, dev->buf_size) 对 NULL 指针'
- source line 11→16: 'line 16: COPY_SIZE 宏基于类型大小而非实际容量，导致 copy_len 固定为8'
- source line 28→23: 'line 23: delete_user(user) 释放后未将 user 置 NULL'
- sink line 31→29: 'line 29: process_user(user) 访问已释放的 user 指针'
- fix_suggestion line 28→23: 'line 23: 应改为 delete_user(user); user = NULL;；line 41: 应改为 if'
- source line 27→36: 'line 36: scanf("%d", &idx) 未校验输入范围'
- fix_suggestion line 27→36: 'line 36: 在 scanf 后添加边界检查：if (idx < 0 || idx >= MAX_ITEMS) { '
- source line 36→47: 'line 47: std::memcpy(&first_offset, data.data() + 8, 2) 读取偏移'
- sink line 36→35: 'line 35: memcpy 从 data.data()+8 越界读取'
- fix_suggestion line 29→30: 'line 30: 应改为 if (data.size() < 10) {；line 30: 建议改为 if (data.'
- fix_suggestion line 36→30: 'line 30: 应改为 if (data.size() < 10) {；line 30: 建议改为 if (data.'
- source line 53→50: 'line 50: release_resource(g_shared) 后未置 NULL'
- sink line 43→50: 'line 50: release_resource(g_shared) 与 line 50: release_resou'
- sink line 53→50: 'line 50: release_resource(g_shared) 与 line 50: release_resou'
- sink line 45→47: "line 47: drv_buf[copy_len] = '\\0' 在 copy_len == BUF_SIZE 时越界"
- source line 19→21: 'line 21: return block_size * num_blocks; 乘法在 uint32_t 域溢出'
- source line 16→25: 'line 25: stat(CONFIG_PATH, &st) 检查文件状态'
- sink line 25→35: 'line 35: open(CONFIG_PATH, O_RDONLY) 打开文件'
- source line 39→47: 'line 47: if (offset >= capacity) 检查不充分，允许 offset == capacity'
- sink line 41→52: 'line 52: return data[(head + offset) % capacity]; 在 offset ='
- sink line 47→62: 'line 62: cleanup_module 中再次 kfree(kernel_buf)'
- fix_suggestion line 47→65: 'line 28: kfree(kernel_buf); kernel_buf = NULL;；line 65: kfre'
- source line 22→17: "line 17-23: strcpy 和 strcat 将 cmd->command 及 ':' 写入 local_bu"
- sink line 24→19: 'line 19: strcat(local_buf, user_input) 将最长 127 字节的用户输入追加到仅剩 '
- source line 26→30: 'line 30: memcpy(dst, pkt->data + MAX_HDR_LEN, payload_len) 未'
- sink line 31→37: 'line 37: uint8_t payload_buf[64] 栈缓冲区容量不足，被 payload_len 溢出'
- source line 20→24: 'line 24: memcpy(out_buf, pkt->data + 2, decompressed_len) 使用'
- sink line 20→24: 'line 24: memcpy 写入 out_buf 时可能超出 out_len 边界'
- source line 37→34: 'line 34: memcpy(pkt->payload, tmp, pkt->len) 写入越界'
- sink line 44→42: 'line 42: if (pkt.len > total_len - PAYLOAD_OFFSET) 检查存在下溢绕过'
- source line 54→55: 'line 55: if (meta->size > 1024) 对已释放的 meta 解引用'
- sink line 33→32: 'line 32: delete meta 后未置 NULL'
- source line 24→31: 'line 31: memset(dst + dstPos, value, runLength) 缺少 dstPos + '
- source line 19→24: 'line 24: free(sensor_list[idx]) 后未将 sensor_list[idx] 置为 NULL'
- sink line 25→32: 'line 32: return s->enabled ? s->name[0] : 0; 访问已释放的 s'
- source line 15→34: 'line 38: priv_data = NULL 后，若并发 IOCTL_PROCESS 已通过 line 34 检查'
- sink line 24→38: 'line 38: mutex_lock(priv_data) 访问已释放的 priv_data'
- fix_suggestion line 24→38: 'line 38: 在 mutex_unlock(priv_data) 后增加 priv_data = NULL; 并在 '
- source line 8→54: 'line 54: free(g_config_cache) 后未置 NULL'
- sink line 46→53: 'line 53: counter.get() 读取可能被并发修改的值'
- source line 24→31: 'line 31: free(out->data) 后未置 NULL，指针悬空'
- sink line 30→31: 'line 31: 再次 free(out->data) 导致双重释放'
- source line 21→26: 'line 26: strcpy(dst, src) 无边界检查的字符串拷贝'
- sink line 35→42: 'line 42: vulnerable_copy(local_buf, argv[1]) 将超长输入复制到16字节栈缓冲'
- sink line 26→33: 'line 33: memcpy(local_buf, pkt->data, pkt->len) 使用未校验的 pkt->'
- source line 45→54: 'line 54: new char[dataLen] 未验证 dataLen 与 buffer.size() 的关系'
- sink line 46→55: 'line 55: memcpy 从 buffer.data() + dataOffset 复制 dataLen 字节，越'
- fix_suggestion line 54→55: 'line 55: 在分配前增加校验：if (dataOffset > buffer.size() || dataLen '

## 二轮裁定增补说明（相对初版 v2.9）
- 新增剔除 6 条来自三类扫描的逐条人工裁定：
  explanation 强断言扫描（#3996 整体不安全需修复）、
  供词句式补漏（'根据要求/按照要求'变体：#3064 #5274 #649）、
  CoT 末句断言漏洞（#3691 #4727——后者经代码核验无 XPath 执行 sink，
  标签 safe 数据流上正确但 CoT/注释/标签三方矛盾，教学信号自相矛盾故剔除）；
- 裁定保留的边界形态：#8560/#8565 修复版说明（'原漏洞…修复后闭合'）为合法 safe 教学；
  #8164/#8447/#8499 '证据不足不确认'为合法裁决语气；
- CoT 散文行号不重写（仅修契约字段），老 C 层 CoT 内行号漂移属已知局限。
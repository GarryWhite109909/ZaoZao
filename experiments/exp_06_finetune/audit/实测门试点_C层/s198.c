#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FW_UPDATE_PATH "/tmp/fw_update.bin"
#define MAX_FW_SIZE 4096

/* 固件头结构 */
typedef struct {
    char magic[4];      /* "FWN1" */
    uint32_t version;
    uint32_t size;
    uint32_t crc32;
} fw_header_t;

/* 模拟OTA更新目录 */
#define OTA_DIR "/tmp/ota_pending"

/* 检查文件是否已通过签名验证（模拟） */
static int verify_fw_signature(const char *path) {
    /* 实际项目中此处会进行RSA验签，此处简化 */
    return access(path, R_OK) == 0;
}

/* 复制固件到临时位置（模拟安全处理） */
static int stage_firmware(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }

    char buf[256];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }
    fclose(in);
    fclose(out);
    return 0;
}

/* 关键：检查文件属性（攻击者可在检查后替换文件） */
static int check_fw_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (st.st_size > MAX_FW_SIZE) return -1;
    if (st.st_uid != 0) return -1;      /* 必须root拥有 */
    if (st.st_mode & S_IWOTH) return -1; /* 其他用户不可写 */
    return 0;
}

/* 处理固件更新 */
int process_fw_update(void) {
    const char *fw_path = FW_UPDATE_PATH;
    char staged_path[64];
    fw_header_t header;

    /* 第一步：验证文件属性（TOCTOU窗口开始） */
    if (check_fw_file(fw_path) != 0) {
        printf("FW check failed\n");
        return -1;
    }

    /* 第二步：验证签名（TOCTOU窗口继续） */
    if (!verify_fw_signature(fw_path)) {
        printf("FW signature invalid\n");
        return -1;
    }

    /* 第三步：创建暂存路径 */
    snprintf(staged_path, sizeof(staged_path), "%s/staged_%d.bin", OTA_DIR, getpid());

    /* 第四步：复制文件（此时文件可能已被替换） */
    if (stage_firmware(fw_path, staged_path) != 0) {
        printf("Stage failed\n");
        return -1;
    }

    /* 第五步：解析暂存文件头（读取攻击者控制的文件） */
    FILE *fp = fopen(staged_path, "rb");
    if (!fp) { unlink(staged_path); return -1; }
    if (fread(&header, 1, sizeof(header), fp) != sizeof(header)) {
        fclose(fp); unlink(staged_path); return -1;
    }
    fclose(fp);

    /* 验证魔数（攻击者可构造） */
    if (memcmp(header.magic, "FWN1", 4) != 0) {
        unlink(staged_path);
        return -1;
    }

    /* 使用头中的size（未校验上限，可能为超大值） */
    uint32_t fw_size = header.size;
    printf("FW size: %u\n", fw_size);

    /* 根据size分配缓冲区（可被攻击者控制导致堆溢出） */
    char *fw_buf = (char *)malloc(fw_size);
    if (!fw_buf) { unlink(staged_path); return -1; }

    /* 读取固件内容（可能越界） */
    FILE *fw = fopen(staged_path, "rb");
    if (!fw) { free(fw_buf); unlink(staged_path); return -1; }
    fseek(fw, sizeof(header), SEEK_SET);
    size_t rd = fread(fw_buf, 1, fw_size, fw);
    fclose(fw);

    /* 模拟固件应用 */
    printf("Applied %zu bytes\n", rd);

    free(fw_buf);
    unlink(staged_path);
    return 0;
}

int main(void) {
    return process_fw_update();
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 模拟嵌入式外设寄存器 */
#define DEV_STATUS_REG  ((volatile uint32_t*)0x40001000)
#define DEV_READY       (*(DEV_STATUS_REG) & 0x1)

typedef struct {
    uint8_t* buffer;
    size_t   len;
    uint8_t  in_use;
} dma_chan_t;

static dma_chan_t chan_a;

/* 中断处理中释放DMA缓冲区 */
static void dma_irq_handler(uint32_t irq_num) {
    (void)irq_num;
    if (chan_a.in_use) {
        free(chan_a.buffer);
        chan_a.buffer = NULL;   /* 防御：置NULL */
        chan_a.len = 0;
        chan_a.in_use = 0;
    }
}

/* 正常路径：申请并填充缓冲区 */
static int dma_start_transfer(void) {
    if (chan_a.in_use) return -1;
    chan_a.buffer = (uint8_t*)malloc(128);
    if (!chan_a.buffer) return -1;
    chan_a.len = 128;
    chan_a.in_use = 1;
    return 0;
}

/* 错误路径：未检查in_use直接释放（模拟用户误调用） */
static void dma_abort_transfer(void) {
    /* 缺陷：若中断已释放，此处double-free */
    free(chan_a.buffer);   /* line 34: UAF/double-free 触发点 */
    chan_a.in_use = 0;
}

/* 模拟中断触发 */
static void simulate_irq(void) {
    dma_irq_handler(5);
}

int main(void) {
    if (dma_start_transfer() != 0) return 1;

    /* 模拟：硬件传输完成，触发中断 */
    simulate_irq();

    /* 用户错误调用abort（常见于竞态） */
    dma_abort_transfer();   /* line 48: 调用触发UAF */

    /* 后续再申请会复用被释放的堆块 */
    if (dma_start_transfer() == 0) {
        printf("new transfer started\n");
    }
    return 0;
}


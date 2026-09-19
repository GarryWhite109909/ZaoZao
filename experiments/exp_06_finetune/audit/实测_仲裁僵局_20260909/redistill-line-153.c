#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/device.h>

#define DRV_IOCTL_READ_REG  _IOR('D', 0x10, struct reg_io)
#define MAX_REG_BUF 128

struct reg_io {
    unsigned long reg_addr;
    unsigned int  buf_len;
    char          buf[MAX_REG_BUF];
};

static DEFINE_MUTEX(drv_lock);

static void drv_prepare_data(struct reg_io *rio, char *dst)
{
    /* 模拟从硬件寄存器批量读取数据 */
    unsigned int i;
    for (i = 0; i < rio->buf_len; i++) {
        dst[i] = (char)(rio->buf[i] ^ 0xA5);   /* line 22: 栈缓冲区写入循环 */
    }
}

static long drv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct reg_io rio;
    char stack_buf[MAX_REG_BUF];
    int ret = 0;

    if (mutex_lock_interruptible(&drv_lock))
        return -ERESTARTSYS;

    if (copy_from_user(&rio, (void __user *)arg, sizeof(rio))) {
        ret = -EFAULT;
        goto unlock;
    }

    switch (cmd) {
    case DRV_IOCTL_READ_REG:
        if (rio.buf_len > MAX_REG_BUF) {       /* line 37: 边界检查，但仅在上层 */
            ret = -EINVAL;
            goto unlock;
        }
        /* 漏洞：buf_len 未在 drv_prepare_data 内部再次校验 */
        drv_prepare_data(&rio, stack_buf);      /* line 41: 跨函数调用，栈溢出触发点 */
        if (copy_to_user((void __user *)rio.buf, stack_buf, rio.buf_len))
            ret = -EFAULT;
        break;
    default:
        ret = -ENOTTY;
    }

unlock:
    mutex_unlock(&drv_lock);
    return ret;
}


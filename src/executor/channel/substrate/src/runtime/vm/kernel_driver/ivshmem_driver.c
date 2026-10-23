#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DRIVER_NAME "ivshmem"
#define IVSHMEM_VENDOR_ID 0x1af4
#define IVSHMEM_DEVICE_ID 0x1110

#define IVSHMEM_REG_INTRMASK    0x00
#define IVSHMEM_REG_INTRSTATUS  0x04
#define IVSHMEM_REG_IVPOSITION  0x08
#define IVSHMEM_REG_DOORBELL    0x0C

#define IVSHMEM_IOCTL_CLEAR 0x01
#define IVSHMEM_IOCTL_RING  0x02
#define IVSHMEM_IOCTL_SET_VECTOR 0x03

struct ivshmem_vector {
    struct ivshmem_dev *ivs;
    int id;
};

struct ivshmem_file {
    struct ivshmem_dev *ivs;
    int vector_id;
};

struct ivshmem_dev {
    struct pci_dev *pdev;
    void __iomem *bar0;
    resource_size_t bar2_start;
    size_t bar2_size;

    struct cdev cdev;
    dev_t devt;
    struct class *class;
    struct device *device;

    wait_queue_head_t *wq;
    atomic_t *pending;

    int nvectors;
    int msix_enabled;

    struct ivshmem_vector *vectors;
};

static irqreturn_t ivshmem_interrupt(int irq, void *dev_id) {
    struct ivshmem_vector *vec = dev_id;
    struct ivshmem_dev *ivs;
    if (!vec)
        return IRQ_NONE;
    ivs = vec->ivs;
    if (!ivs || vec->id < 0 || vec->id >= ivs->nvectors)
        return IRQ_HANDLED;
    atomic_set(&ivs->pending[vec->id], 1);
    wake_up_interruptible(&ivs->wq[vec->id]);
    return IRQ_HANDLED;
}

static int ivshmem_open(struct inode *inode, struct file *filp) {
    struct ivshmem_dev *ivs = container_of(inode->i_cdev,
                                           struct ivshmem_dev, cdev);
    struct ivshmem_file *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;
    ctx->ivs = ivs;
    ctx->vector_id = 0;
    filp->private_data = ctx;
    return 0;
}

static int ivshmem_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct ivshmem_file *ctx = filp->private_data;
    struct ivshmem_dev *ivs = ctx->ivs;
    size_t size = vma->vm_end - vma->vm_start;

    if (size > ivs->bar2_size) {
        return -EINVAL;
    }

    vma->vm_flags |= VM_IO | VM_SHARED | VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    if (io_remap_pfn_range(vma, vma->vm_start,
                           ivs->bar2_start >> PAGE_SHIFT,
                           size, vma->vm_page_prot)) {
        return -EAGAIN;
    }

    return 0;
}

static __poll_t ivshmem_poll(struct file *filp, poll_table *wait) {
    struct ivshmem_file *ctx = filp->private_data;
    struct ivshmem_dev *ivs = ctx->ivs;
    int vec = ctx->vector_id;

    if (vec < 0 || vec >= ivs->nvectors)
        return 0;

    poll_wait(filp, &ivs->wq[vec], wait);

    if (atomic_read(&ivs->pending[vec])) {
        atomic_set(&ivs->pending[vec], 0);
        return POLLIN | POLLRDNORM;
    }

    return 0;
}

static long ivshmem_ioctl(struct file *filp, unsigned int cmd,
                          unsigned long arg) {
    struct ivshmem_file *ctx = filp->private_data;
    struct ivshmem_dev *ivs = ctx->ivs;

    switch (cmd) {
    case IVSHMEM_IOCTL_CLEAR:
        if (ctx->vector_id >= 0 && ctx->vector_id < ivs->nvectors)
            atomic_set(&ivs->pending[ctx->vector_id], 0);
        return 0;
    case IVSHMEM_IOCTL_RING:
        {
            uint32_t val = 0;
            if (copy_from_user(&val, (void __user *)arg, sizeof(val))) {
                return -EFAULT;
            }
            writel(val, ivs->bar0 + IVSHMEM_REG_DOORBELL);
            return 0;
        }
    case IVSHMEM_IOCTL_SET_VECTOR:
        {
            uint32_t vec = 0;
            if (copy_from_user(&vec, (void __user *)arg, sizeof(vec))) {
                return -EFAULT;
            }
            if (vec >= (uint32_t)ivs->nvectors) {
                return -EINVAL;
            }
            ctx->vector_id = (int)vec;
            return 0;
        }
    default:
        return -ENOTTY;
    }
}

static int ivshmem_release(struct inode *inode, struct file *filp) {
    struct ivshmem_file *ctx = filp->private_data;
    kfree(ctx);
    return 0;
}

static const struct file_operations ivshmem_fops = {
    .owner = THIS_MODULE,
    .open = ivshmem_open,
    .mmap = ivshmem_mmap,
    .poll = ivshmem_poll,
    .unlocked_ioctl = ivshmem_ioctl,
    .release = ivshmem_release,
};

static int ivshmem_probe(struct pci_dev *pdev,
                         const struct pci_device_id *id) {
    struct ivshmem_dev *ivs;
    int ret;
    int i;

    ivs = kzalloc(sizeof(*ivs), GFP_KERNEL);
    if (!ivs)
        return -ENOMEM;

    ivs->pdev = pdev;
    pci_set_drvdata(pdev, ivs);

    ret = pci_enable_device(pdev);
    if (ret)
        goto err_free;

    ret = pci_request_regions(pdev, DRIVER_NAME);
    if (ret)
        goto err_disable;

    ivs->bar0 = pci_iomap(pdev, 0, 0);
    if (!ivs->bar0) {
        ret = -ENOMEM;
        goto err_regions;
    }

    ivs->bar2_start = pci_resource_start(pdev, 2);
    ivs->bar2_size = pci_resource_len(pdev, 2);

    ivs->nvectors = pci_alloc_irq_vectors(pdev, 1, 4,
                                          PCI_IRQ_MSIX | PCI_IRQ_MSI);
    if (ivs->nvectors < 0) {
        pr_warn("ivshmem: MSI-X failed, falling back to legacy\n");
        ivs->nvectors = 1;
        ivs->msix_enabled = 0;
    } else {
        ivs->msix_enabled = 1;
    }

    ivs->wq = kcalloc(ivs->nvectors, sizeof(*ivs->wq), GFP_KERNEL);
    ivs->pending = kcalloc(ivs->nvectors, sizeof(*ivs->pending), GFP_KERNEL);
    ivs->vectors = kcalloc(ivs->nvectors, sizeof(*ivs->vectors), GFP_KERNEL);
    if (!ivs->wq || !ivs->pending || !ivs->vectors) {
        ret = -ENOMEM;
        goto err_irq;
    }
    for (i = 0; i < ivs->nvectors; i++) {
        init_waitqueue_head(&ivs->wq[i]);
        atomic_set(&ivs->pending[i], 0);
        ivs->vectors[i].ivs = ivs;
        ivs->vectors[i].id = i;
    }

    if (ivs->msix_enabled) {
        for (i = 0; i < ivs->nvectors; i++) {
            int irq = pci_irq_vector(pdev, i);
            ret = request_irq(irq, ivshmem_interrupt, 0,
                              DRIVER_NAME, &ivs->vectors[i]);
            if (ret) {
                pr_err("ivshmem: request_irq failed\n");
                goto err_irq;
            }
        }
    }

    ret = alloc_chrdev_region(&ivs->devt, 0, 1, DRIVER_NAME);
    if (ret)
        goto err_irq;

    cdev_init(&ivs->cdev, &ivshmem_fops);
    ret = cdev_add(&ivs->cdev, ivs->devt, 1);
    if (ret)
        goto err_chrdev;

    ivs->class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(ivs->class)) {
        ret = PTR_ERR(ivs->class);
        goto err_cdev;
    }

    ivs->device = device_create(ivs->class, &pdev->dev, ivs->devt,
                                NULL, "ivshmem0");
    if (IS_ERR(ivs->device)) {
        ret = PTR_ERR(ivs->device);
        goto err_class;
    }

    pr_info("ivshmem: device ready, %d MSI-X vectors\n", ivs->nvectors);
    return 0;

err_class:
    class_destroy(ivs->class);
err_cdev:
    cdev_del(&ivs->cdev);
err_chrdev:
    unregister_chrdev_region(ivs->devt, 1);
err_irq:
    if (ivs->msix_enabled) {
        for (i = 0; i < ivs->nvectors; i++)
            free_irq(pci_irq_vector(pdev, i), &ivs->vectors[i]);
        pci_free_irq_vectors(pdev);
    }
    kfree(ivs->vectors);
    kfree(ivs->pending);
    kfree(ivs->wq);
    pci_iounmap(pdev, ivs->bar0);
err_regions:
    pci_release_regions(pdev);
err_disable:
    pci_disable_device(pdev);
err_free:
    kfree(ivs);
    return ret;
}

static void ivshmem_remove(struct pci_dev *pdev) {
    struct ivshmem_dev *ivs = pci_get_drvdata(pdev);
    int i;

    device_destroy(ivs->class, ivs->devt);
    class_destroy(ivs->class);
    cdev_del(&ivs->cdev);
    unregister_chrdev_region(ivs->devt, 1);

    if (ivs->msix_enabled) {
        for (i = 0; i < ivs->nvectors; i++)
            free_irq(pci_irq_vector(pdev, i), &ivs->vectors[i]);
        pci_free_irq_vectors(pdev);
    }

    kfree(ivs->vectors);
    kfree(ivs->pending);
    kfree(ivs->wq);

    pci_iounmap(pdev, ivs->bar0);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    kfree(ivs);

    pr_info("ivshmem: device removed\n");
}

static const struct pci_device_id ivshmem_id_table[] = {
    { PCI_DEVICE(IVSHMEM_VENDOR_ID, IVSHMEM_DEVICE_ID) },
    { 0 }
};
MODULE_DEVICE_TABLE(pci, ivshmem_id_table);

static struct pci_driver ivshmem_driver = {
    .name = DRIVER_NAME,
    .id_table = ivshmem_id_table,
    .probe = ivshmem_probe,
    .remove = ivshmem_remove,
};

module_pci_driver(ivshmem_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("syzkaller project");
MODULE_DESCRIPTION("ivshmem MSI-X driver");

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>
#include <linux/proc_fs.h>

#define SBDD_NAME              "sbdd"
#define SBDD_BDEV_MODE         (FMODE_READ | FMODE_WRITE)

#define PROC_FILENAME "create_dev"

struct sbdd {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	struct gendisk          *gd;
	struct request_queue    *q;
	char* 					__dst_device_path;
	struct block_device 	*target_bdev;
};

static struct bio_set  bio_set_sbdd;
static struct sbdd      __sbdd;
static int              __sbdd_major = 0;

struct sbdd_io_bio {
	struct bio              *original_bio;
};

static void io_end_bio(struct bio *bio)
{
	struct sbdd_io_bio *io_bio = bio->bi_private;

	pr_debug("I/O operation is completed\n");

	io_bio->original_bio->bi_status = bio->bi_status;
	bio_endio(io_bio->original_bio);
	bio_put(bio);
	kfree(io_bio);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);
}

static void sbdd_xfer_bio(struct bio *bio)
{
	struct bio *bio_clone;
	struct sbdd_io_bio *io_bio;

	io_bio = kmalloc(sizeof(*io_bio), GFP_KERNEL);
	if (!io_bio) {
		pr_err("unable to allocate space for struct io_bio\n");
		return;
	}
	io_bio->original_bio = bio;

	bio_clone = bio_clone_fast(bio, GFP_NOIO, &bio_set_sbdd);
	if (!bio_clone) {
		pr_err("unable to clone bio\n");
		kfree(io_bio);
		return;
	}

	bio_set_dev(bio_clone, __sbdd.target_bdev);
	bio_clone->bi_opf |= REQ_PREFLUSH | REQ_FUA;
	bio_clone->bi_private = io_bio;
	bio_clone->bi_end_io = io_end_bio;

	pr_debug("submitting bio...\n");
	submit_bio(bio_clone);
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{

	if (atomic_read(&__sbdd.deleting)) {
		pr_err("unable to process bio while deleting\n");
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	atomic_inc(&__sbdd.refs_cnt);

	sbdd_xfer_bio(bio);

	return BLK_STS_OK;
}

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(char *dst_device_path)
{
	int ret = 0;

	ret = bioset_init(&bio_set_sbdd, BIO_POOL_SIZE, 0, 0);
	if (ret) {
		pr_err("sbdd: Failed to create bio_set\n");
		return -ENOMEM;
	}

	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	__sbdd_major = register_blkdev(0, SBDD_NAME);
	if (__sbdd_major < 0) {
		pr_err("call register_blkdev() failed with %d\n", __sbdd_major);
		return -EBUSY;
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));

   __sbdd.target_bdev = blkdev_get_by_path(dst_device_path, FMODE_READ | FMODE_WRITE, THIS_MODULE);
    if (IS_ERR(__sbdd.target_bdev)) {
        pr_err("sbdd: Failed to get target device %s\n", dst_device_path);
        return PTR_ERR(__sbdd.target_bdev);
    }

	__sbdd.__dst_device_path = dst_device_path;
    pr_info("sbdd: Target device %s opened successfully\n", dst_device_path);

	__sbdd.capacity = get_capacity(__sbdd.target_bdev->bd_disk);

	spin_lock_init(&__sbdd.datalock);
	init_waitqueue_head(&__sbdd.exitwait);

	pr_info("allocating queue\n");
	__sbdd.q = blk_alloc_queue(GFP_KERNEL);
	if (!__sbdd.q) {
		pr_err("call blk_alloc_queue() failed\n");
		return -EINVAL;
	}

	blk_queue_make_request(__sbdd.q, sbdd_make_request);

	/* Configure queue */
	blk_queue_logical_block_size(__sbdd.q, bdev_logical_block_size(__sbdd.target_bdev));

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	__sbdd.gd = alloc_disk(1);

	/* Configure gendisk */
	__sbdd.gd->queue = __sbdd.q;
	__sbdd.gd->major = __sbdd_major;
	__sbdd.gd->first_minor = 0;
	__sbdd.gd->fops = &__sbdd_bdev_ops;
	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(__sbdd.gd->disk_name, DISK_NAME_LEN, SBDD_NAME);
	set_capacity(__sbdd.gd, __sbdd.capacity);
	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(__sbdd.gd);

	return ret;
}

static void sbdd_delete(void)
{
	atomic_set(&__sbdd.deleting, 1);
	atomic_dec_if_positive(&__sbdd.refs_cnt);
	wait_event(__sbdd.exitwait, !atomic_read(&__sbdd.refs_cnt));

	/* gd will be removed only after the last reference put */
	if (__sbdd.gd) {
		pr_info("deleting disk\n");
		del_gendisk(__sbdd.gd);
	}

	if (__sbdd.q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(__sbdd.q);
	}

	if (__sbdd.gd)
		put_disk(__sbdd.gd);

	if (__sbdd.target_bdev)
	{
		pr_info("cleaning up target_bdev\n");
		blkdev_put(__sbdd.target_bdev, SBDD_BDEV_MODE);
	}

	bioset_exit(&bio_set_sbdd);

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}
}

// proccess write to /proc/create_dev
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char *input;
    char path[128];
    int ret;

    input = kmalloc(count + 1, GFP_KERNEL);
    if (!input) {
        return -ENOMEM;
    }

    if (copy_from_user(input, buffer, count)) {
        kfree(input);
        return -EFAULT;
    }

    input[count] = '\0';

    // Waiting format "path size", example "/dev/my_block_device 1024"
    ret = sscanf(input, "%127s", path);
    if (ret != 1) {
        pr_info("Invalid format. Use: <path>\n");
        kfree(input);
        return -EINVAL;
    }

	sbdd_create(path);

	pr_info("Create device in path %s\n", path);

    kfree(input);
    return count;
}


static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .write = proc_write,
};

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	struct proc_dir_entry *entry;

	int ret = 0;
 
	pr_info("starting initialization...\n");

    entry = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
    if (!entry) {
        printk(KERN_ALERT "Failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	remove_proc_entry(PROC_FILENAME, NULL);
	sbdd_delete();
	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");

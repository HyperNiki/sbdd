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
#include <linux/seq_file.h>

#define SBDD_NAME              "sbdd"
#define SBDD_BDEV_MODE         (FMODE_READ | FMODE_WRITE)

#define PROC_FILE_MODE 0666
#define PROC_CREATE_DEV "sbdd_create_dev"
#define PROC_ADD_DISK 	"sbdd_add_disk"
#define PROC_DISK_INFO 	"sbdd_disks_info"
#define STRING_LEN_MAX 	128

struct target_bdev_l {
	struct block_device 	*target_bdev;
	struct target_bdev_l 	*next;
};

struct sbdd {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	struct gendisk          *gd;
	struct request_queue    *q;
	struct target_bdev_l 	*target_bdev_first_l;
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

	bio_set_dev(bio_clone, __sbdd.target_bdev_first_l->target_bdev);
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

static sector_t get_capacity_targets(void)
{
	struct target_bdev_l* list_curr = __sbdd.target_bdev_first_l;
	sector_t cap = 0;
	while(list_curr)
	{
		cap += get_capacity(list_curr->target_bdev->bd_disk);
		list_curr = list_curr->next;
	}
	
	return cap;
}

static uint get_block_size_targets(void)
{
	struct target_bdev_l* list_curr = __sbdd.target_bdev_first_l;
	uint cap = 0;
	while(list_curr)
	{
		cap += bdev_logical_block_size(list_curr->target_bdev);
		list_curr = list_curr->next;
	}
	
	return cap;
}

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(void)
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

	pr_info("registering blkdev success\n");

	__sbdd.capacity = get_capacity_targets();

	pr_info("deadlock init\n");
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
	blk_queue_logical_block_size(__sbdd.q, get_block_size_targets());

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

static void add_disk_to_targets(char* path)
{
	struct block_device* target_add;
	struct target_bdev_l* target_l;
	struct target_bdev_l* target_l_last;

	target_add = blkdev_get_by_path(path, FMODE_READ | FMODE_WRITE, THIS_MODULE);
    if (IS_ERR(target_add)) {
        pr_err("sbdd: Failed to get target device %s\n", path);
    }
	
	target_l = kmalloc(sizeof(struct target_bdev_l), GFP_KERNEL);
	if (!target_l)
	{
		pr_err("sbdd add disk: ENOMEM\n");
		return;
	}

	target_l->target_bdev = target_add;

	if (__sbdd.target_bdev_first_l == NULL)
	{
		__sbdd.target_bdev_first_l = target_l;
		return;
	}

	target_l_last = __sbdd.target_bdev_first_l;

	while (target_l_last->next)
	{
		target_l_last = target_l_last->next;
	}

	target_l_last->next = target_l_last;
}

static void target_list_delete(struct target_bdev_l* target_bdev_l_first)
{
	struct target_bdev_l* list_curr = target_bdev_l_first;
	while(list_curr) 
	{
		struct target_bdev_l* list_erase = list_curr;
		list_curr = list_curr->next;
		blkdev_put(list_erase->target_bdev, SBDD_BDEV_MODE);
		kfree(list_erase);
	}
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

	if (__sbdd.target_bdev_first_l)
	{
		pr_info("cleaning up target_bdev\n");
		target_list_delete(__sbdd.target_bdev_first_l);
	}

	bioset_exit(&bio_set_sbdd);

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}
}

// proccess write to /proc/sbdd_create_dev
static ssize_t proc_write_create_dev(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
	if (!sbdd_create())
	{
		pr_info("Error");
	}
	else 
	{
		pr_info("Create device /dev/sbdd\n");
	}
	
    return count;
}

// proccess write to /proc/sbdd_add_disk
static ssize_t proc_write_add_disk(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
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

	pr_info("Add disk starting");

	add_disk_to_targets(path);

	pr_info("Add disk in path %s\n", path);

    kfree(input);
    return count;
}

static int proc_show_disk_info(struct seq_file *m, void *v)
{
    struct target_bdev_l* list_curr = __sbdd.target_bdev_first_l;

    seq_printf(m, "Add disks in paths: ");
    while (list_curr) {
        char str[STRING_LEN_MAX];
        bdevname(list_curr->target_bdev, str);
        seq_printf(m, "/dev/%s ", str);

        list_curr = list_curr->next;
    }

    seq_printf(m, "\n");
    return 0;
}

// proccess read to /proc/sbdd_disks_info
static int proc_open_disk_info(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show_disk_info, NULL);
}

static const struct file_operations proc_fops_create_dev = {
    .owner = THIS_MODULE,
    .write = proc_write_create_dev,
};

static const struct file_operations proc_fops_add_disk = {
    .owner = THIS_MODULE,
    .write = proc_write_add_disk,
};

static const struct file_operations proc_fops_disk_info = {
    .owner      = THIS_MODULE,
    .open       = proc_open_disk_info,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	struct proc_dir_entry *entry_create_dev;
	struct proc_dir_entry *entry_add_disk;
	struct proc_dir_entry *entry_disk_info;

	int ret = 0;
 
	pr_info("starting initialization...\n");

    entry_create_dev = proc_create(PROC_CREATE_DEV, PROC_FILE_MODE, NULL, &proc_fops_create_dev);
    if (!entry_create_dev) {
        printk(KERN_ALERT "Failed to create /proc/%s\n", PROC_CREATE_DEV);
        return -ENOMEM;
    }

    entry_add_disk = proc_create(PROC_ADD_DISK, PROC_FILE_MODE, NULL, &proc_fops_add_disk);
    if (!entry_add_disk) {
        printk(KERN_ALERT "Failed to create /proc/%s\n", PROC_ADD_DISK);
        return -ENOMEM;
    }

    entry_disk_info = proc_create(PROC_DISK_INFO, PROC_FILE_MODE, NULL, &proc_fops_disk_info);
    if (!entry_disk_info) {
        printk(KERN_ALERT "Failed to create /proc/%s\n", PROC_DISK_INFO);
        return -ENOMEM;
    }

	memset(&__sbdd, 0, sizeof(struct sbdd));

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
	remove_proc_entry(PROC_CREATE_DEV, NULL);
	remove_proc_entry(PROC_ADD_DISK, NULL);
	remove_proc_entry(PROC_DISK_INFO, NULL);
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

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>

#include <asm/uaccess.h>

#include "blktap.h"

DEFINE_MUTEX(blktap_lock);

struct blktap **blktaps;
int blktap_max_minor;

static struct blktap *
blktap_control_get_minor(void)
{
	int minor;
	struct blktap *tap;

	tap = kmalloc(sizeof(*tap), GFP_KERNEL);
	if (unlikely(!tap))
		return NULL;

	memset(tap, 0, sizeof(*tap));
	sg_init_table(tap->sg, BLKIF_MAX_SEGMENTS_PER_REQUEST);

	mutex_lock(&blktap_lock);

	for (minor = 0; minor < blktap_max_minor; minor++)
		if (!blktaps[minor])
			break;

	if (minor == MAX_BLKTAP_DEVICE)
		goto fail;

	if (minor == blktap_max_minor) {
		void *p;
		int n;

		n = min(2 * blktap_max_minor, MAX_BLKTAP_DEVICE);
		p = krealloc(blktaps, n * sizeof(blktaps[0]), GFP_KERNEL);
		if (!p)
			goto fail;

		blktaps          = p;
		minor            = blktap_max_minor;
		blktap_max_minor = n;

		memset(&blktaps[minor], 0, (n - minor) * sizeof(blktaps[0]));
	}

	tap->minor = minor;
	blktaps[minor] = tap;

	__module_get(THIS_MODULE);
out:
	mutex_unlock(&blktap_lock);
	return tap;

fail:
	mutex_unlock(&blktap_lock);
	kfree(tap);
	tap = NULL;
	goto out;
}

static void
blktap_control_put_minor(struct blktap* tap)
{
	blktaps[tap->minor] = NULL;
	kfree(tap);

	module_put(THIS_MODULE);
}

static struct blktap*
blktap_control_create_tap(void)
{
	struct blktap *tap;
	int err;

	tap = blktap_control_get_minor();
	if (!tap)
		return NULL;

	err = blktap_ring_create(tap);
	if (err)
		goto fail_tap;

	err = blktap_sysfs_create(tap);
	if (err)
		goto fail_ring;

	return tap;

fail_ring:
	blktap_ring_destroy(tap);
fail_tap:
	blktap_control_put_minor(tap);

	return NULL;
}

int
blktap_control_destroy_tap(struct blktap *tap)
{
	int err;

	err = blktap_ring_destroy(tap);
	if (err)
		return err;

	blktap_sysfs_destroy(tap);

	blktap_control_put_minor(tap);

	return 0;
}

static int
blktap_control_ioctl(struct inode *inode, struct file *filp,
		     unsigned int cmd, unsigned long arg)
{
	struct blktap *tap;

	switch (cmd) {
	case BLKTAP2_IOCTL_ALLOC_TAP: {
		struct blktap_handle h;
		void __user *ptr = (void __user*)arg;

		tap = blktap_control_create_tap();
		if (!tap)
			return -ENOMEM;

		h.ring   = blktap_ring_major;
		h.device = blktap_device_major;
		h.minor  = tap->minor;

		if (copy_to_user(ptr, &h, sizeof(h))) {
			blktap_control_destroy_tap(tap);
			return -EFAULT;
		}

		return 0;
	}

	case BLKTAP2_IOCTL_FREE_TAP: {
		int minor = arg;

		if (minor > MAX_BLKTAP_DEVICE)
			return -EINVAL;

		tap = blktaps[minor];
		if (!tap)
			return -ENODEV;

		return blktap_control_destroy_tap(tap);
	}
	}

	return -ENOIOCTLCMD;
}

static struct file_operations blktap_control_file_operations = {
	.owner    = THIS_MODULE,
	.ioctl    = blktap_control_ioctl,
};

static struct miscdevice blktap_misc = {
	.minor    = MISC_DYNAMIC_MINOR,
	.name     = "blktap-control",
	.fops     = &blktap_control_file_operations,
};

size_t
blktap_control_debug(struct blktap *tap, char *buf, size_t size)
{
	char *s = buf, *end = buf + size;

	s += snprintf(s, end - s,
		      "tap %u:%u name:'%s' flags:%#08lx\n",
		      MAJOR(tap->ring.devno), MINOR(tap->ring.devno),
		      tap->name, tap->dev_inuse);

	return s - buf;
}

static int __init
blktap_control_init(void)
{
	int err;

	err = misc_register(&blktap_misc);
	if (err) {
		blktap_misc.minor = MISC_DYNAMIC_MINOR;
		BTERR("misc_register failed for control device");
		return err;
	}

	blktap_max_minor = min(64, MAX_BLKTAP_DEVICE);
	blktaps = kzalloc(blktap_max_minor * sizeof(blktaps[0]), GFP_KERNEL);
	if (!blktaps) {
		BTERR("failed to allocate blktap minor map");
		return -ENOMEM;
	}

	return 0;
}

static void
blktap_control_exit(void)
{
	if (blktaps) {
		kfree(blktaps);
		blktaps = NULL;
	}

	if (blktap_misc.minor != MISC_DYNAMIC_MINOR) {
		misc_deregister(&blktap_misc);
		blktap_misc.minor = MISC_DYNAMIC_MINOR;
	}
}

static void
blktap_exit(void)
{
	blktap_control_exit();
	blktap_ring_exit();
	blktap_sysfs_exit();
	blktap_device_exit();
	blktap_request_pool_free();
}

static int __init
blktap_init(void)
{
	int err;

	if (!xen_pv_domain())
		return -ENODEV;

	err = blktap_request_pool_init();
	if (err)
		return err;

	err = blktap_device_init();
	if (err)
		goto fail;

	err = blktap_ring_init();
	if (err)
		goto fail;

	err = blktap_sysfs_init();
	if (err)
		goto fail;

	err = blktap_control_init();
	if (err)
		goto fail;

	return 0;

fail:
	blktap_exit();
	return err;
}

module_init(blktap_init);
module_exit(blktap_exit);
MODULE_LICENSE("Dual BSD/GPL");

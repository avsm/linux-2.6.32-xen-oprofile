#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "blktap.h"

int blktap_debug_level = 1;

static struct class *class;
static DECLARE_WAIT_QUEUE_HEAD(sysfs_wq);

static inline void
blktap_sysfs_get(struct blktap *tap)
{
	atomic_inc(&tap->ring.sysfs_refcnt);
}

static inline void
blktap_sysfs_put(struct blktap *tap)
{
	if (atomic_dec_and_test(&tap->ring.sysfs_refcnt))
		wake_up(&sysfs_wq);
}

static inline void
blktap_sysfs_enter(struct blktap *tap)
{
	blktap_sysfs_get(tap);               /* pin sysfs device */
	mutex_lock(&tap->ring.sysfs_mutex);  /* serialize sysfs operations */
}

static inline void
blktap_sysfs_exit(struct blktap *tap)
{
	mutex_unlock(&tap->ring.sysfs_mutex);
	blktap_sysfs_put(tap);
}

#define CLASS_DEVICE_ATTR(a,b,c,d) DEVICE_ATTR(a,b,c,d)
static ssize_t
blktap_sysfs_set_name(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int err;
	struct blktap *tap = (struct blktap *)dev_get_drvdata(dev);

	blktap_sysfs_enter(tap);

	if (!tap->ring.dev) {
		err = -ENODEV;
		goto out;
	}
	if (size > BLKTAP2_MAX_MESSAGE_LEN) {
		err = -ENAMETOOLONG;
		goto out;
	}

	if (strnlen(buf, BLKTAP2_MAX_MESSAGE_LEN) >= BLKTAP2_MAX_MESSAGE_LEN) {
		err = -EINVAL;
		goto out;
	}

	snprintf(tap->name, sizeof(tap->name) - 1, "%s", buf);
	err = size;

out:
	blktap_sysfs_exit(tap);	
	return err;
}

static ssize_t
blktap_sysfs_get_name(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t size;
	struct blktap *tap = (struct blktap *)dev_get_drvdata(dev);

	blktap_sysfs_enter(tap);

	if (!tap->ring.dev)
		size = -ENODEV;
	else if (tap->name[0])
		size = sprintf(buf, "%s\n", tap->name);
	else
		size = sprintf(buf, "%d\n", tap->minor);

	blktap_sysfs_exit(tap);

	return size;
}
CLASS_DEVICE_ATTR(name, S_IRUSR | S_IWUSR,
		  blktap_sysfs_get_name, blktap_sysfs_set_name);

static void
blktap_sysfs_remove_work(struct work_struct *work)
{
	struct blktap *tap
		= container_of(work, struct blktap, remove_work);
	blktap_control_destroy_tap(tap);
}

static ssize_t
blktap_sysfs_remove_device(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf, size_t size)
{
	struct blktap *tap;
	int err;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return size;

	if (test_and_set_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		goto wait;

	if (tap->ring.vma) {
		blkif_sring_t *sring = tap->ring.ring.sring;
		sring->private.tapif_user.msg = BLKTAP2_RING_MESSAGE_CLOSE;
		blktap_ring_kick_user(tap);
	} else {
		INIT_WORK(&tap->remove_work, blktap_sysfs_remove_work);
		schedule_work(&tap->remove_work);
	}
wait:
	err = wait_event_interruptible(tap->remove_wait,
				       !dev_get_drvdata(dev));
	if (err)
		return err;

	return size;
}
CLASS_DEVICE_ATTR(remove, S_IWUSR, NULL, blktap_sysfs_remove_device);

static ssize_t
blktap_sysfs_debug_device(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *tmp;
	int i, ret;
	struct blktap *tap = (struct blktap *)dev_get_drvdata(dev);

	tmp = buf;
	blktap_sysfs_get(tap);

	if (!tap->ring.dev) {
		ret = sprintf(tmp, "no device\n");
		goto out;
	}

	tmp += sprintf(tmp, "%s (%u:%u), refcnt: %d, dev_inuse: 0x%08lx\n",
		       tap->name, MAJOR(tap->ring.devno),
		       MINOR(tap->ring.devno), atomic_read(&tap->refcnt),
		       tap->dev_inuse);

	if (tap->device.gd) {
		struct gendisk *gd = tap->device.gd;
		struct block_device *bdev = bdget_disk(gd, 0);
		tmp += sprintf(tmp, "capacity: 0x%llx, sector size: %#x, "
			       "device users: %d\n", get_capacity(gd),
			       gd->queue->hardsect_size, bdev->bd_openers);
		bdput(bdev);
	}

	tmp += sprintf(tmp, "pending requests: %d\n", tap->pending_cnt);

	for (i = 0; i < MAX_PENDING_REQS; i++) {
		struct blktap_request *req = tap->pending_requests[i];
		if (!req)
			continue;

		tmp += sprintf(tmp, "req %d: id: %llu, usr_idx: %d, "
			       "status: 0x%02x, pendcnt: %d, "
			       "nr_pages: %u, op: %d, time: %lu:%lu\n",
			       i, (unsigned long long)req->id, req->usr_idx,
			       req->status, atomic_read(&req->pendcnt),
			       req->nr_pages, req->operation, req->time.tv_sec,
			       req->time.tv_usec);
	}

	ret = (tmp - buf) + 1;

out:
	blktap_sysfs_put(tap);
	BTDBG("%s\n", buf);

	return ret;
}
CLASS_DEVICE_ATTR(debug, S_IRUSR, blktap_sysfs_debug_device, NULL);

static ssize_t
blktap_sysfs_show_task(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	ssize_t rv = 0;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (tap->ring.task)
		rv = sprintf(buf, "%d\n", tap->ring.task->pid);

	return rv;
}
DEVICE_ATTR(task, S_IRUSR, blktap_sysfs_show_task, NULL);

int
blktap_sysfs_create(struct blktap *tap)
{
	struct blktap_ring *ring;
	struct device *dev;
	int err = 0;

	if (!class)
		return -ENODEV;

	ring = &tap->ring;
	mutex_init(&ring->sysfs_mutex);
	atomic_set(&ring->sysfs_refcnt, 0);
	init_waitqueue_head(&tap->remove_wait);

	dev = device_create(class, NULL, ring->devno,
			    tap, "blktap%d", tap->minor);
	if (IS_ERR(dev))
		err = PTR_ERR(dev);
	if (!err)
		err = device_create_file(dev, &dev_attr_name);
	if (!err)
		err = device_create_file(dev, &dev_attr_remove);
	if (!err)
		err = device_create_file(dev, &dev_attr_debug);
	if (!err)
		err = device_create_file(dev, &dev_attr_task);
	if (!err)
		ring->dev = dev;
	else
		device_unregister(dev);

	return err;
}

void
blktap_sysfs_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct device *dev;

	dev = ring->dev;

	if (!dev)
		return;

	dev_set_drvdata(dev, NULL);
	wake_up(&tap->remove_wait);

	device_unregister(dev);
	ring->dev = NULL;
}

static ssize_t
blktap_sysfs_show_verbosity(struct class *class, char *buf)
{
	return sprintf(buf, "%d\n", blktap_debug_level);
}

static ssize_t
blktap_sysfs_set_verbosity(struct class *class, const char *buf, size_t size)
{
	int level;

	if (sscanf(buf, "%d", &level) == 1) {
		blktap_debug_level = level;
		return size;
	}

	return -EINVAL;
}
CLASS_ATTR(verbosity, S_IRUSR | S_IWUSR,
	   blktap_sysfs_show_verbosity, blktap_sysfs_set_verbosity);

static ssize_t
blktap_sysfs_show_devices(struct class *class, char *buf)
{
	int i, ret;
	struct blktap *tap;

	mutex_lock(&blktap_lock);

	ret = 0;
	for (i = 0; i < blktap_max_minor; i++) {
		tap = blktaps[i];
		if (!tap)
			continue;

		if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
			continue;

		ret += sprintf(buf + ret, "%d %s\n", tap->minor, tap->name);
	}

	mutex_unlock(&blktap_lock);

	return ret;
}
CLASS_ATTR(devices, S_IRUSR, blktap_sysfs_show_devices, NULL);

void
blktap_sysfs_free(void)
{
	if (!class)
		return;

	class_remove_file(class, &class_attr_verbosity);
	class_remove_file(class, &class_attr_devices);

	class_destroy(class);
}

int __init
blktap_sysfs_init(void)
{
	struct class *cls;
	int err;

	if (class)
		return -EEXIST;

	cls = class_create(THIS_MODULE, "blktap2");
	if (IS_ERR(cls))
		return PTR_ERR(cls);

	err = class_create_file(cls, &class_attr_verbosity);
	if (err)
		goto out_unregister;
	err = class_create_file(cls, &class_attr_devices);
	if (err)
		goto out_unregister;

	class = cls;
	return 0;
out_unregister:
	class_destroy(cls);
	return err;
}

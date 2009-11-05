obj-y += pcifront.o

pcifront-y := xenbus.o

ifeq ($(CONFIG_XEN_PCIDEV_FE_DEBUG),y)
EXTRA_CFLAGS += -DDEBUG
endif

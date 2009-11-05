obj-y += pcifront.o

pcifront-y := pci_op.o xenbus.o

ifeq ($(CONFIG_XEN_PCIDEV_FE_DEBUG),y)
EXTRA_CFLAGS += -DDEBUG
endif

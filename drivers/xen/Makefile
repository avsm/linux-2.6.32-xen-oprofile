obj-y	+= grant-table.o features.o events.o manage.o biomerge.o
obj-y	+= xenbus/

nostackp := $(call cc-option, -fno-stack-protector)
CFLAGS_features.o			:= $(nostackp)

obj-$(CONFIG_PCI)			+= pci.o
obj-$(CONFIG_HOTPLUG_CPU)	+= cpu_hotplug.o
obj-$(CONFIG_XEN_XENCOMM)	+= xencomm.o
obj-$(CONFIG_XEN_BALLOON)	+= balloon.o
obj-$(CONFIG_XEN_DEV_EVTCHN)	+= xen-evtchn.o
obj-$(CONFIG_XENFS)		+= xenfs/
obj-$(CONFIG_XEN_SYS_HYPERVISOR)	+= sys-hypervisor.o

xen-evtchn-y			:= evtchn.o

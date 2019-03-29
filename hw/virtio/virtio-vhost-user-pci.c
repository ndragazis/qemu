/*
 * Virtio Vhost-user Device
 *
 * Copyright (C) 2017-2018 Red Hat, Inc.
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-vhost-user.h"
#include "qapi/error.h"

typedef struct VirtIOVhostUserPCI VirtIOVhostUserPCI;

/*
 * virtio-vhost-user-pci: This extends VirtioPCIProxy.
 */

#define TYPE_VIRTIO_VHOST_USER_PCI "virtio-vhost-user-pci-base"
#define VIRTIO_VHOST_USER_PCI(obj) \
        OBJECT_CHECK(VirtIOVhostUserPCI, (obj), TYPE_VIRTIO_VHOST_USER_PCI)
/* TODO The definition has been temporarily moved into hw/virtio/virtio-pci.h
 * because we want it to be accessible from hw/virtio/virtio-vhost-user.c. This
 * is going to be fixed in later commits.
 */
/*
struct VirtIOVhostUserPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOVhostUser vdev;
};
*/
static Property virtio_vhost_user_pci_properties[] = {
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors, 3),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_vhost_user_pci_realize(VirtIOPCIProxy *vpci_dev,
                                          Error **errp)
{
    VirtIOVhostUserPCI *vvup = VIRTIO_VHOST_USER_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&vvup->vdev);

    qdev_set_parent_bus(vdev, BUS(&vpci_dev->bus));
    object_property_set_bool(OBJECT(vdev), true, "realized", errp);
}

static void virtio_vhost_user_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    dc->props = virtio_vhost_user_pci_properties;
    k->realize = virtio_vhost_user_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = PCI_DEVICE_ID_VIRTIO_VHOST_USER;
    pcidev_k->revision = VIRTIO_PCI_ABI_VERSION;
    pcidev_k->class_id = PCI_CLASS_OTHERS;
}

static void virtio_vhost_user_pci_initfn(Object *obj)
{
    VirtIOVhostUserPCI *dev = VIRTIO_VHOST_USER_PCI(obj);

     virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_VHOST_USER);
}

static const VirtioPCIDeviceTypeInfo virtio_vhost_user_pci_info = {
    .base_name     = TYPE_VIRTIO_VHOST_USER_PCI,
    .generic_name  = "virtio-vhost-user-pci",
    .instance_size = sizeof(VirtIOVhostUserPCI),
    .instance_init = virtio_vhost_user_pci_initfn,
    .class_init    = virtio_vhost_user_pci_class_init,
};

static void virtio_vhost_user_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_vhost_user_pci_info);
}

type_init(virtio_vhost_user_pci_register_types);

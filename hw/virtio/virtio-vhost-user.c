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
#include "standard-headers/linux/virtio_ids.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/sockets.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-vhost-user.h"
#include "virtio-pci.h" /* TODO remove, see virtio_vhost_user_init_bar() */
#include "trace.h"
#include "hw/pci/msix.h"

/* vmstate migration version number */
#define VIRTIO_VHOST_USER_VM_VERSION    0

/* Descriptor ring size.  Only one vhost-user protocol message is processed at
 * a time but later messages can be queued.
 */
#define VIRTIO_VHOST_USER_VIRTQUEUE_SIZE 128

/* Protocol features that have been implemented */
#define SUPPORTED_VHOST_USER_FEATURES \
    (VHOST_USER_PROTOCOL_F_MQ | VHOST_USER_PROTOCOL_F_REPLY_ACK)

/* Connection state machine
 *
 * The vhost-user master might not always be connected and the driver might not
 * always be ready either.  The device interface has a way to manage connection
 * establishment:
 *
 * The driver indicates readiness with the VIRTIO_VHOST_USER_STATUS_SLAVE_UP
 * status bit.  The device then begins establishing a connection with the
 * vhost-user master.  The VIRTIO_VHOST_USER_STATUS_MASTER_UP status bit is set
 * when connected.
 *
 * The driver may decide it wants to disconnect at any time.  Vhost-user
 * protocol violations and other errors might cause the device to give up on
 * the connection too.
 *
 * This state machine captures all transitions in one place.  This way the
 * connection management code isn't sprinkled around many locations.
 */
typedef enum {
    CONN_STATE_UNDEFINED,
    CONN_STATE_INITIAL,     /* !SLAVE_UP + !CHR_OPENED */
    CONN_STATE_SLAVE_UP,    /* SLAVE_UP + !CHR_OPENED */
    CONN_STATE_CHR_OPENED,  /* !SLAVE_UP + CHR_OPENED */
    CONN_STATE_CONNECTED,   /* SLAVE_UP + CHR_OPENED */
    CONN_STATE_MAX
} ConnectionState;

typedef enum {
    /* Driver sets VIRTIO_VHOST_USER_STATUS_SLAVE_UP */
    CONN_EVENT_SLAVE_UP,

    /* Driver clears VIRTIO_VHOST_USER_STATUS_SLAVE_UP */
    CONN_EVENT_SLAVE_DOWN,

    /* Socket connected and also each time we update chardev handlers */
    CONN_EVENT_CHR_OPENED,

    /* Socket disconnected */
    CONN_EVENT_CHR_CLOSED,

    /* Socket chardev was replaced */
    CONN_EVENT_CHR_CHANGE,

    /* Socket I/O error */
    CONN_EVENT_SOCKET_ERROR,

    /* Virtio device reset */
    CONN_EVENT_DEVICE_RESET,

    /* Vhost-user protocol violation by master */
    CONN_EVENT_MASTER_EINVAL,

    /* Vhost-user protocol violation by slave */
    CONN_EVENT_SLAVE_EINVAL,

    CONN_EVENT_MAX
} ConnectionEvent;

static void conn_state_transition(VirtIOVhostUser *s, ConnectionEvent evt);
void virtio_vhost_user_guest_notifier_read(EventNotifier *n);

/* TODO Add those function prototypes temporarily. Remove then later. */
void virtio_set_isr(VirtIODevice *vdev, int value);
void virtio_notify_vector(VirtIODevice *vdev, uint16_t vector);
int virtio_pci_queue_mem_mult(struct VirtIOPCIProxy *proxy);
void virtio_pci_modern_region_map(VirtIOPCIProxy *proxy,
                                  VirtIOPCIRegion *region,
                                  struct virtio_pci_cap *cap,
                                  MemoryRegion *mr,
                                  uint8_t bar);

static void virtio_vhost_user_reset_async_state(VirtIOVhostUser *s)
{
    s->read_bytes_needed = 0;
    s->read_ptr = NULL;
    s->read_done = NULL;
    s->read_waiting_on_rxq = false;
    s->read_msg_size = 0;

    s->write_bytes_avail = 0;
    s->write_ptr = NULL;
    s->write_done = NULL;
    if (s->write_watch_tag) {
        g_source_remove(s->write_watch_tag);
    }
    s->write_watch_tag = 0;
}

static void virtio_vhost_user_chr_event(void *opaque, int event)
{
    VirtIOVhostUser *s = opaque;

    trace_virtio_vhost_user_chr_event(s, event);

    switch (event) {
    case CHR_EVENT_OPENED:
        conn_state_transition(s, CONN_EVENT_CHR_OPENED);
        break;
    case CHR_EVENT_CLOSED:
        conn_state_transition(s, CONN_EVENT_CHR_CLOSED);
        break;
    }
}

static int virtio_vhost_user_chr_change(void *opaque)
{
    VirtIOVhostUser *s = opaque;

    trace_virtio_vhost_user_chr_change(s);

    if (s->config.status & (1 << VIRTIO_VHOST_USER_STATUS_MASTER_UP)) {
        conn_state_transition(s, CONN_EVENT_CHR_CHANGE);
    }
    return 0;
}

static int virtio_vhost_user_chr_can_read(void *opaque)
{
    VirtIOVhostUser *s = opaque;

    return s->read_bytes_needed;
}

static void virtio_vhost_user_chr_read(void *opaque,
                                       const uint8_t *buf, int size)
{
    VirtIOVhostUser *s = opaque;

    assert(size <= s->read_bytes_needed);

    memcpy(s->read_ptr, buf, size);
    s->read_ptr += size;
    s->read_bytes_needed -= size;

    if (s->read_bytes_needed == 0) {
        qemu_chr_fe_set_handlers(&s->chr, NULL, NULL,
                virtio_vhost_user_chr_event,
                virtio_vhost_user_chr_change,
                s, NULL, false);

        s->read_done(s);
    }
}

/* Start reading from vhost-user socket */
static void virtio_vhost_user_aio_read(VirtIOVhostUser *s,
                                       void *buf, size_t len,
                                       void (*done)(VirtIOVhostUser *s))
{
    assert(s->read_bytes_needed == 0);

    s->read_ptr = buf;
    s->read_bytes_needed = len;
    s->read_done = done;

    qemu_chr_fe_set_handlers(&s->chr,
            virtio_vhost_user_chr_can_read,
            virtio_vhost_user_chr_read,
            virtio_vhost_user_chr_event,
            virtio_vhost_user_chr_change,
            s, NULL, false);
}

/* Called once with chan=NULL, cond=0 to begin and then called by event loop */
static gboolean virtio_vhost_user_chr_write(GIOChannel *chan, GIOCondition cond,
                                            void *opaque)
{
    VirtIOVhostUser *s = opaque;
    int nwritten;
    guint tag = s->write_watch_tag;

    nwritten = qemu_chr_fe_write(&s->chr, s->write_ptr, s->write_bytes_avail);
    if (nwritten < 0) {
        if (errno == EAGAIN) {
            nwritten = 0;
        } else {
            conn_state_transition(s, CONN_EVENT_SOCKET_ERROR);
            return G_SOURCE_REMOVE;
        }
    }

    s->write_bytes_avail -= nwritten;
    if (s->write_bytes_avail == 0) {
        s->write_done(s);
        return G_SOURCE_REMOVE;
    }

    if (tag == 0) {
        tag = qemu_chr_fe_add_watch(&s->chr, G_IO_OUT | G_IO_HUP,
                                    virtio_vhost_user_chr_write, s);
        if (!tag) {
            conn_state_transition(s, CONN_EVENT_SOCKET_ERROR);
            return G_SOURCE_REMOVE;
        }

        s->write_watch_tag = tag;
    }

    return G_SOURCE_CONTINUE;
}

/* Start writing to vhost-user socket */
static void virtio_vhost_user_aio_write(VirtIOVhostUser *s,
                                        void *buf, size_t len,
                                        void (*done)(VirtIOVhostUser *s))
{
    assert(s->write_bytes_avail == 0);

    s->write_ptr = buf;
    s->write_bytes_avail = len;
    s->write_done = done;

    virtio_vhost_user_chr_write(NULL, 0, s);
}

static void virtio_vhost_user_cleanup_kickfds(VirtIOVhostUser *s)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(s->kickfds); i++) {
       if (event_notifier_get_fd(&s->kickfds[i].guest_notifier) >= 0) {
           /* Remove the kickfd from the main event loop */
            event_notifier_set_handler(&s->kickfds[i].guest_notifier, NULL);
           event_notifier_cleanup(&s->kickfds[i].guest_notifier);
           s->kickfds[i].msi_vector = VIRTIO_NO_VECTOR;
       }
    }
}

static void virtio_vhost_user_cleanup_callfds(VirtIOVhostUser *s)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(s->callfds); i++) {
        if (s->callfds[i] >= 0) {
            close(s->callfds[i]);
            s->callfds[i] = -1;
        }
    }
}

static void virtio_vhost_user_cleanup_mem_table(VirtIOVhostUser *s)
{
    int i;

    for (i = 0; i < VHOST_MEMORY_MAX_NREGIONS; i++) {
        VirtIOVhostUserMemTableRegion *region = &s->mem_table[i];

        if (!region->mmap_addr) {
            continue;
        }

        munmap(region->mmap_addr, region->total_size);
        region->mmap_addr = NULL;

        memory_region_del_subregion(&s->additional_resources_bar,
                                    &region->mr);
        object_unparent(OBJECT(&region->mr));
    }
}

static void conn_action_set_slave_up(VirtIOVhostUser *s)
{
    /* Guest-initiated, no need for virtio_notify_config() */
    s->config.status = (1 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);
}

static void conn_action_set_slave_down(VirtIOVhostUser *s)
{
    /* Guest-initiated, no need for virtio_notify_config() */
    s->config.status = 0;
}

static void virtio_vhost_user_hdr_done(VirtIOVhostUser *s);

static void conn_action_connect(VirtIOVhostUser *s)
{
    s->config.status = (1 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP) |
                       (1 << VIRTIO_VHOST_USER_STATUS_MASTER_UP);
    virtio_notify_config(VIRTIO_DEVICE(s));

    /* Begin servicing vhost-user messages */
    virtio_vhost_user_aio_read(s, &s->read_msg, VHOST_USER_HDR_SIZE,
                               virtio_vhost_user_hdr_done);
}

static void conn_action_disconnect_no_notify(VirtIOVhostUser *s)
{
    qemu_chr_fe_set_handlers(&s->chr,
            NULL,
            NULL,
            virtio_vhost_user_chr_event,
            virtio_vhost_user_chr_change,
            s, NULL, false);
    qemu_chr_fe_set_open(&s->chr, 0);

    virtio_vhost_user_reset_async_state(s);

    /* TODO drain txq? */

    /* It is only safe to clean up resources where future accesses have no
     * guest-visible effects.  Vcpus may still access resources if they haven't
     * noticed the disconnect event yet.  Callfds are safe since writes to
     * invalid indices are ignored.  Memory table regions cannot be unmapped
     * since vring polling may still be running.
     */
    virtio_vhost_user_cleanup_kickfds(s);
    virtio_vhost_user_cleanup_callfds(s);

    s->config.status = 0;
}

static void conn_action_disconnect(VirtIOVhostUser *s)
{
    conn_action_disconnect_no_notify(s);
    virtio_notify_config(VIRTIO_DEVICE(s));
}

static const struct {
    void (*action)(VirtIOVhostUser *s);
    ConnectionState new_state;
} conn_state_machine[CONN_STATE_MAX][CONN_EVENT_MAX] = {
    [CONN_STATE_INITIAL] = {
        [CONN_EVENT_SLAVE_UP] = {conn_action_set_slave_up,
                                 CONN_STATE_SLAVE_UP},
        [CONN_EVENT_CHR_OPENED] = {NULL, CONN_STATE_CHR_OPENED},
        [CONN_EVENT_CHR_CLOSED] = {NULL, CONN_STATE_INITIAL},
        [CONN_EVENT_CHR_CHANGE] = {NULL, CONN_STATE_INITIAL},
        [CONN_EVENT_DEVICE_RESET] = {NULL, CONN_STATE_INITIAL},
    },
    [CONN_STATE_SLAVE_UP] = {
        [CONN_EVENT_SLAVE_DOWN] = {conn_action_set_slave_down,
                                   CONN_STATE_INITIAL},
        [CONN_EVENT_CHR_OPENED] = {conn_action_connect, CONN_STATE_CONNECTED},
        [CONN_EVENT_CHR_CLOSED] = {NULL, CONN_STATE_SLAVE_UP},
        [CONN_EVENT_CHR_CHANGE] = {NULL, CONN_STATE_SLAVE_UP},
        [CONN_EVENT_DEVICE_RESET] = {conn_action_set_slave_down,
                                     CONN_STATE_INITIAL},
    },
    [CONN_STATE_CHR_OPENED] = {
        [CONN_EVENT_SLAVE_UP] = {conn_action_connect, CONN_STATE_CONNECTED},
        [CONN_EVENT_CHR_OPENED] = {NULL, CONN_STATE_CHR_OPENED},
        [CONN_EVENT_CHR_CLOSED] = {NULL, CONN_STATE_INITIAL},
        [CONN_EVENT_CHR_CHANGE] = {NULL, CONN_STATE_CHR_OPENED},
        [CONN_EVENT_DEVICE_RESET] = {NULL, CONN_STATE_INITIAL},
    },
    [CONN_STATE_CONNECTED] = {
        [CONN_EVENT_SLAVE_DOWN] = {conn_action_disconnect_no_notify,
                                   CONN_STATE_INITIAL},
        [CONN_EVENT_CHR_OPENED] = {NULL, CONN_STATE_CONNECTED},
        [CONN_EVENT_CHR_CLOSED] = {conn_action_disconnect,
                                   CONN_STATE_INITIAL},
        [CONN_EVENT_CHR_CHANGE] = {conn_action_disconnect, CONN_STATE_INITIAL},
        [CONN_EVENT_SOCKET_ERROR] = {conn_action_disconnect,
                                     CONN_STATE_INITIAL},
        [CONN_EVENT_DEVICE_RESET] = {conn_action_disconnect_no_notify,
                                     CONN_STATE_INITIAL},
        [CONN_EVENT_MASTER_EINVAL] = {conn_action_disconnect,
                                      CONN_STATE_INITIAL},
        [CONN_EVENT_SLAVE_EINVAL] = {conn_action_disconnect,
                                     CONN_STATE_INITIAL},
    },
};

static void conn_state_transition(VirtIOVhostUser *s, ConnectionEvent evt)
{
    ConnectionState old_state = s->conn_state;
    ConnectionState new_state = conn_state_machine[old_state][evt].new_state;

    trace_virtio_vhost_user_conn_state_transition(s, old_state, evt,
                                                  new_state);
    assert(new_state != CONN_STATE_UNDEFINED);

    s->conn_state = new_state;

    if (conn_state_machine[old_state][evt].action) {
        conn_state_machine[old_state][evt].action(s);
    }
}

/* Master-to-slave message processing
 *
 * Messages are read from the vhost-user socket into s->read_msg.  They are
 * then parsed and may be modified.  Finally they are put onto the rxq for the
 * driver to read.
 *
 * Functions with "m2s" in their name handle the master-to-slave code path.
 */

/* Put s->read_msg onto the rxq */
static void virtio_vhost_user_deliver_m2s(VirtIOVhostUser *s)
{
    VirtQueueElement *elem;
    size_t copied;

    elem = virtqueue_pop(s->rxq, sizeof(*elem));
    if (!elem) {
        /* Leave message in s->read_msg and wait for rxq */
        trace_virtio_vhost_user_rxq_empty(s);
        s->read_waiting_on_rxq = true;
        return;
    }

    s->read_waiting_on_rxq = false;

    copied = iov_from_buf(elem->in_sg, elem->in_num, 0, &s->read_msg,
                          s->read_msg_size);
    if (copied != s->read_msg_size) {
        g_free(elem);
        virtio_error(VIRTIO_DEVICE(s),
                     "rxq buffer too small, got %zu, needed %zu",
                     copied, s->read_msg_size);
        return;
    }

    virtqueue_push(s->rxq, elem, copied);
    g_free(elem);

    virtio_notify(VIRTIO_DEVICE(s), s->rxq);

    /* Next message, please */
    virtio_vhost_user_aio_read(s, &s->read_msg, VHOST_USER_HDR_SIZE,
                               virtio_vhost_user_hdr_done);
}

static void m2s_set_vring_kick(VirtIOVhostUser *s)
{
    uint8_t vq_idx;
    int fd;

    vq_idx = s->read_msg.payload.u64 & VHOST_USER_VRING_IDX_MASK;

    if (s->read_msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK) {
        fd = -1;
    } else {
        fd = qemu_chr_fe_get_msgfd(&s->chr);
    }

    if (event_notifier_get_fd(&s->kickfds[vq_idx].guest_notifier) >= 0) {
       /* Remove the kickfd from the main event loop */
       event_notifier_set_handler(&s->kickfds[vq_idx].guest_notifier, NULL);
       event_notifier_cleanup(&s->kickfds[vq_idx].guest_notifier);
    }

    /* Initialize the EventNotifier with the received kickfd */
    event_notifier_init_fd(&s->kickfds[vq_idx].guest_notifier, fd);

    /* Insert the kickfd in the main event loop */
    event_notifier_set_handler(&s->kickfds[vq_idx].guest_notifier, virtio_vhost_user_guest_notifier_read);
}

static void m2s_set_vring_call(VirtIOVhostUser *s)
{
    uint8_t vq_idx;
    int fd;

    vq_idx = s->read_msg.payload.u64 & VHOST_USER_VRING_IDX_MASK;

    /* We should always have a large enough array */
    QEMU_BUILD_BUG_ON(0xff >= ARRAY_SIZE(s->callfds));

    if (s->read_msg.payload.u64 & VHOST_USER_VRING_NOFD_MASK) {
        fd = -1;
    } else {
        fd = qemu_chr_fe_get_msgfd(&s->chr);

        /* Must not block when reach max eventfd counter value */
        qemu_set_nonblock(fd);
    }

    if (s->callfds[vq_idx] >= 0) {
        close(s->callfds[vq_idx]);
    }

    s->callfds[vq_idx] = fd;
}

static void m2s_set_mem_table(VirtIOVhostUser *s)
{
    VhostUserMemory *memory = &s->read_msg.payload.memory;
    hwaddr subregion_offset;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    int num_fds;
    uint32_t i;

    if (memory->nregions > VHOST_MEMORY_MAX_NREGIONS) {
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    num_fds = qemu_chr_fe_get_msgfds(&s->chr, fds, ARRAY_SIZE(fds));
    if (num_fds != memory->nregions) {
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    virtio_vhost_user_cleanup_mem_table(s);

    /* Start after the notification structure */
    VirtIOVhostUserPCI *vvup = container_of(s, struct VirtIOVhostUserPCI, vdev);
    subregion_offset = vvup->shared_memory.offset;

    for (i = 0; i < memory->nregions; i++) {
        VhostUserMemoryRegion *input = &memory->regions[i];
        VirtIOVhostUserMemTableRegion *region = &s->mem_table[i];
        void *mmap_addr;

        region->total_size = input->mmap_offset + input->memory_size;
        if (region->total_size < input->mmap_offset ||
            region->total_size < input->memory_size) {
            goto err;
        }

        mmap_addr = mmap(0, region->total_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fds[i], 0);
        close(fds[i]);
        fds[i] = -1;
        if (mmap_addr == MAP_FAILED) {
            goto err;
        }
        region->mmap_addr = mmap_addr;

        trace_virtio_vhost_user_memory_region(s,
                memory->regions[i].guest_phys_addr,
                memory->regions[i].memory_size,
                memory->regions[i].userspace_addr,
                memory->regions[i].mmap_offset,
                region->mmap_addr);

        memory_region_init_ram_ptr(&region->mr, OBJECT(s),
                "virtio-vhost-user-mem-table-region",
                region->total_size, region->mmap_addr);
        memory_region_add_subregion(&s->additional_resources_bar,
                                    subregion_offset, &region->mr);

        subregion_offset += region->total_size;
    }

    return;

err:
    for (i = 0; i < memory->nregions; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
}

static void m2s_set_protocol_features(VirtIOVhostUser *s)
{
    /* Only allow features we support too */
    s->read_msg.payload.u64 &= SUPPORTED_VHOST_USER_FEATURES;
}

/* Parse s->read_msg from master */
static void virtio_vhost_user_parse_m2s(VirtIOVhostUser *s)
{
    uint32_t version = s->read_msg.hdr.flags & VHOST_USER_VERSION_MASK;

    if (version != VHOST_USER_VERSION) {
        trace_virtio_vhost_user_m2s_bad_version(s, version);
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    if (s->read_msg.hdr.flags & VHOST_USER_REPLY_MASK) {
        trace_virtio_vhost_user_m2s_unexpected_reply(s);
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    if (s->read_msg.hdr.request >= VHOST_USER_MAX) {
        trace_virtio_vhost_user_m2s_bad_request(s, s->read_msg.hdr.request);
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    trace_virtio_vhost_user_m2s_request(s, s->read_msg.hdr.request);

    /* Most messages are passed through but a few need to be handled */
    switch (s->read_msg.hdr.request) {
    case VHOST_USER_GET_FEATURES:
        break;
    case VHOST_USER_SET_FEATURES:
        break;
    case VHOST_USER_SET_OWNER:
        break;
    case VHOST_USER_RESET_OWNER:
        break;
    case VHOST_USER_SET_MEM_TABLE:
        m2s_set_mem_table(s);
        break;
    case VHOST_USER_SET_VRING_NUM:
        break;
    case VHOST_USER_SET_VRING_ADDR:
        break;
    case VHOST_USER_SET_VRING_BASE:
        break;
    case VHOST_USER_GET_VRING_BASE:
        break;
    case VHOST_USER_SET_VRING_KICK:
        m2s_set_vring_kick(s);
        break;
    case VHOST_USER_SET_VRING_CALL:
        m2s_set_vring_call(s);
        break;
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        break;
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        m2s_set_protocol_features(s);
        break;
    case VHOST_USER_GET_QUEUE_NUM:
        break;
    case VHOST_USER_SET_VRING_ENABLE:
        break;
    default:
        trace_virtio_vhost_user_m2s_unknown_request(s, s->read_msg.hdr.request);
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    /* Bail if a handler function reset the connection */
    if (s->conn_state != CONN_STATE_CONNECTED) {
        return;
    }

    /* Stash size before we endian-convert s->read_msg */
    s->read_msg_size = VHOST_USER_HDR_SIZE + s->read_msg.hdr.size;

    /* TODO convert read_msg to little-endian for cross-endian support */

    virtio_vhost_user_deliver_m2s(s);
}

static void virtio_vhost_user_hdr_done(VirtIOVhostUser *s)
{
    if (s->read_msg.hdr.size > VHOST_USER_PAYLOAD_SIZE) {
        trace_virtio_vhost_user_m2s_bad_payload_size(s, s->read_msg.hdr.size);
        conn_state_transition(s, CONN_EVENT_MASTER_EINVAL);
        return;
    }

    /* Clear out unused payload bytes */
    memset(&s->read_msg.payload, 0, VHOST_USER_PAYLOAD_SIZE);

    if (s->read_msg.hdr.size > 0) {
        virtio_vhost_user_aio_read(s, &s->read_msg.payload, s->read_msg.hdr.size,
                                   virtio_vhost_user_parse_m2s);
    } else {
        virtio_vhost_user_parse_m2s(s);
    }
}

static void virtio_vhost_user_rxq(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);

    if (s->read_waiting_on_rxq) {
        virtio_vhost_user_deliver_m2s(s);
    }
}

/* Slave-to-master message processing
 *
 * Messages are read from the txq into s->write_msg.  They are then parsed and
 * may be modified.  Finally they are written to the vhost-user socket.
 *
 * Functions with "s2m" in their name handle the slave-to-master code path.
 */

static void s2m_get_protocol_features(VirtIOVhostUser *s)
{
    /* Only allow features we support too */
    s->write_msg.payload.u64 &= SUPPORTED_VHOST_USER_FEATURES;
}

static void virtio_vhost_user_tx_done(VirtIOVhostUser *s);

/* Parse s->write_msg from slave */
static void virtio_vhost_user_parse_s2m(VirtIOVhostUser *s)
{
    uint32_t version = s->write_msg.hdr.flags & VHOST_USER_VERSION_MASK;

    if (version != VHOST_USER_VERSION) {
        trace_virtio_vhost_user_s2m_bad_version(s, version);
        conn_state_transition(s, CONN_EVENT_SLAVE_EINVAL);
        return;
    }

    if (!(s->write_msg.hdr.flags & VHOST_USER_REPLY_MASK)) {
        trace_virtio_vhost_user_s2m_expected_reply(s);
        conn_state_transition(s, CONN_EVENT_SLAVE_EINVAL);
        return;
    }

    if (s->write_msg.hdr.request >= VHOST_USER_MAX) {
        trace_virtio_vhost_user_s2m_bad_request(s, s->write_msg.hdr.request);
        conn_state_transition(s, CONN_EVENT_SLAVE_EINVAL);
        return;
    }

    trace_virtio_vhost_user_s2m_request(s, s->write_msg.hdr.request);

    /* Very few messages need to be touched */
    switch (s->write_msg.hdr.request) {
    case VHOST_USER_GET_FEATURES:
        break;
    case VHOST_USER_SET_FEATURES:
        break;
    case VHOST_USER_SET_OWNER:
        break;
    case VHOST_USER_RESET_OWNER:
        break;
    case VHOST_USER_SET_MEM_TABLE:
        break;
    case VHOST_USER_SET_VRING_NUM:
        break;
    case VHOST_USER_SET_VRING_ADDR:
        break;
    case VHOST_USER_SET_VRING_BASE:
        break;
    case VHOST_USER_GET_VRING_BASE:
        break;
    case VHOST_USER_SET_VRING_KICK:
        break;
    case VHOST_USER_SET_VRING_CALL:
        break;
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        s2m_get_protocol_features(s);
        break;
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        break;
    case VHOST_USER_GET_QUEUE_NUM:
        break;
    case VHOST_USER_SET_VRING_ENABLE:
        break;
    default:
        trace_virtio_vhost_user_s2m_unknown_request(s, s->write_msg.hdr.request);
        conn_state_transition(s, CONN_EVENT_SLAVE_EINVAL);
        return;
    }

    /* Bail if a handler function reset the connection */
    if (s->conn_state != CONN_STATE_CONNECTED) {
        return;
    }

    virtio_vhost_user_aio_write(s, &s->write_msg,
                                VHOST_USER_HDR_SIZE + s->write_msg.hdr.size,
                                virtio_vhost_user_tx_done);
}

static void virtio_vhost_user_txq(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);
    VirtQueueElement *elem;
    size_t msgsize;
    size_t copied;

    /* If the last message is still being transferred we'll come back later */
    if (s->write_bytes_avail != 0) {
        return;
    }

    elem = virtqueue_pop(s->txq, sizeof(*elem));
    if (!elem) {
        return; /* no elements left on virtqueue */
    }

    msgsize = iov_size(elem->out_sg, elem->out_num);
    if (msgsize < VHOST_USER_HDR_SIZE || msgsize > sizeof(s->write_msg)) {
        g_free(elem);
        virtio_error(VIRTIO_DEVICE(s),
                     "invalid txq buffer size, got %zu", msgsize);
        return;
    }

    /* Clear out unused payload bytes */
    memset(&s->write_msg.payload, 0, VHOST_USER_PAYLOAD_SIZE);

    copied = iov_to_buf(elem->out_sg, elem->out_num, 0,
                        &s->write_msg, msgsize);
    if (copied != VHOST_USER_HDR_SIZE + s->write_msg.hdr.size ||
        copied != msgsize) {
        g_free(elem);
        virtio_error(VIRTIO_DEVICE(s),
                     "invalid txq buffer size, got %zu", msgsize);
        return;
    }

    virtqueue_push(s->txq, elem, copied);
    g_free(elem);

    virtio_notify(VIRTIO_DEVICE(s), s->txq);

    /* TODO convert from little-endian */

    virtio_vhost_user_parse_s2m(s);
}

static void virtio_vhost_user_tx_done(VirtIOVhostUser *s)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    VirtQueue *vq = s->txq;

    trace_virtio_vhost_user_tx_done(s);

    /* Try to process more messages from the driver */
    virtio_vhost_user_txq(vdev, vq);
}

static uint64_t
virtio_vhost_user_get_features(VirtIODevice *vdev,
                               uint64_t requested_features,
                               Error **errp)
{
    return requested_features;
}

static void virtio_vhost_user_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOVhostUserConfig *vvuconfig = (VirtIOVhostUserConfig *)config;
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);

    virtio_stl_p(vdev, &vvuconfig->status, s->config.status);
    virtio_stl_p(vdev, &vvuconfig->max_vhost_queues,
                 s->config.max_vhost_queues);
    memcpy(vvuconfig->uuid, s->config.uuid, sizeof(vvuconfig->uuid));
}

static void virtio_vhost_user_set_config(VirtIODevice *vdev,
                                         const uint8_t *config)
{
    VirtIOVhostUserConfig *vvuconfig = (VirtIOVhostUserConfig *)config;
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);
    uint32_t status;
    bool old_slave_up;
    bool new_slave_up;

    status = virtio_ldl_p(vdev, &vvuconfig->status);
    trace_virtio_vhost_user_set_config(s, s->config.status, status);
    if (status & ~((1 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP) |
                   (1 << VIRTIO_VHOST_USER_STATUS_MASTER_UP))) {
        virtio_error(vdev, "undefined virtio-vhost-user status bit set "
                           "(%#x)", status);
        return;
    }

    old_slave_up = s->config.status & (1 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);
    new_slave_up = status & (1 << VIRTIO_VHOST_USER_STATUS_SLAVE_UP);

    if (!old_slave_up && new_slave_up) {
        conn_state_transition(s, CONN_EVENT_SLAVE_UP);
    } else if (old_slave_up && !new_slave_up) {
        conn_state_transition(s, CONN_EVENT_SLAVE_DOWN);
    }
}

static void virtio_vhost_user_reset(VirtIODevice *vdev)
{
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);

    conn_state_transition(s, CONN_EVENT_DEVICE_RESET);

    virtio_vhost_user_reset_async_state(s);
}

static uint64_t virtio_vhost_user_doorbells_read(void *opaque, hwaddr addr,
                                                 unsigned size)
{
    return 0;
}

static void virtio_vhost_user_doorbells_write(void *opaque, hwaddr addr,
                                              uint64_t val, unsigned size)
{
    VirtIOVhostUser *s = opaque;
    VirtIOVhostUserPCI *vvup = container_of(s, struct VirtIOVhostUserPCI, vdev);
    VirtIOPCIProxy *proxy = &vvup->parent_obj;
    unsigned idx = addr / virtio_pci_queue_mem_mult(proxy);


    if (idx < VIRTIO_QUEUE_MAX) {
        /* TODO use memory_region_add_eventfd() to avoid entering QEMU */

        if (s->callfds[idx] >= 0) {
            uint64_t val = 1;
            ssize_t nwritten;

            nwritten = write(s->callfds[idx], &val, sizeof(val));
            trace_virtio_vhost_user_doorbell_write(s, idx, nwritten);
        }
    } else if (idx == VIRTIO_QUEUE_MAX) {
        /* TODO log doorbell */
    }
}

static uint64_t virtio_vhost_user_notification_read(void *opaque, hwaddr addr,
                                               unsigned size)
{
    VirtIOVhostUser *s = opaque;
    uint64_t val = 0;

    switch (addr) {
    case NOTIFICATION_SELECT:
           val = s->nselect;
           break;
    case NOTIFICATION_MSIX_VECTOR:
           if (s->nselect < ARRAY_SIZE(s->kickfds))
               val = s->kickfds[s->nselect].msi_vector;
           break;
    default:
           break;
    }

    trace_virtio_vhost_user_notification_read(s, addr, val);

    return val;
}

/* Set the MSI vectors for the master virtqueue notifications. */
static void virtio_vhost_user_notification_write(void *opaque, hwaddr addr,
                                               uint64_t val, unsigned size)
{
   /* MMIO regions are byte-addressable. The value of the `addr` argument is
    * relative to the starting address of the MMIO region. For example,
    * `addr = 6` means that the 6th byte of this MMIO region has been written.
    */
    VirtIOVhostUser *s = opaque;
    VirtIOVhostUserPCI *vvup = container_of(s, struct VirtIOVhostUserPCI, vdev);
    VirtIOPCIProxy *proxy = &vvup->parent_obj;

    switch (addr) {
    case NOTIFICATION_SELECT:
       if (val < VIRTIO_QUEUE_MAX) {
            s->nselect = val;
       }
       break;
    case NOTIFICATION_MSIX_VECTOR:
       msix_vector_unuse(&proxy->pci_dev, s->kickfds[s->nselect].msi_vector);
       if (msix_vector_use(&proxy->pci_dev, val) < 0) {
           val = VIRTIO_NO_VECTOR;
       }
        s->kickfds[s->nselect].msi_vector = val;
       break;
    default:
        break;
    }

    trace_virtio_vhost_user_notification_write(s, addr, val);
}

/* Handler for the master kickfd notifications. Inject an INTx or MSI-X interrupt
 * to the guest in response to the master notification. Use the appropriate
 * vector in the latter case.
 */
void virtio_vhost_user_guest_notifier_read(EventNotifier *n)
{
    struct kickfd *kickfd = container_of(n, struct kickfd, guest_notifier);
    VirtIODevice *vdev = kickfd->vdev;
    VirtIOVhostUser *vvu = container_of(vdev, struct VirtIOVhostUser, parent_obj);
    VirtIOVhostUserPCI *vvup = container_of(vvu, struct VirtIOVhostUserPCI, vdev);
    VirtIOPCIProxy *proxy = &vvup->parent_obj;
    PCIDevice *pci_dev = &proxy->pci_dev;

    if (event_notifier_test_and_clear(n)) {
       /* The ISR status register is used only for INTx interrupts. Thus, we
        * use it only in this case.
        */
       if (!msix_enabled(pci_dev)) {
           virtio_set_isr(vdev, 0x2);
       }
       /* Send an interrupt, either with INTx or MSI-X mechanism. msix_notify()
        * already handles the case where the MSI-X vector is NO_VECTOR by not issuing
        * interrupts. Thus, we don't have to check this case here.
        */
       virtio_notify_vector(vdev, kickfd->msi_vector);

       trace_virtio_vhost_user_guest_notifier_read(kickfd->guest_notifier.rfd, kickfd->msi_vector);
    }
}

/* TODO implement "5.7.7 Additional Device Resources over PCI" in
 * hw/virtio/virtio-pci.c instead of adding PCI BARs here
 * https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2920007
 */
static void virtio_vhost_user_init_bar(VirtIOVhostUser *s)
{
    /* virtio-pci doesn't use BAR 2 & 3, so we use it */
    const int bar_index = 2;

    /* TODO If the BAR is too large the guest won't have address space to map
     * it!
     */
    const uint64_t bar_size = 1ULL << 36;

    VirtIOVhostUserPCI *vvup = container_of(s, struct VirtIOVhostUserPCI, vdev);

    memory_region_init(&s->additional_resources_bar, OBJECT(s),
                       "virtio-vhost-user", bar_size);

    pci_register_bar(&vvup->parent_obj.pci_dev, bar_index,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_PREFETCH |
                     PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &s->additional_resources_bar);

    /* Initialize the VirtIOPCIRegions for the virtio configuration structures
     * corresponding to the additional device resource capabilities.
     * Place the additional device resources in the additional_resources_bar.
     */
    VirtIOPCIProxy *proxy = VIRTIO_PCI(vvup);

    vvup->doorbells.offset = 0x0;
    vvup->doorbells.size = virtio_pci_queue_mem_mult(proxy) * (VIRTIO_QUEUE_MAX + 1 /* logfd */);
    /* TODO Not sure if it is necessary for the size to be aligned */
    vvup->doorbells.size = QEMU_ALIGN_UP(vvup->doorbells.size, 4096);
    vvup->doorbells.type = VIRTIO_PCI_CAP_DOORBELL_CFG;

    vvup->notifications.offset = vvup->doorbells.offset + vvup->doorbells.size;
    vvup->notifications.size = 0x1000;
    vvup->notifications.type = VIRTIO_PCI_CAP_NOTIFICATION_CFG;

    /* cap.offset and cap.length must be 4096-byte (0x1000) aligned. */
    vvup->shared_memory.offset = vvup->notifications.offset + vvup->notifications.size;
    vvup->shared_memory.offset = QEMU_ALIGN_UP(vvup->shared_memory.offset, 4096);
    /* TODO Reconsider the shared memory cap.length later */
    /* The size of the shared memory region in the additional resources BAR doesn't
     * fit into the length field (uint32_t) of the virtio capability structure.
     * However, we don't need to pass this information to the guest driver via
     * the shared memory capability because the guest can figure out the length of
     * the vhost memory regions from the SET_MEM_TABLE vhost-user messages. Therefore,
     * the size of the shared memory region that we are declaring here has no
     * meaning and the guest driver shouldn't rely on this.
     */
    vvup->shared_memory.size = 0x1000;
    vvup->shared_memory.type = VIRTIO_PCI_CAP_SHARED_MEMORY_CFG;

    /* Initialize the MMIO MemoryRegions for the additional device resources. */

    static struct MemoryRegionOps doorbell_ops = {
        .read = virtio_vhost_user_doorbells_read,
       .write = virtio_vhost_user_doorbells_write,
       .impl = {
           .min_access_size = 1,
           .max_access_size = 4,
       },
       .endianness = DEVICE_LITTLE_ENDIAN,
    };

    static struct MemoryRegionOps notification_ops = {
        .read = virtio_vhost_user_notification_read,
        .write = virtio_vhost_user_notification_write,
        .impl = {
            .min_access_size = 1,
            .max_access_size = 4,
        },
        .endianness = DEVICE_LITTLE_ENDIAN,
    };

    memory_region_init_io(&vvup->doorbells.mr, OBJECT(s),
                   &doorbell_ops, s, "virtio-vhost-user-doorbell-cfg",
                   vvup->doorbells.size);

    memory_region_init_io(&vvup->notifications.mr, OBJECT(s),
                    &notification_ops, s, "virtio-vhost-user-notification-cfg",
                    vvup->notifications.size);

    /* Register the virtio PCI configuration structures
     * for the additional device resources. This involves
     * registering the corresponding MemoryRegions as
     * subregions of the additional_resources_bar and creating
     * virtio capabilities.
     */
    struct virtio_pci_cap cap = {
        .cap_len = sizeof cap,
    };
    struct virtio_pci_doorbell_cap doorbell = {
        .cap.cap_len = sizeof doorbell,
        .doorbell_off_multiplier =
            cpu_to_le32(virtio_pci_queue_mem_mult(proxy)),
    };

    virtio_pci_modern_region_map(proxy, &vvup->doorbells, &doorbell.cap,
                                 &s->additional_resources_bar, bar_index);
    virtio_pci_modern_region_map(proxy, &vvup->notifications, &cap,
                                 &s->additional_resources_bar, bar_index);
    virtio_pci_modern_region_map(proxy, &vvup->shared_memory, &cap,
                                 &s->additional_resources_bar, bar_index);
}

static void virtio_vhost_user_cleanup_bar(VirtIOVhostUser *s)
{
    VirtIOVhostUserPCI *vvup = container_of(s, struct VirtIOVhostUserPCI, vdev);

    memory_region_del_subregion(&s->additional_resources_bar,
                                &vvup->doorbells.mr);
    memory_region_del_subregion(&s->additional_resources_bar,
                                &vvup->notifications.mr);
}

static void virtio_vhost_user_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(dev);
    size_t i;

    if (!qemu_chr_fe_backend_connected(&s->chr)) {
        error_setg(errp, "Missing chardev");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(s->kickfds); i++) {
       s->kickfds[i].vdev = vdev;
       event_notifier_init_fd(&s->kickfds[i].guest_notifier, -1);
       s->kickfds[i].msi_vector = VIRTIO_NO_VECTOR;
    }

    for (i = 0; i < ARRAY_SIZE(s->callfds); i++) {
        s->callfds[i] = -1;
    }

    virtio_vhost_user_init_bar(s);

    virtio_init(vdev, "virtio-vhost-user", VIRTIO_ID_VHOST_USER,
                sizeof(VirtIOVhostUserConfig));

    s->rxq = virtio_add_queue(vdev, VIRTIO_VHOST_USER_VIRTQUEUE_SIZE,
                                 virtio_vhost_user_rxq);
    s->txq = virtio_add_queue(vdev, VIRTIO_VHOST_USER_VIRTQUEUE_SIZE,

                                 virtio_vhost_user_txq);
    /* Each vhost-user queue uses doorbells and a notification resources */
    s->config.max_vhost_queues = 1024;

    /* TODO uuid */

    virtio_vhost_user_reset_async_state(s);

    s->conn_state = CONN_STATE_INITIAL;
    qemu_chr_fe_set_handlers(&s->chr, NULL, NULL, virtio_vhost_user_chr_event,
            virtio_vhost_user_chr_change, s, NULL, false);
}

static void virtio_vhost_user_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVhostUser *s = VIRTIO_VHOST_USER(vdev);

    qemu_chr_fe_set_handlers(&s->chr, NULL, NULL, NULL,
                             NULL, NULL, NULL, false);
    virtio_cleanup(vdev);
    virtio_vhost_user_cleanup_bar(s);
    virtio_vhost_user_cleanup_mem_table(s);
    virtio_vhost_user_cleanup_kickfds(s);
    virtio_vhost_user_cleanup_callfds(s);
}

static const VMStateDescription vmstate_virtio_vhost_user_device = {
    .name = "virtio-vhost-user-device",
    .version_id = VIRTIO_VHOST_USER_VM_VERSION,
    .minimum_version_id = VIRTIO_VHOST_USER_VM_VERSION,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_virtio_vhost_user = {
    .name = "virtio-vhost-user",
    .minimum_version_id = VIRTIO_VHOST_USER_VM_VERSION,
    .version_id = VIRTIO_VHOST_USER_VM_VERSION,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_vhost_user_properties[] = {
    DEFINE_PROP_CHR("chardev", VirtIOVhostUser, chr),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_vhost_user_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_vhost_user_properties;
    dc->vmsd = &vmstate_virtio_vhost_user;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_vhost_user_device_realize;
    vdc->unrealize = virtio_vhost_user_device_unrealize;
    vdc->get_config = virtio_vhost_user_get_config;
    vdc->set_config = virtio_vhost_user_set_config;
    vdc->get_features = virtio_vhost_user_get_features;
    vdc->reset = virtio_vhost_user_reset;
    vdc->vmsd = &vmstate_virtio_vhost_user_device;
}

static const TypeInfo virtio_vhost_user_info = {
    .name = TYPE_VIRTIO_VHOST_USER,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOVhostUser),
    .class_init = virtio_vhost_user_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_vhost_user_info);
}

type_init(virtio_register_types)

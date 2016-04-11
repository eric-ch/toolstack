/*
 * Copyright (c) 2016 Assured information Security
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <poll.h>

// TODO: Debugging... Remove.
#include <stdarg.h>
#include <syslog.h>

#include <arpa/inet.h>

#include <libv4v.h>
#include <libdmbus.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/callback.h>

//#define V4V_BUFFER_SIZE 16384

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

#define Val_none    (Val_int(0))
#define caml_alloc_variant(val, tag)    \
        do { val = Val_int(tag); } while (0)
#define caml_alloc_variant_param(val, tag, p) \
        do { val = caml_alloc_small(1, tag); Field(val, 0) = (p); } while (0)
#define caml_alloc_variant_param2(val, tag, p1, p2) \
        do { val = caml_alloc_small(2, tag); \
             Field(val, 0) = (p1); Field(val, 1) = (p2); } while (0)
#define caml_alloc_some(val, param) \
	caml_alloc_variant_param(val, 0, param)

#define ERRMSG_LEN 512
static char errmsg[ERRMSG_LEN] = { 0 };

static char *make_errmsg(const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(errmsg, ERRMSG_LEN, fmt, ap);
    va_end(ap);
    if (n >= ERRMSG_LEN)
        errmsg[ERRMSG_LEN - 1] = '\0';
    return errmsg;
}

/* This has to be kept in sync with /type dmbus_service_id/.
 * Offset 0 -> Surfman, Offset 1 -> Input, is 
 * type dmbus_service_id = Surfman | Input
 */
static const enum dmbus_service_id __service_ids[] = {
    DMBUS_SERVICE_SURFMAN,
    DMBUS_SERVICE_INPUT,
};
/* Associate CAML type /Dmbus.service_id/ to DMBUS service id macros. */
static enum dmbus_service_id caml_to_service_id(int servid)
{
    if (servid < 0 || servid >= ARRAY_SIZE(__service_ids))
        caml_failwith(make_errmsg("%s(%d) failed.", __func__, servid));
    return __service_ids[servid];
}

/* This has to be kept in sync with type /Dmbus.device_type/. */
static const DeviceType __device_types[] = {
    DEVICE_TYPE_XENFB,
    /* Other devices are not handled, so ignore. */
    DEVICE_TYPE_INPUT,
};
static DeviceType caml_to_device_type(int devtype)
{
    if (devtype < 0 || devtype >= ARRAY_SIZE(__device_types))
        caml_failwith(make_errmsg("%s(%d) failed.", __func__, devtype));
    return __device_types[devtype];
}

/* This has to be kept in sync with /type message_type/. */
static const int __message_types[] = {
    DMBUS_MSG_SWITCHER_ABS,
    DMBUS_MSG_INPUT_CONFIG_RESET,
    DMBUS_MSG_DEVICE_MODEL_READY,
};
static int caml_to_message_type(int msgtype)
{
    if (msgtype < 0 || msgtype >= ARRAY_SIZE(__message_types))
        caml_failwith(make_errmsg("%s(%d) failed.", __func__, msgtype));
    return __message_types[msgtype];
}
static int message_type_to_caml(int msgtype)
{
    size_t i = 0;

    while (i < ARRAY_SIZE(__message_types) && __message_types[i] != msgtype)
        ++i;
    if (i >= ARRAY_SIZE(__message_types))
        caml_failwith(make_errmsg("%s(%d) failed.", __func__, msgtype));
    return i;
}

/* C equivalent to /type service/ for ease of use. */
struct c_service {
    enum dmbus_service_id id;
    int domid;
    DeviceType devtype;
};

/* Helper for /type service/ conversion to C types. */
static void caml_to_service(value caml_s, struct c_service *c_s)
{
    assert(c_s != NULL);
    assert(Is_block(caml_s));

    int tag = Tag_val(caml_s);
    value pair = Field(caml_s, 0);

    c_s->id = caml_to_service_id(tag);
    c_s->domid = Int_val(Field(pair, 0));
    c_s->devtype = caml_to_device_type(Int_val(Field(pair, 1)));
}

/* Helper for /type message/ conversion to C types. */
static void caml_to_message(value caml_m, union dmbus_msg *c_m)
{
    assert(c_m != NULL);

    if (!Is_block(caml_m)) {
        /* XXX: Only DeviceModelReady in this case, for now.
         *      Should match Int_val(c_m) for immediate value variants. */
        struct msg_device_model_ready *m = &c_m->device_model_ready;
        m->hdr.msg_len = sizeof (*m);
        m->hdr.msg_type = DMBUS_MSG_DEVICE_MODEL_READY;
        m->hdr.return_value = 0;
    } else {
        /* XXX: Only SwitchABS(bool) in this case, for now.
         *      Should match Tag_val(c_m) for constructor variants. */
        struct msg_switcher_abs *m = &c_m->switcher_abs;
        m->hdr.msg_len = sizeof (*m);
        m->hdr.msg_type = DMBUS_MSG_SWITCHER_ABS;
        m->hdr.return_value = 0;
        m->enabled = Bool_val(Field(caml_m, 0));
    }
}

/* Helpers for /type message/ converstion with C types. */
static value caml_alloc_dmbus_message(const union dmbus_msg *msg)
{
    CAMLparam0();
    CAMLlocal1(r);
    const struct dmbus_msg_hdr *hdr = &msg->hdr;

    switch (hdr->msg_type) {
        case DMBUS_MSG_SWITCHER_ABS: {
            const struct msg_switcher_abs *m = &msg->switcher_abs;
            caml_alloc_variant_param(r,
                    Val_int(message_type_to_caml(hdr->msg_type)),
                    Val_bool(!!m->enabled));
            break;
        }
        case DMBUS_MSG_INPUT_CONFIG_RESET: {
            const struct msg_input_config_reset *m = &msg->switcher_abs;
            caml_alloc_variant_param(r,
                    Val_int(message_type_to_caml(hdr->msg_type)),
                    Val_int(m->slot));
            break;
        }
        case DMBUS_MSG_DEVICE_MODEL_READY:
            caml_alloc_variant(r,
                    Val_int(message_type_to_caml(hdr->msg_type)));
            break;
        default:
            caml_failwith(make_errmsg("%s() unknown dmbus message %d (msg_len:%d).",
                                      __func__, hdr->msg_type, hdr->msg_len));
    }
    CAMLreturn(r);
}

/*
 * Helper to fill the prologue structure sent after connecting to the dmbus service.
 * @param p		prologue connection structure to be filled.
 * @param domid		domain-id of the domain running the dmbus service.
 * @param devtype	integer id from CAML type dmbus_device_type.
 * @throw	CAML Failure exception.
 */
static void dmbus_fill_prologue(struct dmbus_conn_prologue *p,
                                int domid, int devtype)
{
    size_t i;
    const char *hash_str = DMBUS_SHA1_STRING;

    assert(p != NULL);

    p->domain = domid;
    p->type = devtype;
    for (i = 0; i < ARRAY_SIZE(p->hash); ++i) {
        unsigned int c;
        sscanf(hash_str + 2 * i, "%02x", &c);
        p->hash[i] = c & 0xff;
    }
}

/*
 * Connect to the dmbus service described in /service/.
 * @param service	CAML Variant on the service type, constructed with the
 *                      domid and the device id.
 *
 * @return	The file-descriptor connected to the dmbus service id.
 * @throw	CAML Failure exception.
 */
CAMLprim value stub_dmbus_connect(value service)
{
    CAMLparam1(service);
    int err, s, rc;
    v4v_addr_t peer = { 0 };
    struct dmbus_conn_prologue p;
    struct c_service serv;

    s = v4v_socket(SOCK_STREAM);
    if (s < 0)
        caml_failwith(
            make_errmsg("v4v_socket(SOCK_STREAM) failed (%s).",
                        strerror(errno))
        );

    caml_to_service(service, &serv);
    peer.domain = serv.domid;
    peer.port = DMBUS_BASE_PORT + serv.id;
    caml_enter_blocking_section();
    rc = v4v_connect(s, &peer);
    caml_leave_blocking_section();
    if (rc < 0) {
        err = errno;
        close(s);
        caml_failwith(
            make_errmsg("v4v_connect() failed for dom%u:%d (%s).",
                        peer.domain, peer.port, strerror(err))
        );
    }

    dmbus_fill_prologue(&p, serv.domid, serv.devtype);
    caml_enter_blocking_section();
    rc = v4v_send(s, &p, sizeof (p), 0);
    caml_leave_blocking_section();
    if (rc != sizeof (p)) {
        err = errno;
        close(s);
        //caml_failwith(strerror(err));
        caml_failwith(
            make_errmsg("v4v_send() to dom%u:%d failed (%s).",
                        peer.domain, peer.port, strerror(err))
        );
    }

    CAMLreturn(Val_int(s));
}

/*
 * End connection with the dmbus service on which the given file-descriptor is
 * connected.
 * @param fd	file-descriptor connected to the dmbus service.
 * @throw	CAML Failure exception.
 */
CAMLprim void stub_dmbus_disconnect(value fd)
{
    CAMLparam1(fd);

    if (v4v_close(Int_val(fd)))
        caml_failwith(
            make_errmsg("%s() failed (%s).", strerror(errno))
        );

    CAMLreturn0;
}

/*
 * Dmbus message:
 * +--------+-----------------------------------+
 * | Header | Additional binary data (optional) |
 * +--------+-----------------------------------+
 *           <---------- hdr.msg_len ---------->
 * (libdmbus provides a union on all possible messages).
 */

/*
 * Helper to receive the whole header of a dmbus message.
 * @param fd	file-descriptor connected to the dmbus service.
 * @param hdr	message header structure to be filled.
 * @return On success the number of bytes received. If the other end closes the
 *         connection 0, else -1 and pass errno.
 */
static int dmbus_recv_hdr(int fd, struct dmbus_msg_hdr *hdr)
{
    int rc;
    size_t len = 0;
    uint8_t *buf = (void*)hdr;

    memset(hdr, 0, sizeof (*hdr));

    do {
        caml_enter_blocking_section();
        rc = v4v_recv(fd, buf + len, sizeof (*hdr) - len, 0);
        caml_leave_blocking_section();
        switch (rc) {
            case -1:
                if (errno == EINTR)
                    continue;
                return -1;
            case 0:
                return 0;
            default:
                len += rc;
        }
    } while (len != sizeof (*hdr));

    return len;
}

/*
 * Helper to receive the possible content of a message following a header.
 * The header must have been recovered already.
 *
 * @param fd	file-descriptor connected to the dmbus service.
 * @param hdr	message header structure describing the message.
 * @param msg	message structure to be filled.
 * @return On success the number of bytes received. If the other end closes the
 *         connection 0, else -1 and pass errno.
 */
static int dmbus_recv_msg(int fd, union dmbus_msg *msg)
{
    struct dmbus_msg_hdr *hdr = &msg->hdr;
    size_t len = 0;
    uint8_t *buf = (void*)msg + sizeof (*hdr);
    int rc;

    while (len != hdr->msg_len) {
        caml_enter_blocking_section();
        rc = v4v_recv(fd, buf + len, hdr->msg_len - len, 0);
        caml_leave_blocking_section();
        switch (rc) {
            case -1:
                if (errno == EINTR)
                    continue;
                return -1;
            case 0:
                return 0;
            default:
                len += rc;
        }
    }

    return len;
}

/*
 * Receive a message packet and its content from the provided file-descriptor.
 * This call will block until complete reception of the message.
 * @param fd	file-descriptor connected to the dmbus service.
 * @return	A CAML Dmbus.message object.
 * @throw	CAML Failure exception type with string description.
 */
CAMLprim value stub_dmbus_recvmsg(value caml_fd)
{
    CAMLparam1(caml_fd);
    CAMLlocal1(msg_opt);
    int fd = Int_val(caml_fd);
    union dmbus_msg msg;
    struct pollfd fds[1];
    int rc;

    fds[0].fd = fd;
    fds[0].events = POLLIN;
    do {
        /* Wait for the other-end to send us something. */
        caml_enter_blocking_section();
        rc = poll(fds, 1, -1);
        caml_leave_blocking_section();
        if (rc < 0)
            caml_failwith(
                make_errmsg("%s(): poll(%d) failed (%s).", __func__,
                            fd, strerror(errno))
            );

        rc = dmbus_recv_hdr(fd, &msg.hdr);
        if (rc < 0)
            caml_failwith(
                make_errmsg("%s(): recv_hdr(%d, %p) failed (%s).", __func__,
                            fd, &msg.hdr, strerror(errno))
            );
        if (rc == 0)
            break;
        rc = dmbus_recv_msg(fd, &msg);
        if (rc < 0)
            caml_failwith(
                make_errmsg("%s(): recv_msg(%d, %p) failed msg_len:%d (%s).", __func__,
                            fd, &msg, msg.hdr.msg_len, strerror(errno))
            );
        /* This does not handle other-end closing the socket.
         * It could be handled through an exception, in this case it should
         * not matter so much. */
        /* Allocate the CAML message variant equivalent. */
        caml_alloc_some(msg_opt, caml_alloc_dmbus_message(&msg));
        CAMLreturn(msg_opt);
    } while (1);

    CAMLreturn(Val_none);
}

/*
 * Helper to send a complete message on the connected fd provided, depending of
 * its type.
 * @param fd	file-descriptor connected to the dmbus service.
 * @param msg	Dmbus message packet to be sent.
 * @return	The number of bytes sent used to represent the message.
 * @throw	CAML Failure exception.
 */
static int dmbus_send_msg(int fd, const union dmbus_msg *msg)
{
    size_t len = msg->hdr.msg_len;
    ssize_t rc;

    while (len > 0) {
        caml_enter_blocking_section();
        rc = v4v_send(fd, msg, len, MSG_NOSIGNAL);
        caml_leave_blocking_section();
        if (rc < 0) {
            if (errno == ECONNRESET)
                return 0;
            return -1;
        }
        len -= rc;
    }
    return msg->hdr.msg_len;
}

/*
 * Send a Dmbus message on the socket.
 * @param fd	file-descriptor connected to the dmbus service.
 * @return	True on success, False if the other-end disconnects.
 * @throw	CAML Failure exception.
 */
CAMLprim value stub_dmbus_sendmsg(value fd, value omsg)
{
    CAMLparam2(fd, omsg);
    union dmbus_msg msg;
    int rc;

    caml_to_message(omsg, &msg);
    rc = dmbus_send_msg(fd, &msg);
    if (rc < 0)
        caml_failwith(
            make_errmsg("%s(): send_msg(%d, %p) failed msg_len:%d (%s).",
                        __func__, fd, &msg, msg.hdr.msg_len, strerror(errno))
            );
    CAMLreturn(Val_bool(rc != 0));
}


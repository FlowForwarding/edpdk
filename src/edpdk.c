/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2013 Tieto Global Oy. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <signal.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_ring.h>

#include <ei.h>

#include "edpdk.h"
#include "pmdengine.h"

static int eal_init_all(int argc, char ** argv);
static unsigned int mainloop(void);
static int read_cmd(unsigned char *, unsigned int);
static int write_cmd(ei_x_buff *);
static int read_exact(unsigned char *, unsigned int);
static int write_exact(unsigned char *, unsigned int);
static void int_handler(int);
static int encode_recv_ok(ei_x_buff *, char *, int);
static int encode_recv_fail(ei_x_buff *);
static int encode_xmit_ok(ei_x_buff *);
static int encode_xmit_fail(ei_x_buff *);
static int handle_cmd(struct port_se *, unsigned char *);

static FILE *logfp = NULL;

/**
 *
 */
int main(int argc, char ** argv) {
    int rc, ret;

    ret = 0;
    rc = 0;

    /* Log to file, so ei will work */

    rte_set_log_type(RTE_LOGTYPE_EDPDK, 1);

    logfp = fopen("./edpdk.log", "w+");

    /* Don't use RTE logs until eal is initialized */
    if (NULL == logfp) {
        printf("EDPDK: Unable to open log file.\n");
        return -1;
    }

    ret = eal_init_all(argc, argv);

    rc = pe_init();
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Failed to initialize ports\n");
        goto onerror;
    }

    rc = pe_init_lcores();
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Failed to initialize lcores\n");
        goto onerror;
    }

    rc = pe_start_ports(ALL_PORTS_MASK);
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Failed to start ports\n");
        goto onerror;
    }

    rc = pe_parse_args(argc, argv, ret);
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Unable to parse args\n");
        return -1;
    }

    rc = pe_init_mempool();
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Failed to initialize mempool\n");
        goto onerror;
    }

    rc = pe_start_pmdengine();
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Failed to start pmd engine\n");
        goto onerror;
    }

    rc = mainloop();
    if (OK != rc) {
        RTE_LOG(ERR, EDPDK, "Main loop failed\n");
        goto onerror;
    }

    onerror: pe_free_pmd_resources();
    return -1;

    return 0;
}

/**
 *
 */
static int eal_init_all(int argc, char ** argv) {
    int rc = 0;
    int ret = 0;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Failed to initialize EAL\n");

    rc = rte_openlog_stream(logfp);
    if (OK != rc)
        rte_panic("Unable to open log stream\n");

    if (OK != rte_pmd_init_all())
        rte_panic("Failed to initialize PMD\n");

    if (OK != rte_eal_pci_probe())
        rte_panic("Failed to probe PCI\n");

    return ret;
}

/**
 *
 */
static unsigned int mainloop(void) {

    unsigned char * buf;
    int encode_stat;
    int handle_cmd_stat;

    encode_stat = 0;
    handle_cmd_stat = 0;

    buf = (unsigned char *) malloc(sizeof(char) * BUF_SIZE);
    if (NULL == buf)
        return -1;

    memset(buf, 0, sizeof(char) * BUF_SIZE);
    signal(SIGINT, int_handler);

    while (read_cmd(buf, READ_SIZE) > 0) {

        struct port_se se;
        se.port = 0;
        se.version = 0;
        se.arity = 0;
        se.offset = 0;

        if (OK
                != ei_decode_version((const char *) buf, &se.offset,
                        &se.version))
            encode_stat = encode_xmit_fail(&se.result);

        if (OK
                != ei_decode_tuple_header((const char *) buf, &se.offset,
                        &se.arity))
            encode_stat = encode_xmit_fail(&se.result);

        if (CMD_ARITY != se.arity)
            encode_stat = encode_xmit_fail(&se.result);

        if (ei_decode_atom((const char *) buf, &se.offset, se.cmd))
            encode_stat = encode_xmit_fail(&se.result);

        if (ei_x_new_with_version(&(se.result))
                || ei_x_encode_tuple_header(&(se.result), RESULT_ARITY))
            encode_stat = encode_xmit_fail(&se.result);

        handle_cmd_stat = handle_cmd(&se, buf);
        if (OK != handle_cmd_stat)
            encode_stat = encode_xmit_fail(&se.result);

        if (OK != encode_stat) {
            RTE_LOG(ERR, EDPDK, "Failed to encode reply\n");
        } else {
            write_cmd(&(se.result));
        }
        ei_x_free(&(se.result));
    }

    free(buf);

    return 0;

}

/**
 * Add labels to improve readability - TODO(pepe)
 *
 */
static int handle_cmd(struct port_se * se, unsigned char * buf) {

#define NUM_RECV_PACKETS        1

    void * rpackets;
    struct rte_mbuf * mbuf;
    struct fwd_port *fwdp;
    void *dstart;
    int rc, data_len;

    dstart = NULL;
    fwdp = NULL;
    mbuf = NULL;
    rpackets = NULL;
    rc = 0;
    data_len = 0;

    if (OK == strcmp("recv", se->cmd)) {

        /* Skip empty binary {recv, <<>>, Rx} */
        ei_decode_binary((const char *) buf, &se->offset, se->rpacket,
                (long *) &se->pkt_len);

        /* Get requested port */
        if (OK != ei_decode_ulong((const char *) buf, &se->offset, &se->port))
            return encode_recv_fail(&se->result);

        fwdp = pe_get_fwd_port(se->port);
        if (NULL == fwdp)
            return encode_recv_fail(&se->result);;

        rc = rte_ring_sc_dequeue(fwdp->rxtx_rings->xmit_ring, &rpackets);

        if (-ENOENT == rc) {
            return encode_recv_fail(&se->result);
        } else if (OK != rc) {
            return encode_recv_fail(&se->result);
        } else if (NULL == rpackets) {
            return encode_recv_fail(&se->result);
        } else {
            mbuf = (struct rte_mbuf *) rpackets;
            dstart = rte_pktmbuf_mtod(mbuf, void *);
            data_len = rte_pktmbuf_data_len(mbuf);

            if (NULL == rte_memcpy(se->rpacket, dstart, data_len))
                return encode_recv_fail(&se->result);

            return encode_recv_ok(&se->result, (char *) se->rpacket, data_len);

        }

    } else if (OK == strcmp("xmit", se->cmd)) {

        ei_get_type((char *) buf, &se->offset, &se->type, (int *) &se->pkt_len);
        if ('m' != se->type)
            return encode_xmit_fail(&se->result);

        if (OK
                != ei_decode_binary((const char *) buf, &se->offset,
                        se->xpacket, (long *) &se->pkt_len)) {
            return encode_xmit_fail(&se->result);
        } else {

            /* Get requested port */
            if (OK
                    != ei_decode_ulong((const char *) buf, &se->offset,
                            &se->port))
                return encode_xmit_fail(&se->result);

            fwdp = pe_get_fwd_port(se->port);
            if (NULL == fwdp)
                return encode_xmit_fail(&se->result);

            if (NULL == get_rte_port(se->port))
                return encode_xmit_fail(&se->result);

            /* enqueue mbuf here */
            mbuf = pe_create_rte_mbuf(se->xpacket, se->pkt_len,
                    (unsigned int) se->port);
            /*rte_mbuf_refcnt_update(mbuf, 0);*/

            if (NULL == mbuf)
                return encode_xmit_fail(&se->result);

            rc = rte_ring_sp_enqueue(fwdp->rxtx_rings->recv_ring,
                    (void *) mbuf);

            if (-ENOBUFS == rc)
                return encode_xmit_fail(&se->result);

            encode_xmit_ok(&se->result);
        }
    }
    return 0;
}

/**
 *
 */
static int encode_recv_ok(ei_x_buff * result, char *rpacket, int size) {
    if (ei_x_encode_atom(result, "ok"))
        return -1;
    if (ei_x_encode_binary(result, rpacket, size))
        return -1;
    return 0;
}

/**
 *
 */
static int encode_recv_fail(ei_x_buff * result) {
    if (ei_x_encode_atom(result, "fail"))
        return -1;
    if (ei_x_encode_atom(result, "empty"))
        return -1;
    return 0;
}

/**
 *
 */
static int encode_xmit_ok(ei_x_buff * result) {
    if (ei_x_encode_atom(result, "ok"))
        return -1;
    if (ei_x_encode_atom(result, "queued"))
        return -1;
    return 0;
}

/**
 *
 */
static int encode_xmit_fail(ei_x_buff * result) {
    if (ei_x_encode_atom(result, "fail"))
        return -1;
    if (ei_x_encode_atom(result, "full_or_busy"))
        return -1;
    return 0;
}

/**
 *
 */
static int read_cmd(unsigned char * buf, unsigned int size) {

    unsigned int len;

    if (read_exact(buf, HEADER_SIZE) != HEADER_BYTES_COUNT)
        return (-1);

    len = (buf[0] << 8) | buf[1];

    if (len > size) {
        unsigned char* tmp = (unsigned char *) realloc(buf, len);
        if (tmp == NULL)
            return -1;
        else
            buf = tmp;
    }
    return read_exact(buf, len);
}

/**
 *
 */
static int write_cmd(ei_x_buff * buff) {
    unsigned char li;

    li = (buff->index >> 8) & 0xff;
    write_exact(&li, 1);
    li = buff->index & 0xff;
    write_exact(&li, 1);

    return write_exact((unsigned char *) buff->buff, buff->index);
}

/**
 *
 */
static int read_exact(unsigned char * buf, unsigned int len) {

    unsigned int i, got = 0;

    do {
        if ((i = read(STDIN_FILENO, buf + got, len - got)) <= 0) {
            return i;
        }
        got += i;
    } while (got < len);

    return len;
}

/**
 *
 */
static int write_exact(unsigned char * buf, unsigned int len) {
    unsigned int i, wrote = 0;

    do {
        if ((i = write(STDOUT_FILENO, buf + wrote, len - wrote)) <= 0)
            return i;
        wrote += i;
    } while (wrote < len);

    return len;
}

/**
 *
 */
static void int_handler(int dummy) {
    RTE_LOG(INFO, EDPDK, "%d\n", dummy);
    /* async safe ? */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
}

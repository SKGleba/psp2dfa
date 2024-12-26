#include <hardware/paddr.h>
#include <hardware/xbar.h>

#include "include/defs.h"
#include "include/debug.h"
#include "include/clib.h"
#include "include/compat.h"
#include "include/ernie.h"
#include "include/gpio.h"
#include "include/jig.h"
#include "include/maika.h"
#include "include/rpc.h"
#include "include/crypto.h"
#include "include/perv.h"
#include "include/i2c.h"
#include "include/uart.h"

#include "include/test.h"

// default init test function
void dfl_test(int arg) {
    printf("[BOB] test test test\n");

    if (arg & 1)
        set_dbg_mode(true);

    _MEP_SYNC_BUS_;

    printf("[BOB] killing arm...\n");
    compat_killArm(false);

    printf("[BOB] arm is dead, disable the OLED screen...\n");
    gpio_port_clear(0, GPIO_PORT_OLED);

    printf("[BOB] set max clock\n");
    vp 0xe3103040 = 0x10007;

#ifndef GLITCH_SKIP_TEST
    gpio_set_port_mode(0, GPIO_PORT_GAMECARD_LED, GPIO_PORT_MODE_OUTPUT);
    gpio_port_set(0, GPIO_PORT_GAMECARD_LED);
#endif

    printf("[BOB] test test stuff\n");
    rpc_loop();

    printf("[BOB] all tests done\n");
}


// glitch init test function
/*
void glitch_test(void) {
#ifndef SILENT
    statusled(0x31);
    hexdump(0x40000, 0x20000, true);
#endif

    statusled(0x32);
    for (uint32_t d_addr = 0x40000; d_addr < 0x60000; d_addr += 0x10)
        jig_update_shared_buffer((uint8_t*)d_addr, 0, 0x10, true);

    statusled(0x33);
    delay_nx(0x10000, 200);
}*/
struct _partial_s {
    uint8_t full[0x10];
    uint8_t four[0x10];
    uint8_t eight[0x10];
    uint8_t twelve[0x10];
};
typedef struct _partial_s partial_s;
void glitch_xbr128(bool ch, int slave_ks, int master_ks, int m2s_algo, void *seed, partial_s *dst) {
    if (master_ks)
        crypto_bigmacDefaultCmd(ch, (uint32_t)seed, slave_ks, 0x10, m2s_algo | CRYPTO_BIGMAC_FUNC_FLAG_TARGETS_KS, master_ks, 0, 0);

    crypto_bigmacDefaultCmd(ch, DEVNULL_OFFSET, (uint32_t)dst->twelve, 0x4, CRYPTO_BIGMAC_FUNC_AES_ECB_DEC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);
    crypto_bigmacDefaultCmd(ch, (uint32_t)dst->twelve, DEVNULL_OFFSET, 0x4, CRYPTO_BIGMAC_FUNC_AES_ECB_ENC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);

    crypto_bigmacDefaultCmd(ch, DEVNULL_OFFSET, (uint32_t)dst->eight, 0x8, CRYPTO_BIGMAC_FUNC_AES_ECB_DEC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);
    crypto_bigmacDefaultCmd(ch, (uint32_t)dst->eight, DEVNULL_OFFSET, 0x8, CRYPTO_BIGMAC_FUNC_AES_ECB_ENC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);

    crypto_bigmacDefaultCmd(ch, DEVNULL_OFFSET, (uint32_t)dst->four, 0xC, CRYPTO_BIGMAC_FUNC_AES_ECB_DEC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);
    crypto_bigmacDefaultCmd(ch, (uint32_t)dst->four, DEVNULL_OFFSET, 0xC, CRYPTO_BIGMAC_FUNC_AES_ECB_ENC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, DEVNULL_OFFSET, 0, 0);

    crypto_bigmacDefaultCmd(ch, DEVNULL_OFFSET, (uint32_t)dst->full, 0x10, CRYPTO_BIGMAC_FUNC_AES_ECB_DEC | CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128, slave_ks, 0, 0);
}

struct _glitch_arg {
    uint32_t flags;  // &0x3ff - keyslot, &0x400 - keysize 256, &0x800 - ecb enc, &0x7000 - clk, &0x8000 - use ch1, &0x3f0000 - keyslot2, &0x400000 - add a dumy op, &0x800000 - exp data to 256, &0xff000000 - hash
    uint8_t data[0x10];
};
typedef struct _glitch_arg glitch_arg;
void glitch_test(void) {
    vp 0xe3103040 = 0x10005;  // 27Mhz mep, 56Mhz mxbar
    int lastclk = 5;
    gpio_set_port_mode(0, GPIO_PORT_GAMECARD_LED, GPIO_PORT_MODE_OUTPUT);
    gpio_port_set(0, GPIO_PORT_GAMECARD_LED);
    glitch_arg *arg = (glitch_arg *)0x4C01c;
    maika_s *maika = (maika_s *)MAIKA_OFFSET;
    partial_s *parts = (partial_s *)0x4c080;
    void *dummydst = (void *)0x4c0c0;
    { // disable the 37mhz clock, let f00d fall back to ?27mhz ref?, up the voltage on all lines other than f00d, drop the voltage on f00d
        i2c_init_bus(0);
        i2c_transfer_write_short(0, 0xd2, 0xbf81, 2);
        ernie_exec_cmd_short(0x88e, 0x1004, 0x2);
        ernie_exec_cmd_short(0x88e, 0x1003, 0x2);
        ernie_exec_cmd_short(0x88e, 0x1002, 0x2);
        ernie_exec_cmd_short(0x88e, 0x3f01, 0x2); // drop as far as we can
    }
    { // add a dummy key to x31
        memset32(dummydst, 0x22222222, 0x20);
        crypto_bigmacDefaultCmd(1, (uint32_t)dummydst, (uint32_t)dummydst, 0x20, CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_256 | CRYPTO_BIGMAC_FUNC_AES_ECB_ENC | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY, DEVNULL_OFFSET, 0, 0);
        crypto_bigmacDefaultCmd(1, (uint32_t)dummydst, 0x31, 0x20, CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_256 | CRYPTO_BIGMAC_FUNC_AES_ECB_DEC | CRYPTO_BIGMAC_FUNC_FLAG_TARGETS_KS | CRYPTO_BIGMAC_FUNC_FLAG_USE_EXT_KEY, DEVNULL_OFFSET, 0, 0);
    }
    // int ret = 0;
    while (1) {
        memset(arg, 0, sizeof(glitch_arg));
        rxflush();
        print("kglr\n");
        scanb(arg, sizeof(glitch_arg));
        uint8_t hash = 0;
        for (int i = 0; i < 0x10; i++)
            hash += arg->data[i];
        if (hash != (arg->flags >> 24)) {
            printf("kgbh: %X, %X, %X, %X, %X, exp %X\n", arg->flags, vp(arg->data), vp(arg->data + 4), vp(arg->data + 8), vp(arg->data + 12), hash);
            break;
        }
        if (((arg->flags & 0x7000) >> 12) != lastclk) {
            pervasive_control_clock(0x10, 0x10000 | ((arg->flags & 0x7000) >> 12), true);
            lastclk = (arg->flags & 0x7000) >> 12;
        }
        bool ch = !!(arg->flags & 0x8000);
        uint32_t keyslot2 = (arg->flags & 0x3f0000) >> 16;
        uint32_t func = ((arg->flags & 0x400) ? CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_256 : CRYPTO_BIGMAC_FUNC_FLAG_KEYSIZE_128) |
                        ((arg->flags & 0x800) ? CRYPTO_BIGMAC_FUNC_AES_ECB_ENC : CRYPTO_BIGMAC_FUNC_AES_ECB_DEC) |
                        (keyslot2 ? CRYPTO_BIGMAC_FUNC_FLAG_TARGETS_KS : 0);
        if (arg->flags & 0x800000)
            memcpy(arg->data + 0x10, arg->data, 0x10);
        if (arg->flags & 0x400000)
            crypto_bigmacDefaultCmd(ch, DEVNULL_OFFSET, keyslot2 ? (uint32_t)keyslot2 : (uint32_t)dummydst, (arg->flags & 0x800000) ? 0x20 : 0x10, func, arg->flags & 0x3ff, 0, 0);
        {
            maika->bigmac_ctrl.channel[ch].src = (uint32_t)arg->data;
            maika->bigmac_ctrl.channel[ch].dst = keyslot2 ? (uint32_t)keyslot2 : (uint32_t)arg->data;
            maika->bigmac_ctrl.channel[ch].sz = (arg->flags & 0x800000) ? 0x20 : 0x10;
            maika->bigmac_ctrl.channel[ch].work_ks = arg->flags & 0x3ff;
            maika->bigmac_ctrl.channel[ch].func = func;
            maika->bigmac_ctrl.unk_status = 0;

            vp 0xE20A000C = 0x40;  // gpio clear

            maika->bigmac_ctrl.channel[ch].trigger = 1;  // rerun last op

            asm volatile("nop");
            asm volatile("nop");
            asm volatile("nop");
            asm volatile("nop");

            while (maika->bigmac_ctrl.channel[ch].res & 1) {}; // skip this for noW @SK

            vp 0xE20A0008 = 0x40;  // gpio set
        }
        if (maika->bigmac_ctrl.channel[ch].res & 1) {
            print("kgte:"); // flag that the operation is still running, shouldnt in normal cases
            while (maika->bigmac_ctrl.channel[ch].res & 1) {};
        }
        if (keyslot2) {
            memset(parts, 0, sizeof(partial_s));
            glitch_xbr128(ch, keyslot2, 0, 0, NULL, parts);
            hexdump(parts, sizeof(partial_s), false, false);
        } else
            hexdump(arg->data, (arg->flags & 0x800000) ? 0x20 : 0x10, false, false);
    }
}
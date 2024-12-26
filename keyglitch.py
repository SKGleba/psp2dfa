import sys
import time
import teensy_rpc
import sdboot
import bert
import serial
import re
from datetime import datetime
import random
import analyze_faults
import binascii

DEFAULT_COMMS = 'COM10'
DEFAULT_BAUD = 38400

DEFAULT_VARS_DICT = {
    "mosfet" : [22, "teensy pad to which the mosfet gate is connected"],
    "gpio" : [15, "teensy pad to which the gpio probe is connected"],
    "offset" : [4000, "delay between gpio going up and glitch insertion, starting value for the [width->width_max] loop"],
    "offset_mult" : [1, "multiplier for the [offset] delay"],
    "width" : [137, "how long the glitch/mosfet is held for, starting value for the glitch loop"],
    "state" : [1, "gpio up pad logic level, set this to 0 if gpio is inverted"],
    "width_max" : [139, "max [width] value for the glitch loop"],
    "width_step" : [1, "[width] increment size between each attempt in the glitch loop"],
    "offset_max" : [4200, "max [offset] value for the [width->width_max] loop"],
    "offset_step" : [1, "[offset] increment size after each [width->width_max] loop"],
    "loops" : [0, "glitch loop count, 0 - infinite"],
    "reply_timeout" : [3, "uart read timeout in seconds"],
    "delay_next" : [0.2, "delay (in seconds) between each attempt in the glitch loop"],
    "retry_count" : [2, "trigger retry count"],
    "loops" : [0, "glitch loop count, 0 - infinite"],
    "keyslot" : [0x31, "master keyslot"],
    "key256" : [1, "use 256bit AES enc/dec"],
    "enc" : [0, "encrypt"],
    "vclk" : [5, "mep clk, 2: 27Mhz, 3: 42Mhz, 4: 56Mhz, 5: 83Mhz, 6: 111Mhz, 7: 166Mhz"],
    "keyslot2" : [0, "slave keyslot"],
    "ch" : [0, "channel"],
    "preop" : [1, "add a dummy op before the actual op"],
    "go" : [0, "skip initial sdboot"],
    "analyze" : [0, "analyze the output live"],
    "skip" : [0, "skip to offset"],
    "expand" : [1, "expand data to 256bit"],
    "rand" : [0, "use \"random\" data as seed"],
}

VAR_ALIASES_DICT = {
    "u" : "up_to_read",
    "ux" : "up_to_read_mult",
    "o" : "offset",
    "ox" : "offset_mult",
    "om" : "offset_max",
    "os" : "offset_step",
    "w" : "width",
    "wm" : "width_max",
    "ws" : "width_step",
    "dn" : "delay_next",
    "db" : "delay_boot",
    "dc" : "delay_check",
    "l" : "loops"
}

KG_OK = "kgok"
KG_READY = "kglr"
KG_BAD_HASH = "kgbh" # bad input hash
KG_NOT_EQUAL = "kgne" # :128 != 128:
KG_TOO_EARLY = "kgte" # finished too early
KG_BAD_DECRYPT = "kgbd" # followed by 4x 32bit of data - eg kgbd:0x00000000:0x00000000:0x00000000:0x00000000
PC_READY = "PCGO\r\n"
#LOG_FILE = f"keyglitch.log.{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}"
LOG_FILE = "keyglitch.log"

HARD_SEED = bytes.fromhex("11111111111111111111111111111111")
ANALYZER_KEY = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")

def rand128():
    return random.getrandbits(128).to_bytes(16, byteorder='big')

def create_arg(keyslot=0x354, keyslot2=0, key256=0, enc=0, clk=2, ch=0, preop=0, expand=1, seed=HARD_SEED):
    # create a proper arg structure: 32bit flags folllowed by 128bit data
    ## &0x3ff - keyslot, &0x400 - keysize 256, &0x800 - ecb enc, &0x7000 - clk, &0x8000 - use ch1, &0x3f0000 - keyslot2, &0x400000 - add a dummy preop, &0x800000 - exp data to 256, &0xff000000 - hash
    arg = bytearray(20)
    arg[4:] = seed
    # set flags
    arg[0] = keyslot & 0xff
    arg[1] = ((keyslot >> 8) & 0x3) | ((key256 & 0x1) << 2) | ((enc & 0x1) << 3) | ((clk & 0x7) << 4) | ((ch & 0x1) << 7)
    arg[2] = (keyslot2 & 0x3f) | ((preop & 0x1) << 6) | ((expand & 0x1) << 7)
    # calculate the data hash - just add bytes, allow overflow
    arg[3] = 0
    for x in arg[4:]:
        arg[3] = (arg[3] + x) & 0xff
    return arg, arg[4:]


def cycle_payload():
    sdboot_args = {param: value[0] for param, value in sdboot.DEFAULT_VARS_DICT.copy().items()}
    sdboot_args["delay_check"] = 3
    if sdboot.glitch_loop(sdboot_args) == False:
        print("failed to cycle payload, retrying from cold")
        with open(LOG_FILE, 'a') as f:
            f.write(f"poweroff,cause=failed_cycle {datetime.now()}\n")
        bert.handle_cmd("power-off", ["","",0])
        time.sleep(1)
        print("retrying payload cycle")
        if sdboot.glitch_loop(sdboot_args) == False:
            with open(LOG_FILE, 'a') as f:
                f.write(f"exit,cause=failed_cycle {datetime.now()}\n")
            sys.exit(1)
    time.sleep(1)

def glitch_loop(argd):
    uart = serial.Serial(DEFAULT_COMMS, baudrate=DEFAULT_BAUD, timeout=argd["reply_timeout"])
    if uart.is_open:
        print(f"uart {uart.name} is open")
    else:
        print(f"uart {uart.name} is closed")
        return
    glitch = {param: value[0] for param, value in teensy_rpc.DEFAULT_ARG_DICT.copy().items()}
    glitch["trigger"] = argd["gpio"]
    glitch["trigger_state"] = argd["state"]
    glitch["driver"] = argd["mosfet"]
    glitch["queue"] = 0
    glitch["offset_mult"] = argd["offset_mult"]
    glitch["override"] = 1
    glitch["trigger_reconfigure"] = 1
    glitch["trigger_pke"] = 1
    glitch["trigger_pue"] = 1
    glitch["trigger_pus"] = 3

    print("getting clean output")
    seed = HARD_SEED if argd["rand"] == 0 else rand128()
    arg, datta = create_arg(argd["keyslot"], argd["keyslot2"], argd["key256"], argd["enc"], argd["vclk"], argd["ch"], argd["preop"], argd["expand"], seed)
    uart.reset_input_buffer()
    uart.write(arg)
    cont = uart.readline(0x1000).decode('utf-8').strip()
    if cont == "":
        for i in range(argd["retry_count"]):
            #uart.write(PC_READY.encode())
            cont = uart.readline().decode('utf-8').strip()
            if cont != "":
                break
        if cont == "":
            print("timeout without glitch, exiting")
            with open(LOG_FILE, 'a') as f:
                f.write(f"exit,cause=clean_to {datetime.now()}\n")
            return
    if argd["keyslot2"] != 0:
        with open(LOG_FILE, 'a') as f:
            f.write(f"flag,cause=clean seed={seed.hex().upper()},partials={cont[:32]}:{cont[32:56]}:{cont[64:80]}:{cont[96:104]} {datetime.now()}\n")
        exp_ret = cont[:64]
    else:
        with open(LOG_FILE, 'a') as f:
            f.write(f"flag,cause=clean seed={seed.hex().upper()},data={cont[:32]}:{cont[32:]} {datetime.now()}\n")
        exp_ret = cont[:32]
        if argd["expand"] == 1:
            exp_ret = exp_ret + exp_ret
        _akey = ANALYZER_KEY
        if argd["key256"] == 0:
            _akey = ANALYZER_KEY[:16]

    print("entering glitch loop")
    loopc = 0
    startoff = argd["skip"] + argd["offset"]
    while argd["loops"] == 0 or loopc < argd["loops"]:
        for width in range(argd["width"], argd["width_max"] + 1, argd["width_step"]):
            for offset in range(startoff, argd["offset_max"] + 1, argd["offset_step"]):
                print(f"try offset: {offset}, width: {width}")
                arg, datta = create_arg(argd["keyslot"], argd["keyslot2"], argd["key256"], argd["enc"], argd["vclk"], argd["ch"], argd["preop"], argd["expand"], seed)
                glitch["offset"] = offset
                glitch["width"] = width
                if teensy_rpc.glitch_add_dfl(glitch, max_wait=2) < 0:
                    print("Could not add dfl, cycling")
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"sdboot,cause=teensy_dfl {datetime.now()}\n")
                    cycle_payload()
                    if teensy_rpc.glitch_add_dfl(glitch, max_wait=5) < 0:
                        print("Could not add dfl, exiting")
                        with open(LOG_FILE, 'a') as f:
                            f.write(f"exit,cause=teensy_dfl {datetime.now()}\n")
                        return
                teensy_rpc.send_rpc_cmd("glitch_arm", [1])
                uart.reset_input_buffer()
                # write raw arg
                uart.write(arg)
                cont = uart.readline().decode('utf-8').strip()

                if cont == "":
                    for i in range(argd["retry_count"]):
                        #uart.write(PC_READY.encode())
                        cont = uart.readline().decode('utf-8').strip()
                        if cont != "":
                            break
                    if cont == "":
                        print("timeout")
                        with open(LOG_FILE, 'a') as f:
                            f.write(f"sdboot,cause=timeout offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']} {datetime.now()}\n")
                        cycle_payload()
                        continue
                if "jig" in cont or "ping" in cont:
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"flag,cause=reset offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']} {datetime.now()}\n")
                    #cycle_payload()
                    time.sleep(2)
                    uart.reset_input_buffer()
                    continue
                elif "CORE:" in cont:
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"flag,cause=exc offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']} {datetime.now()}\n")
                    time.sleep(4)
                    uart.reset_input_buffer()
                    #cycle_payload()
                    continue
                elif KG_READY in cont:
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"flag,cause=ready offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']} {datetime.now()}\n")
                    time.sleep(1)
                    uart.reset_input_buffer()
                    #cycle_payload()
                    continue
                elif KG_BAD_HASH in cont:
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"sdboot,cause=bad_hash offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']},{cont} {datetime.now()}\n")
                    time.sleep(1)
                    cycle_payload()
                    continue
                elif KG_TOO_EARLY in cont:
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"flag,cause=too_early offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']} {datetime.now()}\n")
                    time.sleep(1)
                    uart.reset_input_buffer()
                    #cycle_payload()
                    continue
                if argd["keyslot2"] != 0:
                    if cont[:64] != exp_ret[:64]:
                        with open(LOG_FILE, 'a') as f:
                            f.write(f"flag,cause=bad_decrypt offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']},partials={cont[:32]}:{cont[32:56]}:{cont[64:80]}:{cont[96:104]} {datetime.now()}\n")
                        time.sleep(1)
                        #cycle_payload()
                        continue
                else:
                    if cont != exp_ret:
                        afop = 1
                        opret = cont[:32]
                        if argd["expand"] == 1:
                            if cont[:32] == exp_ret[:32]:
                                afop = 0
                            if cont[32:] != exp_ret[32:]:
                                opret = cont[32:]
                                afop |= 2
                                print(f"W: Second op affected! afop: {afop}, data: {cont}")
                        if argd["analyze"] == 1:
                            if argd["enc"] == 0:
                                _atxt = binascii.unhexlify(exp_ret[:32])
                                _aexp = datta
                            else:
                                _atxt = datta
                                _aexp = binascii.unhexlify(exp_ret[:32])
                            try:
                                r,s,d = analyze_faults.parse(opret, offset, width, argd["vclk"], akey=_akey, aexp=_aexp, atxt=_atxt, aencrypt=argd["enc"])
                            except Exception as e:
                                print(f"ANalyzer exception: {e}")
                                r,s,d = "?", 0, "?"
                            opret = cont[:32] + ":" + cont[32:]
                            with open(LOG_FILE, 'a') as f:
                                f.write(f"flag,cause=bad_decrypt offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']},data={opret},af_op={afop},round={r},step={analyze_faults.AES.Step(s).name},diff={d} {datetime.now()}\n")
                        else:
                            opret = cont[:32] + ":" + cont[32:]
                            with open(LOG_FILE, 'a') as f:
                                f.write(f"flag,cause=bad_decrypt offset={offset},width={width},vclk={argd['vclk']},ch={argd['ch']},enc={argd['enc']},key256={argd['key256']},keyslot={argd['keyslot']},keyslot2={argd['keyslot2']},data={opret},af_op={afop} {datetime.now()}\n")
                        time.sleep(1)
                        uart.reset_input_buffer()
                        #cycle_payload()
                        continue
                time.sleep(argd["delay_next"])
            startoff = argd["offset"]
        loopc += 1

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "help":
        print("\nUsage: " + sys.argv[0] + " param=value par6=val6 par3=val3 ...\n")
        print("Descr: " + "insert glitches during keyring ops" + "\n")
        print(f"{'PARAM':>16}" + " : " + f"{'DEFAULT':^11}" + " : " + "DESCRIPTION")
        print(f"{'-----':>16}" + " : " + f"{'-------':^11}" + " : " + "-----------")
        for arg in DEFAULT_VARS_DICT:
            print(f"{arg:>16}" + " : " + f"{str(DEFAULT_VARS_DICT[arg][0]):^11}" + " : " + DEFAULT_VARS_DICT[arg][1])
    else:
        arg_dict = {param: value[0] for param, value in DEFAULT_VARS_DICT.copy().items()}
        for arg in sys.argv[1:]:
            key, val = re.split(r'[=\+\-\/\*]', arg, maxsplit=1)
            if key in VAR_ALIASES_DICT:
                    key = VAR_ALIASES_DICT[key]
            if val.startswith('0x'):
                val = int(val, 16)
            elif '.' in val:
                val = float(val)
            else:
                val = int(val)
            if '=' in arg:
                arg_dict[key] = val
            elif '+' in arg:
                arg_dict[key] += val
            elif '-' in arg:
                arg_dict[key] -= val
            elif '*' in arg:
                arg_dict[key] *= val
            elif '/' in arg:
                arg_dict[key] /= val
        print(arg_dict)
        with open(LOG_FILE, 'a') as f:
            f.write(f"new offset={arg_dict['offset']},offset_max={arg_dict['offset_max']},offset_step={arg_dict['offset_step']},width={arg_dict['width']},width_max={arg_dict['width_max']},width_step={arg_dict['width_step']} {datetime.now()}\n")
        if arg_dict["go"] == 0:
            cycle_payload()
        glitch_loop(arg_dict)
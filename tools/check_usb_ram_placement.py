"""The USB code does not take internal RAM while USB is off.

Reads the symbol table of the built ELF and checks where the linker put:
- the USB host driver's buffer fill/execute functions (IRAM_ATTR in the
  driver): in flash, moved there by main/usb_flash.lf;
- the plain state of usb_port.c, cell_uplink.c and eth_uplink.c: in PSRAM
  (EXT_RAM_BSS_ATTR), not in internal DRAM.
Atomics and spinlocks stay internal on purpose (no atomics in PSRAM on the
ESP32-S3) and are not listed. Usage: check_usb_ram_placement.py <build dir>
"""
from pathlib import Path
import shutil
import subprocess
import sys

FLASH_TEXT = (0x42000000, 0x44000000)
EXT_RAM = (0x3C000000, 0x3E000000)
DRIVER_FLASH = {'hcd_dwc.c': ('_buffer_fill', '_buffer_exec')}
PSRAM = {
    'usb_port.c': ('s_dev', 's_choice', 's_switched', 's_mem', 's_glue', 'text.*'),   # text.*: the function-static message buffer
    'cell_uplink.c': ('s_saved', 's_running', 's_status'),
    'eth_uplink.c': ('s_saved', 's_running', 's_status'),
}


def objdump():
    found = shutil.which('xtensa-esp-elf-objdump')
    if found:
        return found
    for path in sorted((Path.home() / '.platformio/packages').glob('toolchain-xtensa-esp*/bin/xtensa-esp*-elf-objdump*')):
        return str(path)
    raise SystemExit('FAIL: xtensa objdump not found')


def symbols(elf):
    """{source file: {symbol: address}} from the ELF symbol table (local symbols follow their file)."""
    table, current = {}, None
    for line in subprocess.check_output([objdump(), '-t', str(elf)], text=True, errors='replace').splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-3] == '*ABS*' and 'df' in parts:
            current = parts[-1]
            continue
        if len(parts) >= 5 and current:
            try:
                table.setdefault(current, {})[parts[-1].replace('$', '.')] = int(parts[0], 16)
            except ValueError:
                pass
    return table


def main():
    build = Path(sys.argv[1])
    elf = next((p for p in (build / 'firmware.elf', build / 'esp32_tsr.elf') if p.is_file()), None)
    assert elf, f'no ELF in {build}'
    table = symbols(elf)
    problems = []
    for rule, (low, high), where in ((DRIVER_FLASH, FLASH_TEXT, 'flash'), (PSRAM, EXT_RAM, 'PSRAM')):
        for source, names in rule.items():
            found = table.get(source)
            if found is None:
                problems.append(f'{source}: not in the symbol table')
                continue
            for name in names:
                if name.endswith('.*'):
                    address = next((v for k, v in found.items() if k.startswith(name[:-1])), None)
                else:
                    address = found.get(name)
                if address is None:
                    problems.append(f'{source}:{name}: symbol missing')
                elif not low <= address < high:
                    problems.append(f'{source}:{name} at 0x{address:08x}, expected {where}')
    assert not problems, 'FAIL: ' + '; '.join(problems)
    print('PASS: USB driver buffer code in flash and USB/cellular/Ethernet state in PSRAM (%s)' % elf.name)


if __name__ == '__main__':
    main()

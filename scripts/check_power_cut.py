#!/usr/bin/env python3
"""Abrupt QEMU guest power cuts. Requires prepared Linux kernel and module tree.
Usage: check_power_cut.py KERNEL MODULES_DIR [ROUNDS]
MODULES_DIR contains lib/modules-style version directories (e.g. Alpine modloop's modules).
Build first: cargo build --locked -p gateway-runtime --example power_cut
Requires QEMU, static /bin/busybox, cpio, gzip, mkfs.ext4. No root or host mounts.
"""
import os
import pathlib
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import hashlib
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    kernel, modules = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:3])
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    if rounds < 1:
        raise ValueError('ROUNDS must be positive')
    print(subprocess.check_output(['qemu-system-x86_64', '--version'], text=True).splitlines()[0])
    print('kernel_sha256=' + hashlib.sha256(kernel.read_bytes()).hexdigest(), flush=True)
    binary = pathlib.Path('target/debug/examples/power_cut').resolve()
    with tempfile.TemporaryDirectory(prefix='hypgate-power-') as temporary:
        work = pathlib.Path(temporary)
        root = work / 'root'
        for directory in ['bin', 'dev', 'proc', 'sys', 'data', 'lib/modules']:
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / 'sbin').symlink_to('bin')
        shutil.copytree(modules, root / 'lib/modules', dirs_exist_ok=True)
        shutil.copy('/bin/busybox', root / 'bin/busybox')
        for app in ['sh', 'mount', 'modprobe', 'poweroff', 'sleep', 'cat', 'uname', 'dmesg', 'ls']:
            (root / 'bin' / app).symlink_to('busybox')
        shutil.copy(binary, root / 'workload')
        for line in subprocess.check_output(['ldd', str(binary)], text=True).splitlines():
            match = re.search(r'(/\S+)', line)
            if match:
                source = pathlib.Path(match[1])
                destination = root / source.relative_to('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(source, destination)
        init = root / 'init'
        init.write_text('''#!/bin/sh
export PATH=/bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
uname -a
modprobe virtio_pci
modprobe virtio_blk
modprobe virtio_rng
modprobe ext4
sleep 2
mount -t ext4 -o data=ordered,barrier=1 /dev/vda /data || poweroff -f
cat /proc/mounts
mode=$(cat /proc/cmdline)
mode=${mode##*case=}
/workload "$mode"
echo POWER_DONE
poweroff -f
''')
        init.chmod(0o755)
        archive = work / 'initramfs.gz'
        with archive.open('wb') as output:
            run('bash', '-c', 'find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -1', cwd=root, stdout=output)
        disk = work / 'disk.img'

        def boot(mode, cut=None):
            command = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '384', '-display', 'none',
                       '-device', 'virtio-rng-pci', '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-nic', 'none',
                       '-kernel', str(kernel), '-initrd', str(archive),
                       '-append', f'console=ttyS0 quiet panic=-1 case={mode}',
                       '-drive', f'file={disk},format=raw,if=virtio,cache=writeback']
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            observed = 0
            transcript = bytearray()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 120
            try:
                while time.monotonic() < deadline:
                    if not selector.select(1):
                        if process.poll() is not None:
                            break
                        continue
                    block = os.read(process.stdout.fileno(), 65536)
                    if not block:
                        break
                    transcript.extend(block)
                    (work / "console.log").write_bytes(transcript)
                    acks = re.findall(rb'POWER_ACK (\d+)\r?\n', transcript)
                    if acks:
                        observed = int(acks[-1])
                    if cut and observed >= cut:
                        process.kill()  # no guest shutdown, unmount, or sync
                        process.wait()
                        return observed
                    if b'POWER_PASS ' in transcript and b'POWER_DONE' in transcript:
                        print(transcript.decode(errors='replace').split('POWER_PASS ')[-1].splitlines()[0])
                        return observed
                raise RuntimeError(transcript.decode(errors='replace'))
            finally:
                selector.close()
                if process.poll() is None:
                    process.kill()
                process.wait()

        for trial in range(rounds):
            with disk.open('wb') as image:
                image.truncate(128 * 1024 * 1024)
            run('mkfs.ext4', '-q', '-F', '-m', '0', str(disk))
            target = [1, 3, 8, 17, 32, 63][trial % 6]
            mode = 'pause' if trial == 0 else 'write'
            acknowledged = boot(mode, target)
            print(f'trial={trial + 1} mode={mode} cut_after={acknowledged}', flush=True)
            boot(str(acknowledged))


if __name__ == '__main__':
    main()

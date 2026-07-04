from __future__ import annotations

from besta_tools.common.styling import ListLabel
from besta_tools.dfutool.partition import scan_partition

from .._version import *

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from io import SEEK_END, BufferedReader, BufferedWriter
from pathlib import Path
import sys
import traceback
from typing import Callable, TYPE_CHECKING, Self, cast, override
import weakref

import click_extra as click
from click_extra import ColorOption, NoColorOption, TableFormat, VerbosityOption, VerboseOption, QuietOption, VersionOption
from click._termui_impl import ProgressBar
from click.termui import progressbar
from usb.core import Device

from besta_tools.common.utils import anybase, bytes_unit, copyfileobjex_progress
from besta_tools.dfutool.device import enumerate_device, generate_udev_file, generate_zadig_files
from besta_tools.dfutool.dfu import MAX_BULK_XFER_SIZE, DfuDevice, Lun

if TYPE_CHECKING:
    from types import TracebackType
    from _typeshed import MaybeNone, SupportsRead


@dataclass
class GlobalOptions:
    device_index: int | MaybeNone = field(default=None)
    device_type: str | None = field(default=None)
    usb_address: UsbAddress | None = field(default=None)
    yes: bool | MaybeNone = field(default=None)


class UsbAddress:
    bus: int
    address: int

    def __init__(self, s: str) -> None:
        b_str, a_str = s.split(':')
        self.bus, self.address = int(b_str, 10), int(a_str, 10)


class CopyProgress(AbstractContextManager):  # pyright: ignore[reportMissingTypeArgument], we're using it as an ABC
    _lun: Lun
    _total: int
    _current: int
    _pc: int
    _pb: ProgressBar[int]

    def __init__(self, lun: Lun, total_bytes: int) -> None:
        self._lun = weakref.proxy(lun)
        self._total = total_bytes
        self._current = 0
        self._pc = 0
        self._pb = progressbar(length=total_bytes)

    @override
    def __enter__(self) -> Self:
        self._pb = self._pb.__enter__()
        return cast(Self, super().__enter__())

    @override
    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None, /) -> None:
        self._lun.set_progress(self._pc)
        self._pb.__exit__(exc_type, exc_value, traceback)
        return None

    def update(self, inc: int) -> None:
        self._pb.update(inc)
        self._current += inc
        new_pc = int(round(self._current * 100 / self._total))
        if new_pc > self._pc:
            # Defer the last 100% update to after we flush the writer to
            # prevent the possibility of set_progress messing with flash lock.
            if new_pc < 100:
                self._lun.set_progress(new_pc)
            self._pc = new_pc


def _format_usb_addr(dev: Device) -> str:
    return f'Bus {dev.bus:03d} Address {dev.address:03d}'


def _pick_device(opts: GlobalOptions) -> DfuDevice | None:
    if opts.usb_address is not None:
        for kind, dev in enumerate_device():
            if dev.address == opts.usb_address.address and dev.bus == opts.usb_address.bus:
                click.echo(f'Using device at {_format_usb_addr(dev)}, type {kind.name}.')
                return DfuDevice(dev)
        return None
    elif opts.device_type is None:
        for idx, (kind, dev) in enumerate(enumerate_device()):
            if idx == opts.device_index:
                click.echo(f'Using device #{idx} at {_format_usb_addr(dev)}, type {kind.name}.')
                return DfuDevice(dev)
        return None
    else:
        for kind, dev in enumerate_device():
            if kind.name == opts.device_type:
                click.echo(f'Using first device of type {kind.name} at {_format_usb_addr(dev)}.')
                return DfuDevice(dev)
        return None


def compare_progress(
    f1: SupportsRead[bytes],
    f2: SupportsRead[bytes],
    limit: int,
    length: int = 512,
    progress_callback: Callable[[int], None] | None = None
) -> bool:
    r1 = f1.read
    r2 = f2.read

    while limit > 0:
        bytes_to_read = min(length, limit)
        data1, data2 = r1(bytes_to_read), r2(bytes_to_read)
        if len(data1) == 0 or len(data2) == 0:
            break
        limit -= bytes_to_read
        if progress_callback is not None:
            progress_callback(bytes_to_read)
        if data1 != data2:
            return False
    return True

@click.group(
    name='dfutool',
    help='Tool for interfacing with Besta Device Firmware Update (DFU) mode.',
    params=[
        ColorOption(),
        NoColorOption(),
        VerbosityOption(),
        VerboseOption(),
        QuietOption(),
        VersionOption(),
    ],
)
@click.option(
    '-d', '--device-index',
    type=int,
    default=0,
    help=(
        'Use the device at this index as shown in the list command. ' +
        'This is used when no USB address nor device type is provided.'
    )
)
@click.option(
    '-t', '--device-type',
    default=None,
    help=(
        'Use the first device of this type. This is used over the device ' +
        'index but not the USB address.'
    )
)
@click.option(
    '-U', '--usb-address',
    type=UsbAddress,
    default=None,
    help=(
        'Use the USB device with a specific address. The address must be ' +
        'in the form of Bus:Address (e.g. 001:001). This takes the highest ' +
        'priority.'
    )
)
@click.option(
    '-y', '--yes/--no-yes',
    help='Assume yes to all questions (DANGEROUS).'
)
@click.pass_context
def app(ctx: click.Context, device_index: int, device_type: str | None, usb_address: UsbAddress | None, yes: bool) -> None:
    a = ctx.ensure_object(GlobalOptions)
    a.device_index = device_index
    a.device_type = device_type
    a.usb_address = usb_address
    a.yes = yes


@app.command(
    name='list',
    short_help='List available devices.'
)
def do_list() -> None:
    found_at_least_one = False
    for idx, (kind, dev) in enumerate(enumerate_device()):
        found_at_least_one = True
        size: int
        try:
            dfu = DfuDevice(dev)
            with dfu.get_dfu_lun() as lun:
                size = lun.capacity.size_bytes
        except Exception:
            click.echo(f'WARNING: Cannot attach to DFU interface for device #{idx}')
            click.echo(traceback.format_exc())
            continue

        click.echo(f'Index #{idx}: {_format_usb_addr(dev)}: {kind.description} ({kind.name}) - {bytes_unit(size)}')

    if not found_at_least_one:
        click.echo('No device found.')


@app.command(
    name='reboot',
    short_help='Reboot a device.'
)
@click.pass_context
def do_reboot(ctx: click.Context) -> None:
    opts = ctx.find_object(GlobalOptions)
    assert opts is not None
    dfu = _pick_device(opts)
    if dfu is None:
        click.echo('No matching device found.')
        sys.exit(1)
    with dfu.get_dfu_lun() as lun:
        lun.reboot()


@app.command(
    name='erase',
    short_help='Instruct a device to erase itself and scan for bad blocks.',
    help=(
        '''
        Issue a command to the device that instructs it to erase itself and
        scan for bad blocks. Not all device support this command. Currently
        the s3c series devices are known to support it.
        '''
    )
)
@click.pass_context
def do_erase(ctx: click.Context) -> None:
    opts = ctx.find_object(GlobalOptions)
    assert opts is not None
    dfu = _pick_device(opts)
    if dfu is None:
        click.echo('No matching device found.')
        sys.exit(1)
    if not opts.yes and not click.confirm(
        'This will ERASE THE OS AND ALL USER DATA and render the device ' +
        'UNBOOTABLE until new firmware is flashed onto it. Please DO NOT turn ' +
        'off the device power when erase operation is in progress or it could ' +
        'PERMANENTLY BRICK THE DEVICE! Do you still wish to proceed?'
    ):
        click.echo('Operation canceled.')
        sys.exit(1)
    with dfu.get_dfu_lun() as lun:
        lun.probe_region(0)
        lun.erase()

@app.command(
    name='read',
    short_help='Read raw data from a device.'
)
@click.option(
    '-o', '--output',
    type=click.File('wb'),
    required=True,
    help='Output file'
)
@click.option(
    '-s', '--start-address',
    type=anybase,
    default=0,
    help='Start address.'
)
@click.option(
    '-n', '--num-bytes',
    type=anybase,
    default=None,
    help='Number of bytes to read.'
)
@click.pass_context
def do_read(ctx: click.Context, output: BufferedWriter, start_address: int, num_bytes: int | None) -> None:
    opts = ctx.find_object(GlobalOptions)
    assert opts is not None
    dfu = _pick_device(opts)
    if dfu is None:
        click.echo('No matching device found.')
        sys.exit(1)

    with dfu.get_dfu_lun() as lun:
        leftover = max(0, lun.capacity.size_bytes - start_address)
        limit = min(num_bytes, leftover) if num_bytes is not None else leftover

        if not lun.ping():
            click.echo('ERROR: Device did not respond to DFU ping.')
            sys.exit(1)
        lun.set_progress(0)

        click.echo(f'Reading {limit} bytes ({bytes_unit(limit)}) from device...')
        progress = CopyProgress(lun, limit)
        with progress, lun.get_buffered_reader() as rd:
            if rd.seek(start_address) != start_address:
                click.echo('Failed to seek to start address.')
                sys.exit(1)
            copyfileobjex_progress(rd, output, limit, progress_callback=progress.update)
        click.echo('Done.')


@app.command(
    name='write',
    short_help='Write raw data from a file to the device.',
)
@click.option(
    '-i', '--input', 'input_',
    type=click.File('rb'),
    required=True,
    help='Input file'
)
@click.option(
    '-s', '--start-address',
    type=anybase,
    default=0,
    help='Start address.'
)
@click.option(
    '-n', '--num-bytes',
    type=anybase,
    default=None,
    help='Number of bytes to write.'
)
@click.option(
    '--verify/--no-verify',
    default=True,
    help='Number of bytes to write.'
)
@click.pass_context
def do_write(ctx: click.Context, input_: BufferedReader, start_address: int, num_bytes: int | None, verify: bool) -> None:
    opts = ctx.find_object(GlobalOptions)
    assert opts is not None
    dfu = _pick_device(opts)
    if dfu is None:
        click.echo('No matching device found.')
        sys.exit(1)

    with dfu.get_dfu_lun() as lun:
        input_size = input_.seek(0, SEEK_END)

        leftover = max(0, lun.capacity.size_bytes - start_address)

        if num_bytes is not None and input_size < num_bytes:
            click.echo(
                f'WARNING: File size ({input_size} bytes) is less than ' +
                f'requested  write size ({num_bytes} bytes). Truncate at file ' +
                'size.'
            )
            num_bytes = input_size

        if num_bytes is None and leftover < input_size:
            click.echo(
                'ERROR: File is too big to fit in the selected space ' +
                f'(file is {input_size} bytes long while the device has ' +
                f'only {leftover} bytes available at the base address). ' +
                'Use --num-bytes to truncate the file if you wish to proceed.'
            )
            sys.exit(1)
        elif num_bytes is not None and leftover < num_bytes:
            click.echo(
                'ERROR: Requested number of bytes too small ' +
                f'(requested {input_size} bytes long while the device has ' +
                f'only {leftover} bytes available at the base address). ' +
                'Adjust --num-bytes if you wish to proceed.'
            )
            sys.exit(1)

        limit = min(num_bytes, leftover, input_size) if num_bytes is not None else min(input_size, leftover)

        input_.seek(0)

        if not opts.yes and not click.confirm(
            f'This will write {limit} bytes ({bytes_unit(limit)}) to base ' +
            f'address {hex(start_address)}. Do you wish to proceed?'
        ):
            click.echo('Operation canceled.')
            sys.exit(1)

        if not lun.ping():
            click.echo('ERROR: Device did not respond to DFU ping.')
            sys.exit(1)
        lun.set_progress(0)

        click.echo(f'Writing {limit} bytes ({bytes_unit(limit)}) to device...')
        progress = CopyProgress(lun, limit)
        # Ensure progress will only be flushed after writer has been flushed.
        with progress, lun.get_buffered_writer() as wr:
            if wr.seek(start_address) != start_address:
                click.echo('Failed to seek to start address.')
                sys.exit(1)
            copyfileobjex_progress(input_, wr, limit, length=MAX_BULK_XFER_SIZE, progress_callback=progress.update)
        if verify:
            click.echo('Verifying...')
            lun.set_progress(0)
            input_.seek(0)
            progress = CopyProgress(lun, limit)
            with progress, lun.get_buffered_reader() as rd:
                if rd.seek(start_address) != start_address:
                    click.echo('Cannot verify: Failed to seek to start address.')
                    sys.exit(1)
                result = compare_progress(input_, rd, limit, progress_callback=progress.update)
            if result:
                click.echo('Verified.')
            else:
                click.echo(
                    'Verification FAILED. The NAND might have bad ' +
                    'blocks or something got corrupted during USB transfer.'
                )
        else:
            click.echo('Done.')


@app.command(
    name='lspart',
    short_help='Scan for and list all detected partitions.'
)
@click.pass_context
def do_lspart(ctx: click.Context) -> None:
    opts = ctx.find_object(GlobalOptions)
    assert opts is not None
    dfu = _pick_device(opts)
    if dfu is None:
        click.echo('No matching device found.')
        sys.exit(1)

    with dfu.get_dfu_lun() as lun:
        if not lun.ping():
            click.echo('ERROR: Device did not respond to DFU ping.')
            sys.exit(1)
        lun.set_progress(0)
        with lun.get_buffered_reader() as blk:
            partitions = scan_partition(blk)
        lun.set_progress(100)

    click.secho(ListLabel('Installed Partitions') + ':')
    table_data = [
        (part.name,
         part.type.name,
         part.version,
         hex(part.base_address),
         hex(part.size)) for part in partitions
    ]
    click.print_table(  # pyright: ignore[reportUnknownMemberType], kwargs is untyped
        table_data,
        headers=list[str](
            ListLabel(x) for x in ('Name', 'Type', 'Version', 'Base Addr.', 'Size')
        ),
        table_format=TableFormat.ALIGNED,
    )


@app.group(
    name='gen',
    short_help='Generate OS-specific device driver files.',
    help=(
        '''
        By design, dfutool does not use the operating system's SCSI driver, and
        instead uses libusb to communicate with the DFU's USB Mass Storage
        interface directly to avoid driver-specific behavior or other programs
        from messing with the DFU mode operation. Although dfutool makes use of
        libusb's attach/detach kernel driver feature, it's still recommended to
        disable the SCSI driver for these devices as early as possible as there
        is a potential for the SCSI driver to interfere with the DFU by leaving
        them in an unpredictable state, and thus causing undesired and
        potentially dangerous effects. Additionally, OSes may refuse to allow
        dfutool to access the raw DFU device with the default privilege and/or
        driver configuration. The gen command is developed to solve these
        problems. It generates OS-specific configuration files that set up
        device permission and driver so dfutool can work safely and optimally
        under these systems.
        '''
    ),
)
def do_gen() -> None:
    pass


@do_gen.command(
    name='udev',
    short_help='Generate udev rule file (Linux).',
    help=(
        '''
        Generate udev rules file and place it at specified path.

        The rules set the uaccess tag to allow non-root access of the device,
        and automatically detach the Linux USB Mass Storage driver from listed
        devices.
        '''
    ),
)
@click.option(
    '-o', '--output',
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=Path('./42-besta.rules'),
    help='Path to generated file.',
)
def do_gen_udev(output: Path) -> None:
    generate_udev_file(output)
    click.echo(f'udev file {output} has been generated.')


@do_gen.command(
    name='zadig',
    short_help='Generate zadig config files (Windows).',
    help=(
        '''
        Generate zadig device config files and place them under specified path.

        Download zadig from https://zadig.akeo.ie/ to use these files through
        the Device -> Load Preset Device option. This is required on Windows
        systems as otherwise libusb will not have access to the DFU devices.

        Kindly refer to https://github.com/pbatard/libwdi/wiki/Zadig#basic-usage
        for zadig usage.
        '''
    ),
)
@click.option(
    '-o', '--output',
    type=click.Path(dir_okay=True, file_okay=False, writable=True, path_type=Path),
    default=Path('./zadig'),
    help='Path to create a directory for generated files (must not already exist).',
)
def do_gen_zadig(output: Path) -> None:
    generate_zadig_files(output)
    click.echo(f'zadig device config files have been generated under {output}.')

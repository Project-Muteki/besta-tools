from __future__ import annotations

from dataclasses import dataclass, field
from io import SEEK_END, BufferedReader, BufferedWriter
import sys
import traceback
from typing import TYPE_CHECKING

import click
from usb.core import Device

from besta_tools.common.utils import copyfileobjex_progress
from besta_tools.dfutool.device import enumerate_device
from besta_tools.dfutool.dfu import DfuDevice

if TYPE_CHECKING:
    from _typeshed import MaybeNone


@dataclass
class GlobalOptions:
    device_index: int | MaybeNone = field(default=None)
    device_type: str | None = field(default=None)
    usb_address: UsbAddress | None = field(default=None)
    yes: bool | MaybeNone = field(default=None)


def _unit(val: int) -> str:
    if val < 1000:
        return f'{val} B'

    tmp: float = float(val) / 1024
    for unit in ('KiB', 'MiB', 'GiB'):
        if tmp >= 1000:
            tmp = tmp / 1024
        else:
            return f'{tmp:.2f} {unit}'

    return f'{tmp:.2f} TiB'


def _format_usb_addr(dev: Device) -> str:
    return f'Bus {dev.bus:03d} Address {dev.address:03d}'


def _anybase(s: str) -> int:
    return int(s, 0)


class UsbAddress:
    bus: int
    address: int

    def __init__(self, s: str) -> None:
        b_str, a_str = s.split(':')
        self.bus, self.address = int(b_str, 10), int(a_str, 10)


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


@click.group(help='Tool for interfacing with Besta DFU.')
@click.option('-d', '--device-index', type=int, default=0, help='Use the device at this index as shown in the . This is used when no USB address nor device type is provided.')
@click.option('-t', '--device-type', default=None, help='use the first device of this type. This is used over the device index but not the USB address.')
@click.option('-U', '--usb-address', type=UsbAddress, default=None, help='Use the USB device with a specific address. The address must be in the form of Bus:Address (e.g. 001:001). This takes the highest priority.')
@click.option('-y', '--yes/--no-yes', help='Assume yes to questions (DANGER).')
@click.pass_context
def app(ctx: click.Context, device_index: int, device_type: str | None, usb_address: UsbAddress | None, yes: bool):
    a = ctx.ensure_object(GlobalOptions)
    a.device_index = device_index
    a.device_type = device_type
    a.usb_address = usb_address
    a.yes = yes


@app.command(name='list', short_help='List available devices.')
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

        click.echo(f'Index #{idx}: {_format_usb_addr(dev)}: {kind.description} ({kind.name}) - {_unit(size)}')

    if not found_at_least_one:
        click.echo('No device found.')


@app.command(name='reboot', short_help='Reboot a device.')
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


@app.command(name='read', short_help='Read raw data from a device.')
@click.option('-o', '--output', type=click.File('wb'), required=True, help='Output file')
@click.option('-s', '--start-address', type=_anybase, default=0, help='Start address.')
@click.option('-n', '--num-bytes', type=_anybase, default=None, help='Number of bytes to read.')
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
        click.echo(f'Reading {limit} bytes from device...')
        with lun.get_buffered_reader() as rd:
            if rd.seek(start_address) != start_address:
                click.echo('Failed to seek to start address.')
                sys.exit(1)
            copyfileobjex_progress(rd, output, limit)
        click.echo('Done.')


@app.command(name='write', short_help='Write raw data from a file to the device.')
@click.option('-i', '--input', 'input_', type=click.File('rb'), required=True, help='Input file')
@click.option('-s', '--start-address', type=_anybase, default=0, help='Start address.')
@click.option('-n', '--num-bytes', type=_anybase, default=None, help='Number of bytes to write.')
@click.pass_context
def do_write(ctx: click.Context, input_: BufferedReader, start_address: int, num_bytes: int | None) -> None:
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
                f'WARNING: File size ({input_size}) is less than requested ' +
                f'write size ({num_bytes}). Truncate at file size.'
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
            f'This will write {hex(limit)} bytes to base address' +
            '{hex(start_address)}. Do you wish to proceed?'
        ):
            click.echo('Operation canceled.')
            sys.exit(1)

        with lun.get_buffered_writer() as wr:
            if wr.seek(start_address) != start_address:
                click.echo('Failed to seek to start address.')
                sys.exit(1)
            input_size = input_.seek(0, SEEK_END)
            input_.seek(0)
            copyfileobjex_progress(
                input_,
                wr,
                limit
            )

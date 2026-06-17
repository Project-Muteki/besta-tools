from __future__ import annotations

from dataclasses import dataclass, field
import sys
import traceback
from typing import TYPE_CHECKING

import click
from usb.core import Device

from besta_tools.dfutool.device import enumerate_device
from besta_tools.dfutool.dfu import DfuDevice

if TYPE_CHECKING:
    from _typeshed import MaybeNone


@dataclass
class GlobalOptions:
    device_index: int | MaybeNone = field(default=None)
    device_type: str | None = field(default=None)
    usb_address: UsbAddress | None = field(default=None)


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
@click.pass_context
def app(ctx: click.Context, device_index: int, device_type: str | None, usb_address: UsbAddress | None):
    a = ctx.ensure_object(GlobalOptions)
    a.device_index = device_index
    a.device_type = device_type
    a.usb_address = usb_address


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

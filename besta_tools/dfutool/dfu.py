from __future__ import annotations

# Some resource on how to interface with USB mass storage devices without a driver:
# https://www.downtowndougbrown.com/2018/12/usb-mass-storage-with-embedded-devices-tips-and-quirks/

from typing import Any

from random import randrange

from usb.core import Device, Endpoint, Interface
from usb.util import ENDPOINT_IN, ENDPOINT_OUT, endpoint_direction, find_descriptor
from usb.legacy import CLASS_MASS_STORAGE

from besta_tools.dfutool.formats import CBW, CSW, BestaDfuCommand, BestaDfuConfigPacket, BestaDfuSbcOpcode, CsBestaDfuConfigPacket, CsCBW, CsCSW

from .usbms_const import USB_INTERFACE_PROTOCOL_BBB, USB_INTERFACE_SUBCLASS_SCSI


class DfuDevice:
    dev: Device[Any, Any]
    intf: Interface[Any, Any]
    in_ep: Endpoint[Any, Any]
    out_ep: Endpoint[Any, Any]
    lun: int

    def __init__(self, dev: Device[Any, Any]):
        self.dev = dev

        intf: Interface | None = None
        for cfg in dev:
            intf = find_descriptor(
                cfg,
                bInterfaceClass=CLASS_MASS_STORAGE,
                bInterfaceSubClass=USB_INTERFACE_SUBCLASS_SCSI,
                bInterfaceProtocol=USB_INTERFACE_PROTOCOL_BBB,
            )
            if intf is None:
                continue
            self.dev.detach_kernel_driver(intf.bInterfaceNumber)
            self.dev.set_configuration(cfg.bConfigurationValue)
            break

        if intf is None:
            raise TypeError(f'Device {dev.address} does not seem to have a SCSI interface.')
        self.intf = intf

        #self.dev.detach_kernel_driver(self.intf.bInterfaceNumber)

        in_ep = find_descriptor(self.intf, custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress) == ENDPOINT_IN)
        out_ep = find_descriptor(self.intf, custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress) == ENDPOINT_OUT)

        if in_ep is None or out_ep is None:
            raise TypeError(f'Device {dev.address} does not properly declare required endpoints.')

        self.in_ep, self.out_ep = in_ep, out_ep
        # Assume first lun
        # TODO: Look up LUNs or allow user to specify one (is this necessary?)
        self.lun = 0

    def cmd_write(self, cmd: bytes | bytearray, data: bytes | None = None) -> CSW:
        '''
        Send a write SCSI command and optionally send extra data.
        '''
        tag = randrange(0, 0x100000000)
        cbw = CBW(
            dCBWTag=tag,
            dCBWDataTransferLength=len(data) if data is not None else 0,
            bmCBWFlags=0x00,
            bCBWLUN=self.lun,
            CBWCB=cmd,
        )
        packet = CsCBW.build(cbw)
        self.out_ep.write(packet)
        if data is not None:
            self.out_ep.write(data)
        response = self.in_ep.read(CsCSW.sizeof())
        csw = CsCSW.parse(response.tobytes())
        csw.dCSWTag ^= tag  # If tags are the same, returned dCSWTag should be a 0.
        return csw

    def cmd_read(self, cmd: bytes | bytearray, length: int = 0) -> tuple[CSW, bytes]:
        '''
        Send a read SCSI command and optionally request data.
        '''
        tag = randrange(0, 0x100000000)
        cbw = CBW(
            dCBWTag=tag,
            dCBWDataTransferLength=length,
            bmCBWFlags=0x80,
            bCBWLUN=self.lun,
            CBWCB=cmd,
        )
        packet = CsCBW.build(cbw)
        self.out_ep.write(packet)
        data = self.in_ep.read(length).tobytes() if length > 0 else b''
        response = self.in_ep.read(CsCSW.sizeof())
        csw = CsCSW.parse(response.tobytes())
        csw.dCSWTag ^= tag  # If tags are the same, returned dCSWTag should be a 0.
        return csw, data

    def scsi_besta_set_config(self, cmd: BestaDfuCommand, param: int, data: bytes | None = None) -> CSW:
        req = BestaDfuConfigPacket(
            command=cmd,
            parameter=param
        )
        scsi_cmd = bytearray(16)
        scsi_cmd[0] = BestaDfuSbcOpcode.SET_CONFIG
        if data is not None:
            payload = bytearray(256)
            payload[:len(data)] = data
            req.payload = payload
        return self.cmd_write(scsi_cmd, CsBestaDfuConfigPacket.build(req))

    def scsi_besta_get_config(self) -> tuple[CSW, BestaDfuConfigPacket]:
        scsi_cmd = bytearray(16)
        scsi_cmd[0] = BestaDfuSbcOpcode.GET_CONFIG
        ret, res_data = self.cmd_read(scsi_cmd, CsBestaDfuConfigPacket.sizeof())
        res = CsBestaDfuConfigPacket.parse(res_data)
        return ret, res

    @staticmethod
    def besta_check_ack(packet: BestaDfuConfigPacket, cmd: BestaDfuCommand, param: int) -> bool:
        return packet.command == cmd | BestaDfuCommand.ACK and packet.parameter == param | BestaDfuCommand.ACK

    def ping(self) -> bool:
        ret = self.scsi_besta_set_config(BestaDfuCommand.CMD_PING, BestaDfuCommand.CMD_PING_ARG)
        if ret.bCSWStatus != 0:
            print('SET_CONFIG bCSWStatus error', ret)
            return False

        ret, res = self.scsi_besta_get_config()
        if ret.bCSWStatus != 0:
            print('GET_CONFIG bCSWStatus error', ret)
            return False

        if self.besta_check_ack(res, BestaDfuCommand.CMD_PING, BestaDfuCommand.CMD_PING_ARG):
            return True
        else:
            print('NACK', res)
            return False

    #def set_progress(self, value: int): ...

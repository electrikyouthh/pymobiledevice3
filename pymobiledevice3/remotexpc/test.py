import asyncio
from socket import AF_INET6, create_connection, inet_ntop
from typing import Mapping

import click
from ifaddr import get_adapters
from pymobiledevice3.lockdown import create_using_remotexpc
from scapy.contrib.http2 import (H2DataFrame, H2Frame, H2Setting,
                                 H2SettingsFrame, H2WindowUpdateFrame)
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from zeroconf.const import _TYPE_AAAA

from sniffer import HTTP2_MAGIC
from structs import XpcWrapper, create_xpc_wrapper, get_object_from_xpc_wrapper

# from remoted ([RSDRemoteNCMDeviceDevice createPortListener])
RSD_PORT = 58783

H2FRAME_SIZE = len(H2Frame())


class RemoteXPC:
    def __init__(self, address: str):
        self.address = address
        self.sock = None

    def connect(self) -> None:
        self.sock = create_connection((self.address, RSD_PORT))
        print(self.sock)

    def do_handshake(self) -> Mapping:
        self.sock.sendall(HTTP2_MAGIC)

        settings_frame = H2Frame() / H2SettingsFrame()
        settings_frame.settings = [
            H2Setting(id=H2Setting.SETTINGS_MAX_CONCURRENT_STREAMS, value=100),
            H2Setting(id=H2Setting.SETTINGS_INITIAL_WINDOW_SIZE, value=1048576),
        ]
        self.sock.sendall(bytes(settings_frame))

        window_update_frame = H2Frame() / H2WindowUpdateFrame()
        window_update_frame.win_size_incr = 983041
        self.sock.sendall(bytes(window_update_frame))

        # send empty headers packet (stream_id=1)
        self.sock.sendall(b'\x00\x00\x00\x01\x04\x00\x00\x00\x01')

        xpc_wrapper = create_xpc_wrapper({})
        packet = H2Frame(type=0, stream_id=1) / H2DataFrame(data=xpc_wrapper)
        self.sock.sendall(bytes(packet))

        packet = H2Frame(type=0, stream_id=1) / H2DataFrame(
            data=XpcWrapper.build({'size': 0, 'flags': 0x0201, 'payload': None}))
        self.sock.sendall(bytes(packet))

        # send empty headers packet (stream_id=3)
        self.sock.sendall(b'\x00\x00\x00\x01\x04\x00\x00\x00\x03')

        packet = H2Frame(type=0, stream_id=3) / H2DataFrame(
            data=XpcWrapper.build({'size': 0, 'flags': 0x00400001, 'payload': None}))
        self.sock.sendall(bytes(packet))

        assert isinstance(self.recv_h2_frame().lastlayer(), H2SettingsFrame)

        packet = H2Frame(flags={'A'}) / H2SettingsFrame()
        self.sock.sendall(bytes(packet))

        while True:
            # wait for handshake packet
            frame = self.recv_h2_frame()
            if not isinstance(frame.lastlayer(), H2DataFrame):
                continue
            if not XpcWrapper.parse(frame.data).flags.DATA_PRESENT:
                continue
            return get_object_from_xpc_wrapper(frame.data)

    def recv_h2_frame(self) -> H2Frame:
        buf = self.sock.recv(H2FRAME_SIZE)

        while True:
            try:
                H2Frame(buf).len
                break
            except AssertionError:  # when not enough data
                buf += self.sock.recv(1)

        return H2Frame(buf)


class RemotedListener(ServiceListener):
    def __init__(self):
        super().__init__()
        self.is_finished = asyncio.Event()

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name == 'ncm._remoted._tcp.local.':
            records = zc.cache.async_entries_with_name('iphone.local.')
            for record in records:
                if record.type == _TYPE_AAAA:
                    self.record = record
                    self.is_finished.set()


async def try_get_iphone_address(adapter):
    ip = adapter.ips[0].ip[0]
    zeroconf = Zeroconf(interfaces=[ip])
    waiter_task = asyncio.create_task(zeroconf.notify_event.wait())
    listener = RemotedListener()
    ServiceBrowser(zeroconf, "_remoted._tcp.local.", listener)
    await waiter_task
    await listener.is_finished.wait()
    return inet_ntop(AF_INET6, listener.record.address) + '%' + adapter.nice_name


async def get_iphone_address():
    adapters = get_adapters()
    adapters = [adapter for adapter in adapters if adapter.ips[0].is_IPv6]
    tasks = [asyncio.create_task(try_get_iphone_address(adapter)) for adapter in adapters]
    finished, unfinished = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    return list(finished)[0].result()


@click.command()
def cli():
    addr = asyncio.run(get_iphone_address())
    remote = RemoteXPC(addr)
    remote.connect()
    handshake = remote.do_handshake()
    lockdown_port = int(handshake['Services']['com.apple.mobile.lockdown.remote.untrusted']['Port'])
    lockdown = create_using_remotexpc(hostname=addr, autopair=False,
                                      port=lockdown_port)
    print(lockdown)


if __name__ == '__main__':
    cli()

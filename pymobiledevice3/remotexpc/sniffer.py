import logging
import struct
from pprint import pformat
from typing import List

import click
import coloredlogs
from construct import ConstError
from hexdump import hexdump
from scapy.contrib.http2 import H2Frame
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.sendrecv import sniff
from scapy.sessions import TCPSession
from structs import XpcWrapper, get_object_from_xpc_wrapper

IFACE = "VHC128"
HTTP2_MAGIC = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

IP_TO_NAME = {
    "fe80::aede:48ff:fe00:1122": "imac",
    "fe80::aede:48ff:fe33:4455": "t2"
}

logger = logging.getLogger()

coloredlogs.install(level=logging.DEBUG)


class TCPStream:
    def __init__(self, key):
        self.key = key
        self.data = bytearray()
        self.seq = -1  # so we know seq hasn't been initialized yet
        self.later = {}  # data segments to add later
        # ^^^ {seq: payload, seq: payload, ...}

    def __repr__(self):
        return "Stream<%s>" % self.key

    def __len__(self):
        return len(self.data)

    def src(self):
        return self.key.split("/")[0]

    def dst(self):
        return self.key.split("/")[3]

    def sport(self):
        return int(self.key.split("/")[1])

    def dport(self):
        return int(self.key.split("/")[4])

    # returns true if we added an in-order segment, false if not
    def add(self, tcp_pkt: TCP):
        # if this is a new stream
        if self.seq == -1:
            # set initial seq
            self.seq = tcp_pkt.seq
        # grab payload bytes
        data = bytes(tcp_pkt.payload)
        data_len = len(data)
        seq_idx = tcp_pkt.seq - self.seq
        if len(self.data) < seq_idx:
            # if this data is out of order and needs to be inserted later
            self.later[seq_idx] = data
            return False
        else:
            # if this data is in order (has a place to be inserted)
            self.data[seq_idx:seq_idx + data_len] = data
            # check if there are any waiting data segments to add
            for seq_i in sorted(self.later.keys()):
                if seq_i <= len(
                        self.data):  # if we can add this segment to the stream
                    pl = self.later[seq_i]
                    self.data[seq_i:seq_i + len(pl)] = pl
                    del self.later[seq_i]  # remove from later dict
                else:
                    break  # short circuit because list is sorted
            return True

    def pop_magic(self):
        # if self.data starts with the http/2 magic bytes, pop them off
        magic = HTTP2_MAGIC
        magic_len = len(magic)
        if self.data[:magic_len] == magic:
            self.data = self.data[magic_len:]
            self.seq += magic_len
            return magic
        return b""

    def pop_frames(self) -> List[H2Frame]:
        # iterate over self.data and attempt to form HTTP/2 frames
        frame_size = len(H2Frame())
        frames = []
        while len(self.data) >= frame_size:
            try:
                frame_len = H2Frame(self.data).len
            except AssertionError:  # when not enough data
                break
            # if we've got a frame, but don't have all the data for it yet
            if frame_len > len(self.data):
                break  # without adding this frame
            # if we pop this frame, remove its data from self.data
            # and push self.seq up by len(frame)
            frame = H2Frame(self.data[:frame_size + frame_len])
            self.data = self.data[frame_size + frame_len:]
            self.seq += frame_size + frame_len
            frames.append(frame)
        return frames


class RemoteXPCSniffer:
    def __init__(self):
        self._tcp_streams = {}

    def process_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            if packet[TCP].payload:
                self._process_tcp(packet)

    def _process_tcp(self, pkt: Packet):
        # we are going to separate TCP packets into TCP streams between unique
        # endpoints (ip/port) then, for each stream, we will create a new TCPStream
        # object and pass TCP packets into it TCPStream objects will take the bytes
        # from each TCP packet and add them to the stream.  No error correction /
        # checksum checking will be done. The stream will just overwrite its bytes
        # with whatever is presented in the packets. If the stream receives packets
        # out of order, it will add the bytes at the proper index.
        if pkt.haslayer(IP):
            net_pkt = pkt[IP]
        elif pkt.haslayer(IPv6):
            net_pkt = pkt[IPv6]
        else:
            return
        # we assume the parent function already checked to make sure this packet has a TCP layer
        tcp_pkt = pkt[TCP]
        stream_id = self._create_stream_id(net_pkt.src, net_pkt.dst, tcp_pkt.sport, tcp_pkt.dport)
        tcp_stream = self._tcp_streams.setdefault(stream_id, TCPStream(stream_id))
        # ^^^ like dict.get, but creates new entry if it doesn't exist
        stream_finished_assembling = tcp_stream.add(tcp_pkt)
        if stream_finished_assembling:  # if we just added something in order
            self._process_stream(tcp_stream)

    @staticmethod
    def _handle_no_frames(tcp_stream: TCPStream) -> None:
        """
        this might be because we just got a HUGE frame and have to wait for
        it to be reassembled, so check the first three bytes as a length
        field and see if tcp_stream is shorter than this
        """
        if len(tcp_stream) >= 3:
            len_bytes = struct.unpack('BBB', tcp_stream.data[:3])
            potential_len = (len_bytes[0] << 16) + (
                    len_bytes[1] << 8) + len_bytes[2]
            # ^^^ this is big-endian for some reason
            if potential_len > len(tcp_stream):
                logger.debug(f'Received {len(tcp_stream)} bytes of a {potential_len}-byte http/2 frame')
                return
        logger.warning(f'{tcp_stream} doesn\'t appear to have an http/2 frame')
        hexdump(tcp_stream.data)

    @staticmethod
    def _handle_data_frame(tcp_stream: TCPStream, frame: H2Frame) -> None:
        try:
            frame.data  # for some reason, some malformed packets don't contain this data field
        except AttributeError:
            logger.warning(
                f'Received empty http/2 data frame on Stream {frame.stream_id} on port '
                f'{tcp_stream.dport() if IP_TO_NAME.get(tcp_stream.dst()) == "t2" else tcp_stream.sport()}')
            return

        try:
            xpc_wrapper = XpcWrapper.parse(frame.data)
            logger.info(f'XpcWrapper: {xpc_wrapper}')
            xpc_message = get_object_from_xpc_wrapper(frame.data)

            if xpc_message is not None:
                logger.info(f'As Python Object: {pformat(xpc_message)}')
        except ConstError:  # if we don't know what this payload is
            logger.debug(
                f'New Data frame {IP_TO_NAME.get(tcp_stream.src())}->{IP_TO_NAME.get(tcp_stream.dst())} on '
                f'HTTP/2 stream {frame.stream_id} TCP port '
                f'{tcp_stream.dport() if IP_TO_NAME.get(tcp_stream.dst()) == "t2" else tcp_stream.sport()}')
            hexdump(frame.data[:64])
            if len(frame.data) > 64:
                logger.debug(f'... {len(frame.data)} bytes')

    def _handle_single_frame(self, tcp_stream: TCPStream, frame: H2Frame) -> None:
        logger.debug(f'New HTTP/2 frame: {tcp_stream.key}')
        if frame.fields.get('type', None) == 1:  # Header Frame
            logger.debug(
                f'{IP_TO_NAME.get(tcp_stream.src())} opening stream {frame.stream_id} for communication on port '
                f'{tcp_stream.dport() if IP_TO_NAME.get(tcp_stream.dst()) == "t2" else tcp_stream.sport()}')
        elif frame.fields.get('type', None) == 3:  # Reset Frame
            logger.debug(f'{IP_TO_NAME.get(tcp_stream.src())} closing stream {frame.stream_id} on port '
                         f'{tcp_stream.dport() if IP_TO_NAME.get(tcp_stream.dst()) == "t2" else tcp_stream.sport()}')
        elif frame.fields.get('type', None) == 0:  # Data Frame
            self._handle_data_frame(tcp_stream, frame)

    def _process_stream(self, tcp_stream: TCPStream) -> None:
        if tcp_stream.pop_magic():
            logger.debug('HTTP/2 magic bytes')
        # Does this tcp_stream contain an HTTP/2 frame?
        frames = tcp_stream.pop_frames()
        # if we get back an empty list, then the stream may have something else on
        # it, but I don't know what that would be right now
        if len(frames) == 0:
            self._handle_no_frames(tcp_stream)
            return

        # each packet can store multiple frames -- we only care about data frames
        for frame in frames:
            self._handle_single_frame(tcp_stream, frame)

    @staticmethod
    def _create_stream_id(src: str, dst: str, sport: int, dport: int) -> str:
        s = f'{src}/{sport}'
        d = f'{dst}/{dport}'
        return '//'.join([s, d])  # we use this for directional streams


@click.group()
def cli():
    pass


@cli.command()
@click.argument('file', type=click.Path(exists=True, file_okay=True, dir_okay=False))
def offline(file: str):
    sniffer = RemoteXPCSniffer()
    for p in sniff(offline=file, session=TCPSession):
        sniffer.process_packet(p)


@cli.command()
@click.argument('iface')
def live(iface: str):
    sniffer = RemoteXPCSniffer()
    for p in sniff(iface=iface, prn=sniffer.process_packet):
        sniffer.process_packet(p)


if __name__ == '__main__':
    cli()

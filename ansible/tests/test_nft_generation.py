"""Exercise the production GETGEN reader against independent binary fixtures.

No socket reaches the kernel and the rest of the audit is never executed.
Protocol basis: torvalds/linux v6.1 and v6.8 nf_tables_api.c
nf_tables_fill_gen_info()/nf_tables_getgen(), plus UAPI nf_tables.h/netlink.h.
"""
import ast
import os
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_agentless_audit import SOURCE

# Compile only the actual production function. Never substitute a fixture
# implementation when the function is absent or its dependencies change.
tree = ast.parse(SOURCE)
functions = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name == "nft_ruleset_generation"]
assert len(functions) == 1, "The production audit must define exactly one generation reader"
namespace = {"os": os, "socket": socket, "struct": struct}
module = ast.Module(body=functions, type_ignores=[])
exec(compile(ast.fix_missing_locations(module), "production-nft-generation", "exec"), namespace)
HELPER = SimpleNamespace(nft_ruleset_generation=namespace["nft_ruleset_generation"])

PORT = 0x10203
SEQUENCE = 0x4030201
GENERATION = 0xa1b2c3d4


def attr(kind, value, padding=b"\0"):
    size = 4 + len(value)
    return struct.pack("=HH", size, kind) + value + padding * ((-size) & 3)


def reply(generation=GENERATION, attrs=None, kind=0x0a0f, flags=0, sequence=SEQUENCE, port=PORT, family=0, version=0, low=None):
    if attrs is None:
        attrs = (attr(1, struct.pack("!I", generation)) + attr(2, struct.pack("!I", 12345)) + attr(3, b"python3\0"))
    body = struct.pack("!BBH", family, version, generation & 0xffff if low is None else low) + attrs
    return struct.pack("=IHHII", 16 + len(body), kind, flags, sequence, port) + body


class Channel:
    def __init__(self, response, sender=(0, 0), flags=0, ancillary=(), fail=None, short_send=False):
        self.response, self.sender, self.flags, self.ancillary = response, sender, flags, ancillary
        self.fail, self.short_send = fail, short_send
        self.closed = False
        self.receive_count = 0

    def settimeout(self, value):
        assert value == 1.0

    def bind(self, value):
        assert value == (0, 0)

    def getsockname(self):
        return PORT, 0

    def sendto(self, request, destination):
        assert destination == (0, 0)
        assert struct.unpack("=IHHII", request[:16]) == (20, 0x0a10, 1, SEQUENCE, PORT)
        assert request[16:] == b"\0\0\0\0"
        if self.fail == "send":
            raise socket.timeout("bounded send timeout")
        return len(request) - int(self.short_send)

    def recvmsg(self, size):
        assert size == 4096
        self.receive_count += 1
        assert self.receive_count == 1, "Unexpected retry may shift the observation window"
        if self.fail == "timeout":
            raise socket.timeout("bounded receive timeout")
        if self.fail == "enobufs":
            raise OSError(105, "No buffer space available")
        return self.response, self.ancillary, self.flags, self.sender

    def close(self):
        self.closed = True
        if self.fail == "close":
            raise OSError("close failed")


class GenerationProtocolTests(unittest.TestCase):
    def observe(self, response=None, **options):
        channel = Channel(reply() if response is None else response, **options)
        with patch.object(socket, "socket", return_value=channel) as factory, \
                patch.object(os, "urandom", return_value=struct.pack("=I", SEQUENCE)):
            observed = HELPER.nft_ruleset_generation()
        factory.assert_called_once_with(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.assertTrue(channel.closed)
        return observed

    def test_real_newgen_shape_uses_big_endian_gen_and_nonzero_resource_low_bits(self):
        for generation in (1, 0x10000, GENERATION, 0xffffffff):
            with self.subTest(generation=generation):
                self.assertEqual(self.observe(reply(generation)), generation)

    def test_well_formed_extra_attributes_and_explicit_network_order_flag_are_safe(self):
        for kind in (1, 0x4001):
            attrs = attr(42, b"opaque") + attr(kind, struct.pack("!I", GENERATION))
            self.assertEqual(self.observe(reply(attrs=attrs)), GENERATION)

    def test_zero_or_internally_inconsistent_generation_is_rejected(self):
        for data in (reply(0), reply(low=0), reply(family=2), reply(version=1)):
            with self.subTest(data=data.hex()):
                self.assertIsNone(self.observe(data))

    def test_kernel_sender_request_sequence_and_bound_port_all_must_match(self):
        for data, sender in ((reply(), (123, 0)), (reply(), (0, 1)), (reply(sequence=SEQUENCE + 1), (0, 0)),
                             (reply(port=0), (0, 0)), (reply(port=PORT + 1), (0, 0))):
            with self.subTest(sender=sender, header=data[:16].hex()):
                self.assertIsNone(self.observe(data, sender=sender))

    def test_multipart_done_ack_error_and_overrun_are_not_single_getgen_answers(self):
        controls = [reply(flags=2), reply(flags=16), reply(kind=0x0a10), reply(kind=3), reply(kind=4)]
        for error in (0, -1, -95):
            # NLMSG_ERROR has a signed native-endian errno then the original
            # request header. Success ACK still contains no generation proof.
            payload = struct.pack("=iIHHII", error, 20, 0x0a10, 1, SEQUENCE, PORT)
            controls.append(struct.pack("=IHHII", 16 + len(payload), 2, 0, SEQUENCE, PORT) + payload)
        done = struct.pack("=IHHII", 16, 3, 0, SEQUENCE, PORT)
        controls.append(reply() + done)
        for data in controls:
            with self.subTest(header=data[:16].hex()):
                self.assertIsNone(self.observe(data))

    def test_truncation_control_messages_and_datagram_tail_fail_closed(self):
        for data in (b"", reply()[:15], reply()[:19], reply()[:-1], reply() + b"\0", reply() + b"\0" * 4):
            with self.subTest(length=len(data)):
                self.assertIsNone(self.observe(data))
        self.assertIsNone(self.observe(flags=socket.MSG_TRUNC))
        self.assertIsNone(self.observe(ancillary=[(1, 1, b"unexpected")]))

    def test_malformed_duplicate_missing_nested_or_mis_sized_generation_attributes_fail(self):
        encoded = struct.pack("!I", GENERATION)
        for attrs in (
            b"", b"\0", struct.pack("=HH", 3, 1), struct.pack("=HH", 9, 1) + encoded,
            attr(1, encoded[:-1]), attr(1, encoded + b"x"), attr(0x8001, encoded),
            attr(1, encoded) + attr(1, encoded), attr(1, encoded) + attr(0x4001, encoded),
            attr(42, b"x", padding=b"x") + attr(1, encoded),
        ):
            with self.subTest(attrs=attrs.hex()):
                self.assertIsNone(self.observe(reply(attrs=attrs)))

    def test_send_receive_timeout_buffer_loss_and_short_send_do_not_retry(self):
        for fail in ("send", "timeout", "enobufs"):
            with self.subTest(fail=fail):
                self.assertIsNone(self.observe(fail=fail))
        self.assertIsNone(self.observe(short_send=True))
        self.assertEqual(self.observe(fail="close"), GENERATION)


if __name__ == "__main__":
    unittest.main()

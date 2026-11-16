"""Local IPv4 listening-socket inventory, deliberately separate from TCP probes."""
import ctypes
import ipaddress
import socket
import struct
import sys


def listener_ports(target):
    ip = ipaddress.ip_address(target)
    if ip.version != 4 or not ip.is_loopback:
        raise ValueError('Local inventory requires an IPv4 loopback address, such as 127.0.0.1. Use Start scan for other targets.')
    wanted = {str(ip), '0.0.0.0'}
    result = set()
    if sys.platform == 'win32':
        # MIB_TCPROW: five 32-bit DWORDs, table starts with its DWORD count.
        api = ctypes.WinDLL('iphlpapi').GetTcpTable
        api.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int]
        api.restype = ctypes.c_uint32
        size = ctypes.c_uint32(0)
        code = api(None, ctypes.byref(size), False)
        if code not in (0, 122):
            raise OSError(code, 'Cannot size Windows TCP table')
        for _ in range(4):
            buffer = ctypes.create_string_buffer(size.value)
            code = api(buffer, ctypes.byref(size), False)
            if code == 122:
                continue  # The socket table grew between calls.
            if code:
                raise OSError(code, 'Cannot read Windows TCP table')
            raw = buffer.raw
            count = struct.unpack_from('<I', raw)[0]
            for offset in range(4, 4 + count * 20, 20):
                state, addr, port, _, _ = struct.unpack_from('<5I', raw, offset)
                address = socket.inet_ntoa(struct.pack('<I', addr))
                if state == 2 and address in wanted:
                    result.add(socket.ntohs(port & 65535))
            return result
        raise OSError('Windows TCP table kept changing; try again')
    if sys.platform.startswith('linux'):
        # This is the current network namespace's IPv4 table.
        with open('/proc/net/tcp', encoding='ascii') as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                address, port = fields[1].split(':')
                address = socket.inet_ntoa(bytes.fromhex(address)[::-1])
                if fields[3] == '0A' and address in wanted:
                    result.add(int(port, 16))
        return result
    raise OSError('Local inventory supports Windows and Linux only')


def inventory(target, ports, timeout, stop, events):
    try:
        if stop.is_set():
            return
        found = listener_ports(target) & set(ports)
        for port in sorted(found):
            if stop.is_set():
                return
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = 'Unknown'
            events.put(('open', (port, service, None)))
        events.put(('progress', len(ports)))
    except (OSError, ValueError) as exc:
        events.put(('error', str(exc)))
    finally:
        events.put(('done', stop.is_set()))

"""Loopback-only TCP/UDP/TLS interoperability with programs in a real MinUX guest."""
from pathlib import Path
import argparse
import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root', type=Path, required=True)
    parser.add_argument('--native-libraries', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, help='optional private kernel staged only into the copied image')
    parser.add_argument('--work', type=Path, default=ROOT/'build/minux-network-check')
    parser.add_argument('--program', type=Path, default=ROOT/'build/minux_network')
    args = parser.parse_args()
    work = args.work.resolve()
    fixtures = work/'fixtures'
    fixtures.mkdir(parents=True, exist_ok=True)
    for name in ('server', 'untrusted'):
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(fixtures/(name+'.key')),'-out',str(fixtures/(name+'.crt')),
            '-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    der = ssl.PEM_cert_to_DER_cert((fixtures/'server.crt').read_text())
    (fixtures/'server.sha256').write_bytes(hashlib.sha256(der).digest())
    listeners = []
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_STREAM):
        sock = socket.socket(socket.AF_INET, kind)
        sock.bind(('127.0.0.1', 0))
        if kind == socket.SOCK_STREAM: sock.listen(8)
        sock.settimeout(360)
        listeners.append(sock)
    (fixtures/'ports.bin').write_bytes(struct.pack('<HHH',*[s.getsockname()[1] for s in listeners]))
    errors, results = [], []
    client_cases_done=threading.Event()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(fixtures/'server.crt', fixtures/'server.key')
    legacy=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    legacy.minimum_version=legacy.maximum_version=ssl.TLSVersion.TLSv1_2
    legacy.load_cert_chain(fixtures/'server.crt',fixtures/'server.key')
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));reverse_port=reserve.getsockname()[1]

    def tcp():
        with listeners[0].accept()[0] as client:
            client.settimeout(30)
            if client.recv(64) != b'tcp-ping': raise RuntimeError('TCP payload')
            client.sendall(b'tcp-pong')
        results.append('tcp')

    def udp():
        payload, peer = listeners[1].recvfrom(64)
        if payload != b'udp-ping': raise RuntimeError('UDP payload')
        listeners[1].sendto(b'udp-pong',peer)
        results.append('udp')

    def tls():
        for mode in range(6):
            raw = listeners[2].accept()[0]
            raw.settimeout(45)
            try:
                with (legacy if mode==1 else context).wrap_socket(raw, server_side=True) as client:
                    if mode in (2,3,5):
                        # Pin verification happens after the TLS handshake.
                        if client.recv(1): raise RuntimeError('rejected peer sent application data')
                    else:
                        received = bytearray()
                        while len(received) < 70000:
                            chunk = client.recv(min(16384,70000-len(received)))
                            if not chunk: raise RuntimeError('TLS truncated payload')
                            received.extend(chunk)
                        if received != b'Z'*70000: raise RuntimeError('TLS payload mismatch')
                        client.sendall(received)
                        results.append(f'tls-{mode}')
                        expected='TLSv1.2' if mode==1 else 'TLSv1.3'
                        if client.version()!=expected:raise RuntimeError(f'negotiated {client.version()}, expected {expected}')
            except (ssl.SSLError, ConnectionResetError) as error:
                if mode not in (2,3,5): raise
                results.append(f'rejected-{mode}')
            finally:
                raw.close()
        client_cases_done.set()

    def guard(callback):
        try: callback()
        except Exception as error: errors.append(repr(error))

    def reverse():
        if not client_cases_done.wait(timeout=360):raise RuntimeError('native clients did not finish')
        context=ssl.create_default_context(cafile=fixtures/'server.crt')
        deadline=time.monotonic()+360
        client=None
        while time.monotonic()<deadline:
            try:
                raw=socket.create_connection(('127.0.0.1',reverse_port),timeout=2)
                raw.settimeout(30)
                client=context.wrap_socket(raw,server_hostname='localhost')
                break
            except (OSError,ssl.SSLError):
                time.sleep(0.25)
        if client is None:raise RuntimeError('native MinUX TLS server never accepted')
        with client:
            if client.version()!='TLSv1.3':raise RuntimeError('native server did not negotiate TLS 1.3')
            client.sendall(b'Q'*70000)
            reply=bytearray()
            while len(reply)<70000:
                part=client.recv(70000-len(reply))
                if not part:raise RuntimeError('native server truncated response')
                reply.extend(part)
            if reply!=b'Q'*70000:raise RuntimeError('native server payload')
            results.append('native-server')

    workers = [threading.Thread(target=guard,args=(callback,),daemon=True) for callback in (tcp,udp,tls,reverse)]
    for worker in workers: worker.start()
    try:
        command = [sys.executable,str(ROOT/'tests/run_minux_guest.py'),
            '--minux-root',str(args.minux_root),'--native-libraries',str(args.native_libraries),
            '--fixtures',str(fixtures),'--forward-tcp',f'{reverse_port}:46544','--work',str(work/'guest'),'--timeout','360']
        if args.kernel:
            command += ['--kernel', str(args.kernel.resolve())]
        subprocess.run(command + [str(args.program)],check=True)
        for worker in workers: worker.join(timeout=2)
        if errors or any(worker.is_alive() for worker in workers):
            raise RuntimeError(f'host interoperability failed: {errors}, completed={results}')
        if not {'tcp','udp','tls-0','tls-1','tls-4','native-server'}.issubset(results):
            raise RuntimeError(f'incomplete interoperability: {results}')
        (work/'host-results.txt').write_text('\n'.join(results)+'\n')
        print('MinUX TCP/UDP, TLS 1.2/1.3, CA/hostname/pin acceptance and rejection passed')
    finally:
        for sock in listeners: sock.close()


if __name__ == '__main__': main()

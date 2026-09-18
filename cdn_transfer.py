# Understanding how a file actually moves: cdn.py splits it into numbered UDP
# chunks with a header, and bee.py reassembles them and detects missing,
# duplicate and out-of-order chunks. Normally these two ends are separated by a
# multicast socket; here I hand the packets straight from sender to receiver in
# one process so it runs on windows. The header format and the reassembly logic
# are copied from cdn.py and bee.py.

import hashlib
import struct

# --- packet header, copied verbatim from cdn.py ---
# session_id_int(4) file_index(4) seq_num(4) total_chunks(4) chunk_len(2)
CDN_HEADER = struct.Struct("!IIIIH")
CDN_HEADER_SIZE = CDN_HEADER.size  # 18 bytes
CDN_CHUNK_SIZE = 1400              # safe UDP payload, from cdn.py


def show(label, value):
    print(f"    {label:<24} {value}")


def session_id_int(session_id):
    # copied from cdn.py
    return int(hashlib.md5(session_id.encode()).hexdigest()[:8], 16) & 0xFFFFFFFF


# --- sender side: split a file into packets (cdn.send_file_multicast logic) ---
def make_packets(session_id, file_index, data):
    chunks = [data[i:i+CDN_CHUNK_SIZE] for i in range(0, len(data), CDN_CHUNK_SIZE)]
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    sid = session_id_int(session_id)
    packets = []
    for seq, chunk in enumerate(chunks):
        header = CDN_HEADER.pack(sid, file_index, seq, total, len(chunk))
        packets.append(header + chunk)
    return packets


# --- receiver side: reassemble + track drops (bee._cdn_receive_multicast logic) ---
class Reassembler:
    def __init__(self):
        self.buf = {}          # seq -> chunk
        self.total = None
        self.received = 0
        self.last_seq = -1
        self.dropped_suspected = 0
        self.out_of_order = 0

    def on_packet(self, packet):
        sid, file_index, seq, total, chunk_len = CDN_HEADER.unpack(packet[:CDN_HEADER_SIZE])
        chunk = packet[CDN_HEADER_SIZE:CDN_HEADER_SIZE + chunk_len]
        self.total = total
        if seq in self.buf:
            return  # duplicate, ignore (bee counts unique chunks only)
        self.buf[seq] = chunk
        self.received += 1
        # gap tracking, same rules as bee.py
        if seq > self.last_seq:
            if self.last_seq >= 0 and seq > self.last_seq + 1:
                self.dropped_suspected += (seq - self.last_seq - 1)
            self.last_seq = seq
        else:
            self.out_of_order += 1
            if self.dropped_suspected > 0:
                self.dropped_suspected -= 1

    def complete(self):
        return self.total is not None and len(self.buf) == self.total

    def rebuild(self):
        return b"".join(self.buf[i] for i in range(self.total))


def deliver(reasm, packets, label):
    for p in packets:
        reasm.on_packet(p)
    print(f"    {label}")
    show("chunks received:", f"{reasm.received}/{reasm.total}")
    show("suspected drops:", reasm.dropped_suspected)
    show("out-of-order:", reasm.out_of_order)
    show("complete:", reasm.complete())


def main():
    print("cdn segmentation + bee reassembly (cdn.py + bee.py logic, no socket)\n")

    session_id = "abc123"
    # a file big enough to need several chunks
    data = b"EBW firmware payload. " * 200   # ~4400 bytes -> 4 chunks
    original_sha = hashlib.sha256(data).hexdigest()
    print(f"setup: file is {len(data)} bytes, chunk size {CDN_CHUNK_SIZE}\n")

    print("1. sender splits the file into numbered packets")
    packets = make_packets(session_id, 0, data)
    show("packets made:", len(packets))
    show("each header:", f"{CDN_HEADER_SIZE} bytes (session, file#, seq, total, len)")

    print("\n2. clean delivery: all packets arrive in order")
    r1 = Reassembler()
    deliver(r1, packets, "delivered all packets in order")
    rebuilt = r1.rebuild()
    show("sha256 matches original:", hashlib.sha256(rebuilt).hexdigest() == original_sha)

    print("\n3. lossy delivery: drop packet #2, then it arrives late")
    r2 = Reassembler()
    reordered = [p for i, p in enumerate(packets) if i != 2]  # 0,1,3,...
    for p in reordered:
        r2.on_packet(p)
    show("after gap - suspected drops:", r2.dropped_suspected)
    r2.on_packet(packets[2])   # the missing one arrives late
    show("after late arrival - suspected:", r2.dropped_suspected)
    show("out-of-order counted:", r2.out_of_order)
    show("complete:", r2.complete())
    show("sha256 matches:", hashlib.sha256(r2.rebuild()).hexdigest() == original_sha)
    print("    ^ a late packet fills the gap; the drop was suspected, not confirmed")

    print("\n4. duplicate delivery: same packet twice is ignored")
    r3 = Reassembler()
    for p in packets:
        r3.on_packet(p)
    before = r3.received
    r3.on_packet(packets[0])   # duplicate
    show("received before dup:", before)
    show("received after dup:", r3.received)
    print("    ^ duplicates don't inflate the count; only unique chunks are kept")

    print("\ndone. sender segments with a header, receiver reassembles and tracks drops/reordering.")


if __name__ == "__main__":
    main()

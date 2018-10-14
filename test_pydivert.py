import pydivert
import scapy.all as sp

# construct a scapy icmp unreachable pkt from pydivert pkt
def get_icmp_unreachable_pkt (pkt):
    p = None
    icmp = None
    if pkt.ipv4:
        p = sp.IP(dst = pkt.src_addr, src = pkt.dst_addr)
        icmp = sp.ICMP()
        # ICMP type=3 code=3 port Unreachable
        icmp.type = 3
        icmp.code = 3
    else:
        p = sp.IPv6(dst = pkt.src_addr, src = pkt.dst_addr)
        icmp = sp.ICMPv6DestUnreach()
        # ICMP type=1 code=4 port Unreachable
        icmp.type = 1
        icmp.code = 4

    if pkt.ip.packet_len >= 64:
        return p/icmp/(bytes(pkt.raw)[0:64])
    else:
        return p/icmp/(bytes(pkt.raw))

# construct a scapy rst packet from pydivert pkt
def get_rstpkt(pkt):
    fake_pkt = None
    if (pkt.ipv4):
        fake_pkt = sp.IP(dst=pkt.src_addr, src=pkt.dst_addr) / sp.TCP(dport=pkt.src_port, sport=pkt.dst_port)
    else:
        fake_pkt = sp.IPv6(dst=pkt.src_addr, src=pkt.dst_addr) / sp.TCP(dport=pkt.src_port, sport=pkt.dst_port)

    fake_pkt[sp.TCP].flags = 'AR'
    fake_pkt[sp.TCP].ack = pkt.tcp.seq_num + 1
    fake_pkt[sp.TCP].seq = pkt.tcp.ack_num + 1
    fake_pkt[sp.TCP].window = 0
    return fake_pkt


if __name__ == "__main__":
    print("start")
    pktdump = sp.PcapWriter("test.pcap", append=True, sync=True)
    with pydivert.WinDivert("inbound and (tcp.DstPort == 5000 or udp.DstPort == 5000)") as w:
        for pkt in w:
            print(pkt)

            # dump received packet
            if pkt.ipv4:
                pktdump.write(sp.Ether() / sp.IP(bytes(pkt.raw)))
            else:
                pktdump.write(sp.Ether() / sp.IPv6(bytes(pkt.raw)))

            # send rst for tcp packet
            if (pkt.tcp):
                rst_pkt = get_rstpkt(pkt)
                pktdump.write(sp.Ether() / rst_pkt)
                opkt = pydivert.Packet(sp.raw(rst_pkt), pkt.interface, pydivert.Direction.OUTBOUND)
                print(opkt)
                w.send(opkt)

            # send icmp unreachable to icmp packet
            elif (pkt.udp):
                icmp_pkt = get_icmp_unreachable_pkt(pkt)
                pktdump.write(sp.Ether() / icmp_pkt)
                opkt = pydivert.Packet(sp.raw(icmp_pkt), pkt.interface, pydivert.Direction.OUTBOUND)
                print(opkt)
                w.send(opkt)

            else:
                w.send(pkt)



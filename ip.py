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

        values = read_ipv4_header(datagrama)
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
        ) = values

        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            ttl -= 1
            if ttl > 0:
                next_hop = self._next_hop(dst_addr)
                datagrama = self.criar_datagrama(payload, dst_addr, datagrama)
            else:
                # Criar Mudar o cabeçario 
                values = struct.unpack('!BBHHHBBHII', datagrama[:20])
                values = [*values]

                next_hop = self._next_hop(src_addr)

                (dst_addr, ) = struct.unpack('!I', str2addr(src_addr))
                (src_addr, ) = struct.unpack('!I', str2addr(self.meu_endereco))

                values[5] = 64
                values[6] = 1
                values[7] = 0
                values[8] = src_addr
                values[9] = dst_addr

                ihl = values[0] & 0xF
                tam = 4 * (ihl) + 8

                icmp_header = struct.pack(
                    '!BBHI', 11, 0, 0, 0 
                ) + (datagrama[:tam])

                checksum = calc_checksum(icmp_header)

                icmp_header = struct.pack(
                    '!BBHI', 11, 0, checksum, 0
                ) + (datagrama[:tam])

                values[2] = 20 + len(icmp_header)

                datagrama = self.criar_datagrama(icmp_header, src_addr, values, values)
                

            self.enlace.enviar(datagrama, next_hop)


    def _next_hop(self, dest_addr):
        (destino, ) = struct.unpack('!I', str2addr(dest_addr))
        possiveis_destinos = []

        for cidr, next_hop in self.tabela:
            cidr, n = cidr.split('/')
            (cidr, ) = struct.unpack('!I', str2addr(cidr))
            n = 32 - int(n)
            cidr = cidr >> n << n
            possivel_destino = destino >> n << n
            if possivel_destino == cidr:
                possiveis_destinos.append((n, next_hop))

        if possiveis_destinos:
            return min(possiveis_destinos)[1]
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

    def enviar(self, segmento, dst_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dst_addr)
        datagrama = self.criar_datagrama(segmento, dst_addr)

        self.enlace.enviar(datagrama, next_hop)

    def criar_datagrama(self, segmento, dst_addr, datagrama=None, icmp=None):
        ipv4 = self.criar_ipv4(segmento, dst_addr, datagrama, icmp)
        ip_header = self.calculo_ip_header(ipv4)
        return ip_header + segmento

    def criar_ipv4(self, segmento, dst_addr, datagrama=None, icmp=None):
        """
        Cria o ipv4 com os campos versão, IHL, DSCP, ECN, tamanho total, identificação,
        flags, fragmento, ttl, protocolo, header checksum, ip de saida e ip de destino.
        """
        if datagrama:
            if icmp:
                return icmp

            [*values] = struct.unpack('!BBHHHBBHII', datagrama[:20])
            values[5] -= 1
            values[7] = 0
            return values

        id = self.id
        self.id += 1

        src_ip = str2addr(self.meu_endereco)
        (src_ip,) = struct.unpack('!I', src_ip)

        dst_ip = str2addr(dst_addr)
        (dst_ip,) = struct.unpack('!I', dst_ip)

        return [
            0x45,
            0,
            20 + len(segmento),
            id,
            0,
            64,
            6,
            0,
            src_ip,
            dst_ip,
        ]

    def calculo_ip_header(self, ipv4):
        ip_header = struct.pack('!BBHHHBBHII', *ipv4)
        header_checksum = calc_checksum(ip_header)

        ipv4[7] = header_checksum
        ip_header = struct.pack('!BBHHHBBHII', *ipv4)

        return ip_header




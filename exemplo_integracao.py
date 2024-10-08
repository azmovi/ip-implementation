#!/usr/bin/env python3
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexões TCP que o seu programa estiver tratando:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP


# Este é um exemplo de um programa que faz eco, ou seja, envia de volta para
# o cliente tudo que for recebido em uma conexão.

import asyncio
from camadaenlace import CamadaEnlaceLinux
from tcp import Servidor   # copie o arquivo do Trabalho 2
from ip import IP


def dados_recebidos(conexao, dados):
    if dados == b'':
        conexao.fechar()
    else:
        conexao.enviar(dados)   # envia de volta


def conexao_aceita(conexao):
    conexao.registrar_recebedor(
        dados_recebidos
    )   # usa esse mesmo recebedor para toda conexão aceita


enlace = CamadaEnlaceLinux()
rede = IP(enlace)
rede.definir_endereco_host(
    '192.168.88.231'
)  # altere para o endereço IP da sua máquina, consulte-o com o comando: ip addr
rede.definir_tabela_encaminhamento(
    [
        (
            '192.168.88.231/32',
            '192.168.88.231',
        ),  # altere aqui também para o endereço da sua máquina (sua máquina permite alcançar a si mesma)
        (
            '0.0.0.0/0',
            '192.168.88.1',
        ),  # consulte sua rota padrão com o comando: ip route | grep default
    ]
)
servidor = Servidor(rede, 7000)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)
asyncio.get_event_loop().run_forever()

# IMPORTANTE: Para conectar ao servidor (por exemplo com o nc), você não vai mais usar o endereço localhost nem 127.0.0.1.
# A partir de agora você vai usar o mesmo endereço que passou para rede.definir_endereco_host (acima).

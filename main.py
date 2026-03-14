"""
main.py
=======
Interface CLI do NetGuard IDS.

Uso:
    sudo python main.py
    sudo python main.py -i eth0 -f "not port 22"
    sudo python main.py --listar
"""

import argparse
import sys
import time
import signal


def parse_args():
    parser = argparse.ArgumentParser(
        prog="netguard-ids",
        description="NetGuard IDS — Sistema de Detecção de Intrusões",
    )
    parser.add_argument("-i", "--interface", default="", help="Interface de rede")
    parser.add_argument("-f", "--filtro", default="", help="Filtro BPF", metavar="BPF")
    parser.add_argument("-t", "--tempo", type=int, default=0, help="Duração em segundos (0 = até Ctrl+C)")
    parser.add_argument("--listar", action="store_true", help="Lista interfaces e sai")
    parser.add_argument("--quiet", action="store_true", help="Suprime output de pacotes, mostra só alertas")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.listar:
        try:
            from scapy.all import get_if_list
            print("\nInterfaces disponíveis:")
            for i in get_if_list():
                print(f"  • {i}")
            print()
        except Exception as e:
            print(f"Erro: {e}")
        sys.exit(0)

    print(r"""
  _   _      _    ____                     _   ___ ____  ____
 | \ | | ___| |_ / ___|_   _  __ _ _ __ __| | |_ _|  _ \/ ___|
 |  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` |  | || | | \___ \
 | |\  |  __/ |_| |_| | |_| | (_| | | | (_| |  | || |_| |___) |
 |_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_| |___|____/|____/

   Sistema de Detecção de Intrusões v1.0.0
   Execute com sudo. Pressione Ctrl+C para parar.
    """)

    from ids_engine import IDSEngine
    from alert_logger import AlertLogger

    logger = AlertLogger()

    def on_alerta(alerta):
        logger.registrar(alerta)

    ids = IDSEngine(
        interface=args.interface,
        filtro_bpf=args.filtro,
        verbose=True,
        callback_alerta=on_alerta,
    )

    estado = ids.iniciar()

    def parar(sig, frame):
        print("\n\n[*] Encerrando IDS...")
        ids.parar()
        print(f"\n  Total pacotes analisados : {estado.total_pacotes:,}")
        print(f"  Total alertas gerados    : {estado.total_alertas}")
        for sev, cnt in estado.por_severidade.items():
            if cnt > 0:
                print(f"    {sev:<10}: {cnt}")
        print(f"\n  Log salvo em: {logger.arquivo_log}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT, parar)

    inicio = time.time()
    try:
        while ids.esta_ativo():
            time.sleep(1)
            if args.tempo and (time.time() - inicio) >= args.tempo:
                print(f"\n[*] Tempo limite atingido.")
                break
    finally:
        ids.parar()
        print(f"\n  Pacotes: {estado.total_pacotes} | Alertas: {estado.total_alertas}")


if __name__ == "__main__":
    main()
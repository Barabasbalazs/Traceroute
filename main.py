# Barabás Balázs, 531/1 csoport, Lab2 Traceroute házi
import argparse
from scapy.all import IP, sr1, ICMP
from socket import gethostbyaddr


def get_and_parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target_name", help = "Target hostname or IP address")
    parser.add_argument("-m", help = "Maximum number of hops to search for target", type = int, default = 15)
    parser.add_argument("-w", help = "Wait timeout milliseconds for each reply.", type = int, default = 100)
    return parser.parse_args()


def send_package(target_name, timeout_max, hops_max):
    for i in range(hops_max):
        pingr = IP(dst = target_name, ttl = i) / ICMP(id = i)
        reply = sr1(pingr, timeout = timeout_max / 1000 , verbose = 0)
        for rcv in reply:
            timestamp = rcv.time - pingr.sent_time
            try:
                hostname = gethostbyaddr(rcv.src)[0]
            except:
                hostname = ""
            print("{}. {} ms {} ({})".format(i + 1, timestamp * 100 ,rcv.src, hostname))
            if rcv.type == 0:
                print("Reached destination at {}".format(rcv.src))
                return


if __name__ == "__main__":
    args = get_and_parse_args()
    target_name = args.target_name
    hops_max = args.m
    timeout_max = args.w
    print("Tracing route to {} over a maximum of {} hops.\n".format(target_name, hops_max))
    send_package(target_name, timeout_max, hops_max)
    
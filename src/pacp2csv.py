#!/usr/bin/env python3

# 处理指定目录中的所有PCAP文件：

# python3 pacp2csv.py -d /path/to/pcap_directory
# 处理一个或多个指定的PCAP文件：

# python3 pacp2csv.py -f /path/to/file1.pcap /path/to/file2.pcap
# 指定捕获持续时间（秒）：

# python3 pacp2csv.py -f /path/to/file.pcap -t 3600

import paramiko
from scapy.all import rdpcap
from collections import defaultdict
import csv
import logging
import json
import os
import argparse

# ==============================
# 配置和变量定义
# ==============================

# 设置日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SSH连接信息
vxm_ip = "20.13.4.200"
ssh_port = 22
ssh_user = "root"
ssh_password = "Testvxrail123!"

# 其他IP地址
vc_ip = "20.13.111.166"
esxi_ips = {"20.13.4.101", "20.13.4.102", "20.13.4.103", "20.13.4.104"}
single_node_ip = "20.13.4.66"

# 默认捕获时间，可根据实际情况修改或通过命令行参数传入
capture_duration = 3600  # 秒

# ==============================
# 获取Pod和IP地址的映射
# ==============================

def get_pod_ip_mapping():
    pod_ip_mapping = {}
    try:
        # 创建 SSH 客户端
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vxm_ip, port=ssh_port, username=ssh_user, password=ssh_password)
        logging.info("SSH连接已建立。")

        # 执行 kubectl 命令，获取JSON格式的输出
        stdin, stdout, stderr = ssh.exec_command("kubectl get pods --all-namespaces -o json")
        output = stdout.read()
        ssh.close()

        # 解析 JSON 输出
        pods = json.loads(output)

        for item in pods['items']:
            pod_name = item['metadata']['name']
            pod_ip = item['status'].get('podIP')
            if pod_ip:
                pod_ip_mapping[pod_ip] = pod_name
                logging.debug(f"映射Pod {pod_name} 到 IP {pod_ip}")

    except Exception as e:
        logging.error(f"获取Pod IP映射时出错: {e}")

    return pod_ip_mapping

# ==============================
# 处理单个PCAP文件的函数
# ==============================

def process_pcap_file(pcap_file, pod_ip_mapping):
    # 从PCAP文件名中提取IP地址
    pcap_filename = os.path.basename(pcap_file)
    ip_in_filename = pcap_filename.split('_')[0:4]  # 假设IP地址是文件名的前四部分
    ip_in_filename = '.'.join(ip_in_filename)
    logging.info(f"正在处理文件: {pcap_filename}")
    logging.info(f"从文件名中提取的IP地址: {ip_in_filename}")

    # 判断是否需要使用Pod IP映射
    if ip_in_filename == vxm_ip:
        need_pod_mapping = True
        logging.info("PCAP文件来自VXM，将使用Pod IP映射。")
    elif ip_in_filename == vc_ip:
        need_pod_mapping = False
        logging.info("PCAP文件来自VC，不使用Pod IP映射。")
    else:
        need_pod_mapping = False
        logging.warning("文件名中的IP不匹配VXM或VC IP，将不使用Pod IP映射。")

    # 读取PCAP文件
    logging.info("读取PCAP文件...")
    packets = rdpcap(pcap_file)

    # 初始化字典来存储流量信息
    traffic_stats = defaultdict(lambda: {'packets': 0, 'size': 0})

    # 定义所有感兴趣的IP地址
    interested_ips = set()
    if need_pod_mapping and pod_ip_mapping:
        interested_ips = set(pod_ip_mapping.keys())
    interested_ips = interested_ips.union({vxm_ip, vc_ip}).union(esxi_ips)
    if single_node_ip:
        interested_ips.add(single_node_ip)
    logging.info(f"感兴趣的IP地址: {interested_ips}")

    # 特殊处理ESXi的IP，归类为 clusternodes
    clusternodes_ips = esxi_ips

    # 遍历数据包
    logging.info("处理数据包...")
    for packet in packets:
        if packet.haslayer('IP'):
            src = packet['IP'].src
            dst = packet['IP'].dst

            # 初始化名称
            src_name = None
            dst_name = None

            # 优先匹配特定的 IP 地址
            if src == vxm_ip:
                src_name = "vxm"
            elif src == vc_ip:
                src_name = "vc"
            elif src in clusternodes_ips or src == single_node_ip:
                src_name = "clusternodes"
            elif need_pod_mapping and src in pod_ip_mapping:
                # 从 pod_ip_mapping 中获取 Pod 名称
                src_name = pod_ip_mapping.get(src, "others")
            else:
                src_name = "others"

            if dst == vxm_ip:
                dst_name = "vxm"
            elif dst == vc_ip:
                dst_name = "vc"
            elif dst in clusternodes_ips or dst == single_node_ip:
                dst_name = "clusternodes"
            elif need_pod_mapping and dst in pod_ip_mapping:
                dst_name = pod_ip_mapping.get(dst, "others")
            else:
                dst_name = "others"

            direction = f"{src_name}->{dst_name}"

            # 更新统计信息
            traffic_stats[direction]['packets'] += 1
            traffic_stats[direction]['size'] += len(packet)

    logging.info("数据包处理完成。计算带宽...")

    # 计算带宽，并保留4位小数
    for direction, stats in traffic_stats.items():
        stats['bandwidth'] = round((stats['size'] * 8) / (capture_duration * 1000), 4)  # 转换为Kbps
        logging.debug(f"方向: {direction}, 包数: {stats['packets']}, 大小: {stats['size']}, 带宽: {stats['bandwidth']} Kbps")

    # 将统计信息按方向排序
    sorted_traffic_stats = dict(sorted(traffic_stats.items()))

    # 生成输出文件名，与 PCAP 文件名一致，替换后缀为 .csv，并保存在文件所在目录
    pcap_directory = os.path.dirname(pcap_file)
    pcap_filename = os.path.basename(pcap_file)
    output_filename = os.path.splitext(pcap_filename)[0] + '.csv'
    output_filepath = os.path.join(pcap_directory, output_filename)

    # 写入CSV文件
    logging.info(f"将结果写入CSV文件 {output_filepath}...")
    with open(output_filepath, 'w', newline='') as csvfile:
        fieldnames = ['Direction', 'Packets Number', 'Total Size(Bytes)', 'Bandwidth(Kbps)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for direction, stats in sorted_traffic_stats.items():
            writer.writerow({
                'Direction': direction,
                'Packets Number': stats['packets'],
                'Total Size(Bytes)': stats['size'],
                'Bandwidth(Kbps)': stats['bandwidth']
            })

    logging.info(f"CSV文件 {output_filename} 生成成功，保存在 {pcap_directory}。")

# ==============================
# 主程序入口
# ==============================

if __name__ == "__main__":
    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description='处理PCAP文件并输出CSV统计信息。')
    parser.add_argument('-d', '--directory', help='包含PCAP文件的目录。')
    parser.add_argument('-f', '--files', nargs='+', help='要处理的一个或多个PCAP文件。')
    parser.add_argument('-t', '--duration', type=int, default=3600, help='捕获持续时间（秒）。默认为3600秒。')
    args = parser.parse_args()

    # 更新捕获持续时间
    capture_duration = args.duration

    # 检查用户是否提供了目录或文件
    if args.directory:
        # 检查目录是否存在
        if not os.path.isdir(args.directory):
            logging.error(f"目录 {args.directory} 不存在。")
            exit(1)
        # 获取目录中的所有 .pcap 文件
        pcap_files = [os.path.join(args.directory, f) for f in os.listdir(args.directory) if f.endswith('.pcap')]
        if not pcap_files:
            logging.error(f"目录 {args.directory} 中未找到PCAP文件。")
            exit(1)
        logging.info(f"在目录 {args.directory} 中找到 {len(pcap_files)} 个PCAP文件。")
    elif args.files:
        # 检查指定的文件是否存在
        pcap_files = []
        for file in args.files:
            if os.path.isfile(file):
                pcap_files.append(file)
            else:
                logging.error(f"文件 {file} 不存在。")
        if not pcap_files:
            logging.error("未找到有效的PCAP文件。")
            exit(1)
        logging.info(f"将处理指定的 {len(pcap_files)} 个PCAP文件。")
    else:
        logging.error("必须指定目录 (-d) 或文件 (-f) 参数。")
        exit(1)

    # 创建一个字典来缓存已经获取的 Pod IP 映射
    pod_ip_mapping_cache = {}

    # 处理每个PCAP文件
    for pcap_file in pcap_files:
        try:
            # 从PCAP文件名中提取IP地址
            pcap_filename = os.path.basename(pcap_file)
            ip_in_filename = pcap_filename.split('_')[0:4]  # 假设IP地址是文件名的前四部分
            ip_in_filename = '.'.join(ip_in_filename)

            # 判断是否需要获取Pod IP映射
            need_pod_mapping = False
            if ip_in_filename == vxm_ip:
                need_pod_mapping = True
                logging.info(f"文件 {pcap_filename} 来自VXM，将使用Pod IP映射。")

                # 检查缓存中是否已有Pod IP映射
                if 'vxm' in pod_ip_mapping_cache:
                    pod_ip_mapping = pod_ip_mapping_cache['vxm']
                    logging.info("使用缓存的Pod IP映射。")
                else:
                    # 获取Pod IP映射并缓存
                    pod_ip_mapping = get_pod_ip_mapping()
                    pod_ip_mapping_cache['vxm'] = pod_ip_mapping
                    logging.info(f"获取到 {len(pod_ip_mapping)} 条Pod IP映射，并已缓存。")
            else:
                need_pod_mapping = False
                pod_ip_mapping = {}
                logging.info(f"文件 {pcap_filename} 不需要Pod IP映射。")

            # 处理PCAP文件
            process_pcap_file(pcap_file, pod_ip_mapping)

        except Exception as e:
            logging.error(f"处理文件 {pcap_file} 时出错: {e}")
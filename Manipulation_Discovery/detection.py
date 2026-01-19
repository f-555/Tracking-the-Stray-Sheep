import json
import networkx as nx
import matplotlib.pyplot as plt
import whois
import geoip2.database
import tldextract
import difflib
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import plotly.graph_objects as go
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import MinMaxScaler
from sklearn.manifold import MDS
from sklearn.cluster import DBSCAN
import sys
import ipaddress
from collections import deque
import os
import subprocess
import requests
import time

org_dic = {}
org_ip = {}

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False 

def arin_rdap_query(ip):
    url = f'https://rdap.arin.net/registry/ip/{ip}'
    headers = {
        'User-Agent': 'YourAppName/1.0 (your.email@example.com)'
    }
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    else:
        raise Exception(f'ARIN RDAP query failed: HTTP {resp.status_code}')

def parse_arin_rdap(data):
    asn = None
    asn_list = data.get('arin_originas0_originautnums', [])
    if asn_list:
        asn = asn_list[0]
    
    # 2. 组织名提取（entities -> vcardArray -> fn）
    org = None
    if 'entities' in data:
        for ent in data['entities']:
            vcard = ent.get('vcardArray', [])
            if vcard and len(vcard) > 1:
                props = vcard[1]
                for item in props:
                    if len(item) >= 3 and item[0].lower() == 'fn':
                        org = item[3]
                        if org:
                            return asn, org  

    return asn, org

def whois_IP(ip):
    data = arin_rdap_query(ip)
    asn, org = parse_arin_rdap(data)
    return [asn,org]

def load_whois_ip(file = './lab/iporg_database.txt'):
    f = open(file,'r')
    lines = f.readlines()
    f.close()
    for line in lines:
        line_sp = line[:-1].split(':')
        ip = line_sp[0]
        ASN = line_sp[1].split(',')[0]
        org = line_sp[1].split(',')[1]
        org_ip[ip] = [ASN,org]

def load_whois(file = './lab/org_database.txt'):
    f = open(file,'r')
    lines = f.readlines()
    f.close()
    for line in lines:
        line_sp = line[:-1].split(':')
        domain = line_sp[0]
        org = line_sp[1]
        org_dic[domain] = org

def path_structural_distance(G_tmp, path1, path2, sp):
    distances = []
    for u in path1[1:-1]:
        for v in path2[1:-1]:
            if u == v or v in path1:
                distances.append(0)
                continue
            try:
                #d = nx.shortest_path_length(G_tmp, source=u, target=v)
                d = sp.get(u, {}).get(v, 10)
                distances.append(d)
            except nx.NetworkXNoPath:
                distances.append(16)  
    #meandis1 = sum(distances) / len(distances)

    for u in path2[1:-1]:
        for v in path1[1:-1]:
            if u == v or v in path2:
                distances.append(0)
                continue
            try:
                #d = nx.shortest_path_length(G_tmp, source=u, target=v)
                d = sp.get(u, {}).get(v, 10)
                distances.append(d)
            except nx.NetworkXNoPath:
                distances.append(10)  
    #meandis2 = sum(distances) / len(distances)
    if not distances:
        return 10
    #print(distances)
    #return round((sum(distances))/(len(distances)*len(distances)), 3)  
    return round(sum(distances)/(2*(min(len(path1),len(path2))-2)), 3)  

def path_distance_matrix(G, mainpath_counts):
    #paths = get_main_paths(G)
    #print(paths)
    paths = []
    for key in mainpath_counts:
        paths.append(key.split(' → '))
    n = len(paths)
    matrix = [[0]*n for _ in range(n)]

    G_tmp = G.copy()
    start_node = [n for n, attrs in G.nodes(data=True) if attrs.get("type") == "start"]
    G_tmp.remove_node('end')
    G_tmp.remove_node(start_node[0])
    sp = dict(nx.all_pairs_shortest_path_length(G_tmp))

    for i in range(n):
        for j in range(i,n):
            if i == j:
                continue
            matrix[i][j] = path_structural_distance(G, paths[i], paths[j], sp)
            matrix[j][i] = matrix[i][j]
            #max_len = max(max_len,matrix[i][j])
            #min_len = min(min_len,matrix[i][j])
                
    return matrix, paths

def split_domain(domain):
    parts = domain.strip().lower().split('.')
    if len(parts) >= 3:
        subdomains = parts[:-2]
        return subdomains, parts[-2], parts[-1]  
    elif len(parts) == 2:
        return [], parts[0], parts[1]
    else:
        return [], parts[0], '' 

def list_similarity(list1, list2):
    sm = difflib.SequenceMatcher(None, '.'.join(list1), '.'.join(list2))
    base_score = sm.ratio()
    depth_penalty = 1.0 - abs(len(list1) - len(list2)) * 0.4  
    return max(0.0, base_score * depth_penalty)

def compare_domain(domain1, domain2):
    sub1, main1, tld1 = split_domain(domain1)
    sub2, main2, tld2 = split_domain(domain2)
    sub_score = list_similarity(sub1, sub2)
    main_score = difflib.SequenceMatcher(None, main1, main2).ratio()
    tld_score = 1.0 if tld1 == tld2 else 0.0
    total_score = 0.4 * main_score + 0.2 * sub_score + 0.4 * tld_score
    return round(total_score, 3)

def extract_domain(domain):
    try:
        extracted = tldextract.extract(domain)
        if not extracted.suffix:
            return extracted.domain  # 如果没有后缀，只返回主域名
        return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        return domain

def check_asn(ip):
    line_new = ''
    #print(ip)
    with geoip2.database.Reader(f'./lab/GeoLite2-ASN.mmdb') as reader:
        try:
            response = reader.asn(ip)
            line_new = [str(response.autonomous_system_number),str(response.autonomous_system_organization)]
        except:
            line_new = ['None','None']
    if line_new == ['None','None']:
        try:
            if is_private_ip(ip):
                return ['None','None']
            if ip in org_ip.keys():
                return org_ip[ip]
            line_new = whois_IP(ip)
            org_ip[ip] = line_new
            w = open('./lab/iporg_database.txt','a+')
            w.write(f'{ip}:{line_new[0]},{line_new[1]}\n')
            w.close()
        except:
            pass
    return line_new

def check_org(domain):
    e_domain = extract_domain(domain)
    if e_domain in org_dic.keys():
        return org_dic[e_domain]
    #print(e_domain)

    if domain[-6:] == 'gov.cn':
        org_dic[e_domain] = 'Gov'
        return 'Gov'
    try:
        domain_info = whois.whois(domain)
        if type(domain_info.org) is list:
            org_dic[e_domain] = domain_info.org[0]
        else:
            org_dic[e_domain] = domain_info.org
        w = open('./lab/org_database.txt','a+')
        w.write(f'{e_domain}:{org_dic[e_domain]}\n')
        w.close()
        return org_dic[e_domain]
    except:
        org_dic[e_domain] = 'None'
        w = open('./lab/org_database.txt','a+')
        w.write(f'{e_domain}:{org_dic[e_domain]}\n')
        w.close()
        return org_dic[e_domain]

def to_lower(obj):
    if isinstance(obj, dict):
        return {k.lower(): to_lower(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [to_lower(i) for i in obj]
    elif isinstance(obj, str):
        return obj.lower()
    else:
        return obj

def add_nodes(G, json_string, mainpath_counts):
    data = json.loads(json_string)
    data = to_lower(data)
    steps = data["steps"]
    first = 1
    paths = []
    path = []
    for step in steps:
        domain = step["domain"]
        final_ns_names = step.get("final_ns_names", [])
        final_answer = step.get("final_answer", [])
        cname_target = step.get("cname_target", None)

        if first == 1:
            G.add_node(domain, type="start", simi = 'domain')
            path.append(domain)
            first = 0
        else:
            pass
            #G.add_node(domain, type="main", simi = 'domain')
        org = check_org(domain)
        if not org in ['null','None','Not disclosed']:
            #print(org)
            G.add_node(org, type="org")
            G.add_edge(org, domain, relation="link")
            G.add_edge(domain, org, relation="link")

        if final_answer:
            for ip in final_answer:
                if not(cname_target):
                    path_final = " → ".join(path + [ip,'end'])
                    paths.append(path_final)

                #if ip == '0.0.0.0':
                    #continue
                if ip in G.nodes:
                    G.nodes[ip]['vote'] += 1
                else:
                    G.add_node(ip, type="main", vote=1)
                #print(ip,G.nodes[ip]['vote'])
                G.add_edge(domain, ip, relation="main")
                G.add_edge(ip, 'end', relation="main")
                check = check_asn(ip)
                asn = check[0]
                org = check[1]
                G.add_node(asn, type="asn")
                G.add_edge(asn, ip, relation="link")
                G.add_edge(ip, asn, relation="link")
                G.add_node(org, type="org")
                G.add_edge(org, ip, relation="link")
                G.add_edge(ip, org, relation="link")
        if cname_target:
            G.add_node(cname_target, type="main", simi = 'domain')
            G.add_edge(domain, cname_target, relation="main")
            path.append(cname_target)
        
        for ns in final_ns_names[:min(0,len(final_ns_names))]:
            if extract_domain(ns) == 'gtld-servers.net':
                continue
            G.add_node(ns, type="ns", simi = 'domain')
            org = check_org(ns)
            if not org in ['null','None','Not disclosed']:
                G.add_node(org, type="org")
                G.add_edge(org, ns, relation="link")
                G.add_edge(ns, org, relation="link")
            if final_answer: 
                for ip in final_answer:
                    G.add_edge(ns, ip, relation="link")
                    G.add_edge(ip, ns, relation="link")
            if cname_target:
                G.add_edge(ns, cname_target, relation="link")
                G.add_edge(cname_target, ns, relation="link")
    #print(G.nodes)
    pathsnum = len(paths)
    for path_final in paths:
        if path_final in mainpath_counts.keys():
            mainpath_counts[path_final] += 1/pathsnum
        else:
            mainpath_counts[path_final] = 1/pathsnum
    return G,mainpath_counts

def domain_conn(G):
    domain_nodes = [n for n, attrs in G.nodes(data=True) if attrs.get('simi') == 'domain']
    num = len(domain_nodes)
    for i in range(0,num):
        for j in range(i+1,num):
            domain1 = domain_nodes[i]
            domain2 = domain_nodes[j]
            score = compare_domain(domain1,domain2)
            if score > 0.95 and not G.has_edge(domain1, domain2) and not G.has_edge(domain2, domain1):
                G.add_edge(domain1, domain2, relation="link")
                G.add_edge(domain2, domain1, relation="link")
    return G

def detect_clustering(metric_matrix, G, mainpath_counts, path_names=None , k=300, quantile=0.5):
    if len(metric_matrix) == 1:
        return []
    #print(metric_matrix)
    metric_matrix = np.array(metric_matrix, dtype=np.float64) 
    np.fill_diagonal(metric_matrix, 0) #np.inf
    local_means = []

    vote_per = {}
    distance_per = {}
    vote_all = 0
    for idx, path in enumerate(path_names):
        path_key = " → ".join(path)
        vote_per[idx] = mainpath_counts[path_key]
        vote_all += vote_per[idx]
    print(vote_all)

    for i in range(len(metric_matrix)):
        count = 0
        sum_distance = 0
        dists = metric_matrix[i]
        for j in range(len(metric_matrix)):
            vote = vote_per[j]
            count += vote
            sum_distance += vote*dists[j]
        #local_avg = np.mean(dists)
        local_means.append(sum_distance/count)
        distance_per[i] = local_means[i]
        #print(sum_distance/count)

    vote_now = 0
    IRQ1 = -1
    IRQ3 = -1
    #sorted_indices = sorted(distance_per, key=lambda idx: distance_per[idx])
    for idx in sorted(distance_per, key=lambda i: distance_per[i]):
        vote_now += vote_per[idx]
        if vote_now > vote_all * 0.25 and IRQ1 == -1:
            IRQ1 = distance_per[idx]
        if vote_now > vote_all * 0.75 and IRQ3 == -1:
            IRQ3 = distance_per[idx]       
            break 

    threshold = IRQ3 + 1.5 * (IRQ3 - IRQ1)
    outliers = []
    for i, val in enumerate(local_means):
        if val >= threshold:
            outliers.append({
                'index': i,
                'name': path_names[i] if path_names else f'path_{i}',
                'local_avg': round(val, 3),
                'threshold': round(threshold, 3),
                'vote': vote_per[i]
            })
    return outliers

def find_unbalance(G,path_names):
    #vote_all = 0
    vote_per = {}
    for idx, path in enumerate(path_names):
        vote_per[idx] = G.nodes[path[-2]]['vote']
    
    vals = list(vote_per.values())
    max_val = max(vals)
    min_val = min(vals)

    if min_val < max_val * 0.1:
        result = [k for k, v in vote_per.items() if v == min_val]
    else:
        result = []

    return result

def hijack_detction(domain,num,file_name,draw = False, node_limit = 10000):
    f = open(f'{file_name}')
    lines = f.readlines()#[:30]
    f.close()
    G = nx.DiGraph()
    G.add_node('end', type="end")
    mainpath_counts = {}
    for line in lines:
        if G.number_of_nodes() < node_limit:
            line_sp = line.split(';')
            line_add = line_sp[1][:-1]
            G,mainpath_counts = add_nodes(G,line_add,mainpath_counts)

    G = domain_conn(G)
    G.remove_nodes_from([n for n in G.nodes if (n == 'None' or n == None)])

    print(file_name, G.number_of_nodes(), G.number_of_edges())

    matrix, paths = path_distance_matrix(G, mainpath_counts)
    with open('./results/status.txt','a+') as w:
        w.write(f'{file_name},{G.number_of_nodes()},{G.number_of_edges()},{len(paths)}\n')

    if len(paths) == 0:
        w = open('./results/detection.txt','a+')
        w.write(f"{domain}:error\n")
        w.close()

    if len(matrix) <= 1:
        outliers = []
    elif len(matrix) == 2:
        outliers = []
        dist_array = np.array(matrix)
        nonzero_vals = dist_array[dist_array != 0]
        min_val = nonzero_vals.min()
        max_val = nonzero_vals.max()

        if min_val == max_val:
            outliers_id = find_unbalance(G, path_names=paths)
            for idx in outliers_id:
                outliers.append({
                    'index': idx,
                    'name': paths[idx],
                    'local_avg': min_val,
                    'threshold': max_val
                })
    else:
        outliers = []
        dist_array = np.array(matrix)
        nonzero_vals = dist_array[dist_array != 0]
        min_val = 0 #min(nonzero_vals)
        max_val = max(nonzero_vals)

        gap = max_val - min_val if max_val != min_val else 1
        dist_norm = np.where(dist_array == 0, 0, (dist_array - min_val) / gap)
        outliers = detect_clustering(dist_norm, G, mainpath_counts, path_names=paths)
    
    for o in outliers:
        w = open('./results/detection.txt','a+')
        w.write(f"{o['name']}, Distance: {o['local_avg']} > Threshold: {o['threshold']} {o['vote']} path{o['index']}\n")
        w.close()
        path = o['name']
        for node in path[1:-1]:
            G.nodes[node]['type'] = 'special'
        for i in range(0,len(path)-1):
            G.edges[(path[i],path[i+1])]['relation'] = 'special'
    if not draw:
        return

    if draw:
        with open('mds_data.csv','w+') as mds_data:
            for col in matrix:
                for rol in col:
                    mds_data.write(str(rol) +',')
                mds_data.write('\n')
        
        with open('path_data.csv','w+') as mds_data:
            for idx, path in enumerate(paths):
                mds_data.write(f"{idx}: {' → '.join(path)}")
                mds_data.write('\n')
    return

if __name__ == '__main__':
    path = './resolver_path/'
    file_names = os.listdir(path)
    load_whois_ip()
    load_whois()

    for name in file_names:
        domain = name[:-16]
        file_path = f'{path}{name}'
        print(domain)
        hijack_detction(domain,0,file_path,False)
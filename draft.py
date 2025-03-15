from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template
from scapy.all import rdpcap

import threading

from log import Log
from alert import Alert
from packet import Packet
from rule import Rule
from DB import Database


IDS_app = Flask(__name__)

packets = rdpcap("PCAP/Wednesday-workingHours.pcap")

def update_Top_src_ip(alerts):
    src_ip_count = {}
    
    for alert in alerts:
        
        if alert.src_ip in src_ip_count:
            src_ip_count[alert.src_ip] += 1
            
        else:
            src_ip_count[alert.src_ip] = 1
    
    for ip, count in src_ip_count.items(): 
        
        top_ip = 'N/A'
        top = 1
        
        if count > top:
            
            top = count
            top_ip = ip
            
    return top_ip

def update_Top_dst_ip(alerts):
    dst_ip_count = {}
    
    for alert in alerts:
        
        if alert.dst_ip in dst_ip_count:
            dst_ip_count[alert.dst_ip] += 1
            
        else:
            dst_ip_count[alert.dst_ip] = 1
    
    for ip, count in dst_ip_count.items(): 
        
        top_ip = 'N/A'
        top = 1
        
        if count > top:
            
            top = count
            top_ip = ip
            
    return top_ip
    
def process_packet(pkt, rules):
    
    try:
        DB = Database('DB/IDS.db')
        conn = DB.connect()
        
        if not conn:
        
            print("[Error] Failed to establish database connection.")
            
            return

        packet = Packet(pkt)

        for rule in rules:
        
            rule_1 = Rule(rule)
        
            if rule_1.match_rule(packet):
        
                time = packet.get_packet_time()
                src_ip = packet.get_src_ip()
                dst_ip = packet.get_dst_ip()
                
                action = rule_1.action
                message = rule_1.options.get("msg", "No message specified")
                layer = rule_1.options.get("attack", "No message specified")

                log = Log(time, action, src_ip, dst_ip, message, layer)
                alert = Alert(time, src_ip, dst_ip, message, layer)
                
                log.add_to_log_table(conn)
                alert.add_to_alert_table(conn)
                

    except Exception as e:
        
        print(f"[Error] Error processing packet: {e}")

    finally:
        
        conn.close()

def core(packets, rules):
    
    with ThreadPoolExecutor(max_workers=5) as executor:  
        
        futures = [executor.submit(process_packet, pkt, rules) for pkt in packets]

        for future in futures:
            
            future.result()  

@IDS_app.route("/")
def UI():
    DB = Database('DB/IDS.db')
    conn = DB.connect()
    
    if not conn:
        return "Failed to connect to the database.", 500

    try:
        rules = Rule.get_rules_from_db(conn)
        
        logs = Log.get_logs_from_db(conn)
        
        alerts = Alert.get_alerts_from_db(conn)
        
        num_alerts = len(alerts)
        
        top_src_ip = update_Top_src_ip(alerts)
        
        top_dst_ip = update_Top_dst_ip(alerts)
        
    
    except Exception as e:
     
        print(f"[Error] Error fetching data for dashboard: {e}")
        
        return "An error occurred while loading the dashboard.", 500
    
    finally:
    
        conn.close()

    return render_template('index.html', title="Dashboard",logs=logs, rules=rules, alerts=alerts, num_alerts=num_alerts, top_src_ip=top_src_ip, top_dst_ip=top_dst_ip)

if __name__ == "__main__":
    
    try:
        DB = Database('DB/IDS.db')
        conn = DB.connect()
        
        if not conn:
            print("[Error] Failed to connect to the database.")
            
            exit(1)

        rules = Rule.get_rules_from_db(conn)
        
        DB.clear_table("logs")
        
        DB.clear_table("alerts")
        
        conn.close()
        
        threading.Thread(target=lambda: core(packets, rules), daemon=True).start()

        IDS_app.run(debug=True, port=9000)

    except Exception as e:
        
        print(f"[Critical Error] {e}")
        
        
        
        
        
        
        
        
        
        
        
        
        
 if "pcre" in self.options:
            pcre = self.options["pcre"]

            pcre = pcre.strip("/")  

            
            if pcre.startswith("(?i)"):
                pcre = pcre[4:]  
                pattern = re.compile(pcre, re.IGNORECASE) 
                
            else:
                pattern = re.compile(pcre) 

            payload = packet.payload
            
            if not pattern.search(payload):  
                return False
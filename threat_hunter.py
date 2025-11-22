import json
from datetime import datetime

device_code_starts = {}
ALERTS = []
TIME_WINDOW_SECONDS = 600            #10 minutes

#parsing logs
def parse_logs(lines):
    lines = lines.strip()  
    split_parts = lines.split("|", 4)
    parts = [p.strip() for p in split_parts]                  #strips parts

    t_str, user, ip, event, status = parts    
    try:
        t = datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")              #string ➝ datetime
    except ValueError:
        return None
    
    return {"time": t, 
            "user": user, 
            "ip": ip, 
            "event": event, 
            "status": status, 
            }

#getting json file data
def get_known_ips():
    try:
        with open("known_ips.json", "r") as f:
            known_ips = json.load(f)                                 #reads JSON from file and converts JSON → Python data
    except json.JSONDecodeError:                                   #malformed JSON file
        print("Error")
        return {}
    return known_ips   

#checking if IP is known
def is_known_ip(user, ip, known_ips):
    user_list = known_ips.get(user, [])               #default empty list []
    global_list = known_ips.get("_global", [])
    return ip in user_list or ip in global_list

def detect_logs(parsed_logs, known_ips):
    for l in parsed_logs:                               #access & store logs with each 'l' as a dict
        user = l["user"]
        ip = l["ip"]
        event = l["event"]
        t = l["time"]
        status = l["status"]      #returns strings of each value

        if event == "DeviceCodeStart" and l["status"] == "Success":            #checks if strings are equal to given conditions
            suspicious = not is_known_ip(user, ip, known_ips)
            device_code_starts[user] = {"ip": ip, "time": t, "suspicious": suspicious}              #store event in the variable as dict
 
            if suspicious:
                ALERTS.append({                                                             #alert list appended
                    "user": user,
                    "ip": ip,
                    "time": t.strftime("%Y-%m-%d %H:%M:%S"),                                  #datetime ➝ string
                })
                print(f"\n🚨 ALERT: DeviceCodeStart for {user} from unknown IP {ip} at {t}.")
                send_early_notification(user, ip) 

        elif event == "DeviceCodeSuccess" and status == "Success":
            start = device_code_starts[user]                                  #extracts a dict of details stored for that user
 
            if (t.timestamp() - start["time"].timestamp() <= TIME_WINDOW_SECONDS):               #timestamp() converts your datetime into float seconds since epoch
                if start["suspicious"]:                                              #If suspicious == True → execute the block
                    ALERTS.append({
                        "type": "ConfirmedSuspicious",
                        "user": user,
                        "start_ip": start["ip"],
                        "success_ip": ip,
                        "start_time": start["time"].strftime("%Y-%m-%d %H:%M:%S"),
                        "success_time": t.strftime("%Y-%m-%d %H:%M:%S"),
                    })

                    send_final_notification(user, ip) 
                del device_code_starts[user]

def send_early_notification(user, ip):
    print("\n📩 Notification:")
    print(f"To: {user}\n")
    print("Subject: [Security Warning] Unusual Login Attempt Detected\n")
    print(f"Dear {user.split('@')[0].capitalize()},\n")
    print(f"We detected an unusual Device Code login attempt from IP {ip}.")
    print("This may be harmless, but it is not a recognized location.")
    print("Please be cautious and verify that you are logging into a trusted domain before entering any code.\n")
    print("— Threat Hunter Team")
    print("-" * 100)

def send_final_notification(user, ip):
    print("\n📩 Notification:")
    print(f"To: {user}\n")
    print("Subject: [Security Alert] Suspicious Login Confirmed\n")
    print(f"Dear {user.split('@')[0].capitalize()},\n")
    print(f"A Device Code login from IP {ip} was successfully completed and appears suspicious.")
    print("If this was not you:")
    print(" • Immediately revoke all active sessions")
    print(" • Change your password")
    print(" • Contact the security team for further assistance\n")
    print("This may be a device-code phishing attack.\n")
    print("— Threat Hunter Team")
    print("-" * 100)


if __name__ == "__main__":
    known_ips = get_known_ips()                          # Load known IPs at the start

    parsed_logs_list = []                        #Creates an empty list to store parsed logs
    with open("auth_logs.txt", 'r') as f:                   
        for line in f:
            parsed_entry = parse_logs(line)                 #Sends the string "line" to your parsing function
            if parsed_entry:                                 #checks valid logs
                parsed_logs_list.append(parsed_entry)

    detect_logs(parsed_logs_list, known_ips)
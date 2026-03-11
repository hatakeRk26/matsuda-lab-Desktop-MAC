import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
from scapy.all import rdpcap, Dot11, Dot11Elt
import os
import csv
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

# ========= 設定 =========
INTERFACE = "wlx105a95baef46"
BEACON_PCAP = "beacon_scan.pcap"
BEACON_TIME = 10
CSV_FILE = "wifi_observe.csv"
# ========================

tcpdump_proc = None
selected_channel = None
ap_bssid_set = set()

# =========================
# LOCAL / UNIVERSAL 判定
# =========================
def is_local_mac(mac):
    first_byte = int(mac.split(":")[0], 16)
    return (first_byte & 0b00000010) != 0

# =========================
# 手動チャネル入力
# =========================
def manual_channel_set(event=None):
    global selected_channel
    val = channel_entry.get()
    if not val.isdigit():
        return
    ch = int(val)
    if 1 <= ch <= 165:
        selected_channel = ch
        channel_label.config(text=f"手動チャネル: CH {ch}")
        start_btn.config(state="normal")

# =========================
# CSV初期化
# =========================
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","type","mac","rssi","channel"])

# =========================
# ログ表示
# =========================
def log(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

# =========================
# CSV保存
# =========================
def save_csv(mac_type, mac, rssi, ch):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            mac_type,
            mac,
            rssi,
            ch
        ])

# =========================
# Beacon取得
# =========================
def capture_beacons():
    if os.path.exists(BEACON_PCAP):
        os.remove(BEACON_PCAP)
    cmd = ["tcpdump","-i",INTERFACE,"-w",BEACON_PCAP,"-G",str(BEACON_TIME),"-W","1"]
    log(f"[Beacon] 取得開始 ({BEACON_TIME}秒)")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log("[Beacon] 取得完了")
    if result.stderr:
        log(result.stderr.strip())

# =========================
# Beacon解析
# =========================
def analyze_beacons():
    ap_info = []
    if not os.path.exists(BEACON_PCAP):
        log("[解析] pcapがありません")
        return
    packets = rdpcap(BEACON_PCAP)
    seen = set()
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        if d.type != 0 or d.subtype != 8:
            continue
        ssid = None
        ch = None
        bssid = d.addr2
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and elt.info:
                ssid = elt.info.decode(errors="ignore")
            elif elt.ID == 3 and elt.info:
                ch = elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt)
        if ssid and ch:
            key = (ssid, ch)
            if key not in seen:
                seen.add(key)
                ap_info.append(key)
                if bssid:
                    ap_bssid_set.add(bssid)
    ap_list.delete(0, tk.END)
    for ssid, ch in sorted(ap_info, key=lambda x: (x[1], x[0])):
        ap_list.insert(tk.END, f"CH {ch} | {ssid}")
    log(f"[解析] 検出AP数: {len(ap_info)}")

def scan_beacons():
    threading.Thread(target=beacon_task, daemon=True).start()

def beacon_task():
    capture_beacons()
    analyze_beacons()

# =========================
# AP選択
# =========================
def on_ap_select(event):
    global selected_channel
    sel = ap_list.curselection()
    if not sel:
        return
    text = ap_list.get(sel[0])
    ch = int(text.split()[1])
    selected_channel = ch
    channel_label.config(text=f"選択中チャネル: CH {ch}")
    start_btn.config(state="normal")

# =========================
# MAC抽出
# =========================
def extract_macs(pcap_file):
    if not os.path.exists(pcap_file):
        log("[MAC抽出] pcap無し")
        return
    packets = rdpcap(pcap_file)
    mode = mac_mode.get()
    sta_records = {}
    log("========== MAC + RSSI ==========")
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]
        if dot11.type == 0 and dot11.subtype == 4:
            if not dot11.addr2:
                continue
            mac = dot11.addr2
            if mac in ap_bssid_set:
                continue
            pkt_time = datetime.fromtimestamp(float(pkt.time))
            rssi = getattr(pkt, "dBm_AntSignal", None)
            save_csv("STA", mac, rssi, selected_channel)
            if mac not in sta_records:
                sta_records[mac] = {"first": pkt_time, "last": pkt_time, "rssi_list": []}
            else:
                sta_records[mac]["last"] = pkt_time
            sta_records[mac]["rssi_list"].append(rssi)
    # ログ表示
    if mode == "multi":
        for mac, data in sta_records.items():
            for r in data["rssi_list"]:
                lifetime = (data["last"] - data["first"]).total_seconds()
                mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"
                log(f"STA {mac} [{mac_type}] RSSI={r} lifetime={int(lifetime)}秒")
    else:
        for mac, data in sta_records.items():
            lifetime = (data["last"] - data["first"]).total_seconds()
            avg_rssi = None
            valid = [r for r in data["rssi_list"] if r is not None]
            if valid:
                avg_rssi = int(sum(valid)/len(valid))
            mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"
            log(f"STA {mac} [{mac_type}] AVG_RSSI={avg_rssi} lifetime={int(lifetime)}秒")
    log(f"STA数: {len(sta_records)}")
    log(f"[CSV保存] → {CSV_FILE}")
    log("================================")

# =========================
# 滞在時間タイムライン生成
# =========================
def generate_timeline():
    if not os.path.exists(CSV_FILE):
        log("[Timeline] CSVがありません")
        return
    try:
        df = pd.read_csv(CSV_FILE)
        df = df[df["type"] == "STA"]
        if df.empty:
            log("[Timeline] STAデータ無し")
            return
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        g = df.groupby("mac")["timestamp"].agg(["min", "max"])
        # 0秒滞在のMACを除外するオプション
        if exclude_zero_var.get():
            g = g[(g["max"] - g["min"]).dt.total_seconds() > 0]
        fig, ax = plt.subplots(figsize=(10, max(4,len(g)*0.3)))
        for mac, row in g.iterrows():
            start = row["min"].timestamp()
            end = row["max"].timestamp()
            ax.barh(mac, end-start, left=start)
        ax.set_xlabel("time")
        ax.set_ylabel("MAC")
        ax.set_title("WiFi STA Presence Timeline")
        ax.tick_params(axis='y', labelsize=6)  # 縦軸ラベルを小さめ
        plt.tight_layout()
        out = "wifi_timeline.png"
        plt.savefig(out)
        log(f"[Timeline] 保存 → {out}")
        plt.show()
    except Exception as e:
        log(f"[Timeline ERROR] {e}")

# =========================
# キャプチャ開始
# =========================
def start_capture():
    global tcpdump_proc
    if selected_channel is None:
        messagebox.showwarning("警告", "AP選択またはチャネル入力")
        return
    duration = time_var.get()
    seconds = duration * 60
    subprocess.run(["iw","dev",INTERFACE,"set","channel",str(selected_channel)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pcap_file = f"capture_ch{selected_channel}_{duration}min.pcap"
    log(f"[Capture] 開始 CH{selected_channel}")
    log(f"[時間] {duration}分")
    cmd = ["tcpdump","-i",INTERFACE,"-w",pcap_file,"-G",str(seconds),"-W","1"]
    tcpdump_proc = subprocess.Popen(cmd)
    status_label.config(text="キャプチャ中")
    start_btn.config(state="disabled")
    threading.Thread(target=wait_and_finish, args=(pcap_file,), daemon=True).start()

# =========================
# キャプチャ終了後
# =========================
def wait_and_finish(pcap_file):
    global tcpdump_proc
    tcpdump_proc.wait()
    log("[Capture] 完了")
    extract_macs(pcap_file)
    status_label.config(text="完了")
    start_btn.config(state="normal")

# =========================
# 終了
# =========================
def stop_and_exit():
    global tcpdump_proc
    if tcpdump_proc and tcpdump_proc.poll() is None:
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
    root.destroy()

# =========================
# GUI
# =========================
root = tk.Tk()
root.title("Wi-Fi 人数推定GUI")

rssi_estimate_var = tk.BooleanVar(value=True)
time_var = tk.IntVar(value=5)
mac_mode = tk.StringVar(value="unique")
exclude_zero_var = tk.BooleanVar(value=True)  # lifetime0 MAC除外オプション

top_frame = tk.Frame(root)
top_frame.pack(pady=5)

tk.Button(top_frame, text="① Beaconスキャン", command=scan_beacons).pack(side="left", padx=5)

manual_frame = tk.LabelFrame(top_frame, text="手動チャネル指定")
manual_frame.pack(side="left", padx=10)
channel_entry = tk.Entry(manual_frame, width=6)
channel_entry.pack(padx=5, pady=2)
channel_entry.bind("<Return>", manual_channel_set)

ap_frame = tk.LabelFrame(root, text="AP")
ap_frame.pack(padx=10, pady=5, fill="both")
ap_list = tk.Listbox(ap_frame, height=8)
ap_list.pack(fill="both")
ap_list.bind("<<ListboxSelect>>", on_ap_select)

channel_label = tk.Label(root, text="チャネル未選択")
channel_label.pack()

option_frame = tk.Frame(root)
option_frame.pack(pady=5)

time_frame = tk.LabelFrame(option_frame, text="時間")
time_frame.pack(side="left", padx=5)
for t in [1,2,3,5,10,15]:
    tk.Radiobutton(time_frame, text=f"{t}分", variable=time_var, value=t).pack(anchor="w")

mac_frame = tk.LabelFrame(option_frame, text="MAC表示")
mac_frame.pack(side="left", padx=5)
tk.Radiobutton(mac_frame, text="重複削除", variable=mac_mode, value="unique").pack(anchor="w")
tk.Radiobutton(mac_frame, text="複数表示", variable=mac_mode, value="multi").pack(anchor="w")

estimate_frame = tk.LabelFrame(option_frame, text="RSSI推定")
estimate_frame.pack(side="left", padx=5)
tk.Checkbutton(estimate_frame, text="RSSI人数推定をログ表示", variable=rssi_estimate_var).pack(anchor="w")

exclude_frame = tk.Frame(root)
exclude_frame.pack(pady=5)
tk.Checkbutton(exclude_frame, text="滞在時間0秒のMACを除外", variable=exclude_zero_var).pack(anchor="w")

start_btn = tk.Button(root, text="② キャプチャ開始", command=start_capture, state="disabled")
start_btn.pack(pady=5)

tk.Button(root, text="③ 滞在時間グラフ生成", command=generate_timeline).pack(pady=5)

status_label = tk.Label(root, text="待機中")
status_label.pack()

log_frame = tk.LabelFrame(root, text="ログ")
log_frame.pack(padx=10, pady=5, fill="both")
log_text = tk.Text(log_frame, height=12)
log_text.pack(fill="both")

tk.Button(root, text="終了", fg="red", command=stop_and_exit).pack(pady=15)

root.mainloop()

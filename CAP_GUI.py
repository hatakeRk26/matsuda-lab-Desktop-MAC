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
import matplotlib.dates as mdates 

# ========= 設定 =========
INTERFACE = "wlx105a95baef46"
BEACON_PCAP = "beacon_scan.pcap"
BEACON_TIME = 10
CSV_FILE = "wifi_observe.csv"
GAP_THRESHOLD = 30
# ========================

tcpdump_proc = None
selected_channel = None
ap_bssid_set = set()

def is_local_mac(mac):
    first_byte = int(mac.split(":")[0], 16)
    return (first_byte & 0b00000010) != 0

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

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","type","mac","rssi","channel"])

def log(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

def save_csv(timestamp, mac_type, mac, rssi, ch):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            mac_type,
            mac,
            rssi,
            ch
        ])

def capture_beacons():
    if os.path.exists(BEACON_PCAP):
        os.remove(BEACON_PCAP)
    cmd = ["tcpdump","-i",INTERFACE,"-w",BEACON_PCAP,"-G",str(BEACON_TIME),"-W","1"]
    log(f"[Beacon] 取得開始 ({BEACON_TIME}秒)")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    log("[Beacon] 取得完了")
    if result.stderr:
        log(result.stderr.strip())

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

            save_csv(pkt_time, "STA", mac, rssi, selected_channel)

            if mac not in sta_records:

                sta_records[mac] = {
                    "first": pkt_time,
                    "last": pkt_time,
                    "rssi_list": []
                }

            else:
                sta_records[mac]["last"] = pkt_time

            sta_records[mac]["rssi_list"].append(rssi)

    if mode == "multi":

        for mac, data in sta_records.items():

            lifetime = (data["last"] - data["first"]).total_seconds()

            mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"

            for r in data["rssi_list"]:
                log(f"STA {mac} [{mac_type}] RSSI={r} lifetime={int(lifetime)}秒")

    else:

        for mac, data in sta_records.items():

            lifetime = (data["last"] - data["first"]).total_seconds()

            valid = [r for r in data["rssi_list"] if r is not None]

            avg_rssi = None

            if valid:
                avg_rssi = int(sum(valid) / len(valid))

            mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"

            log(f"STA {mac} [{mac_type}] AVG_RSSI={avg_rssi} lifetime={int(lifetime)}秒")

    log(f"STA数: {len(sta_records)}")
    log(f"[CSV保存] → {CSV_FILE}")
    log("================================")

def generate_timeline():
    import numpy as np

    pcap_files = [f for f in os.listdir() if f.endswith(".pcap")]
    if not pcap_files:
        log("[Timeline] pcapがありません")
        return

    pcap_file = max(pcap_files, key=os.path.getctime)
    log(f"[Timeline] 使用pcap: {pcap_file}")

    packets = rdpcap(pcap_file)
    sta_sessions = {}

    for pkt in packets:

        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]

        if dot11.type == 0 and dot11.subtype == 4:

            mac = dot11.addr2

            if not mac:
                continue

            if mac in ap_bssid_set:
                continue

            pkt_time = datetime.fromtimestamp(float(pkt.time))

            if mac not in sta_sessions:
                sta_sessions[mac] = [[pkt_time, pkt_time]]
            else:
                last_session = sta_sessions[mac][-1]
                gap = (pkt_time - last_session[1]).total_seconds()

                if gap <= GAP_THRESHOLD:
                    last_session[1] = pkt_time
                else:
                    sta_sessions[mac].append([pkt_time, pkt_time])

    rows = []

    for mac, sessions in sta_sessions.items():
        for start, end in sessions:

            duration = (end - start).total_seconds()

            if exclude_zero_var.get():
                if duration < 5:
                    continue

            rows.append({
                "mac": mac,
                "start": start,
                "duration": duration
            })

    if not rows:
        log("[Timeline] 表示できるMAC無し")
        return

    df = pd.DataFrame(rows)

    df = df.sort_values("duration", ascending=False)

    if len(df) > 40:
        df = df.head(40)

    base_time = df["start"].min()

    fig_height = max(6, len(df) * 0.4)
    fig, ax = plt.subplots(figsize=(12, fig_height))

    # =========================
    # ★ 色をMACごとに固定
    # =========================
    unique_macs = df["mac"].unique()
    color_map = {}
    for mac in unique_macs:
        color_map[mac] = np.random.rand(3,)

    # =========================
    # ★ 描画
    # =========================
    for _, row in df.iterrows():
        start_sec = (row["start"] - base_time).total_seconds()
        ax.barh(
            row["mac"],
            row["duration"],
            left=start_sec,
            color=color_map[row["mac"]]
        )

    from matplotlib.ticker import FuncFormatter, MultipleLocator

    def sec_to_minsec(x, pos):
        m = int(x // 60)
        s = int(x % 60)
        return f"{m}:{s:02d}"

    ax.xaxis.set_major_formatter(FuncFormatter(sec_to_minsec))
    ax.set_xlim(0, time_var.get() * 60)
    ax.xaxis.set_major_locator(MultipleLocator(60))

    ax.set_xlabel("Elapsed Time (mm:ss)")
    ax.set_ylabel("MAC")
    ax.set_title(f"WiFi STA Presence Timeline ({time_var.get()} min measurement)")

    ax.text(
        0.99, 0.01,
        f"Measurement: {time_var.get()} min",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=10,
        color="gray"
    )

    ax.grid(axis="x", linestyle="--", alpha=0.3)
    ax.tick_params(axis='y', labelsize=8)

    plt.tight_layout()

    out = "wifi_timeline.png"
    plt.savefig(out)

    log(f"[Timeline] MAC数: {len(df)}")
    log(f"[Timeline] 保存 → {out}")

    plt.show()

def start_capture():
    global tcpdump_proc

    if selected_channel is None:
        messagebox.showwarning("警告", "AP選択またはチャネル入力")
        return

    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","type","mac","rssi","channel"])
    log("[CSV] リセットしました")

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

def wait_and_finish(pcap_file):
    global tcpdump_proc
    tcpdump_proc.wait()
    log("[Capture] 完了")
    extract_macs(pcap_file)
    status_label.config(text="完了")
    start_btn.config(state="normal")

def stop_and_exit():
    global tcpdump_proc
    if tcpdump_proc and tcpdump_proc.poll() is None:
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
    root.destroy()

root = tk.Tk()
root.title("MAC_GUI")

rssi_estimate_var = tk.BooleanVar(value=False)
time_var = tk.IntVar(value=5)
mac_mode = tk.StringVar(value="unique")
exclude_zero_var = tk.BooleanVar(value=True)

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
tk.Checkbutton(exclude_frame, text="滞在時間5秒未満のMACを除外", variable=exclude_zero_var).pack(anchor="w")

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

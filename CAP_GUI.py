import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
from scapy.all import rdpcap, Dot11, Dot11Elt, PcapReader
import os
import csv
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates 
import matplotlib.cm as cm

# ========= 設定 =========
INTERFACE = "wlx105a95baef46"
BEACON_PCAP = "beacon_scan.pcap"
BEACON_TIME = 10
CSV_FILE = "wifi_observe.csv"
GAP_THRESHOLD = 30
TARGET_MAC = "50:a6:d8:7e:d7:c2" 
# ========================

tcpdump_proc = None
selected_channel = None
ap_bssid_set = set()
running = True
current_fig = None

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
    if not running: return
    try:
        # rootが存在し、かつ閉じられていないか確認
        if not root or not root.winfo_exists(): return
    except:
        return

    def _update():
        try:
            if not root.winfo_exists(): return
            if TARGET_MAC in msg.lower():
                log_text.insert(tk.END, msg + "\n", "green_mac")
            else:
                log_text.insert(tk.END, msg + "\n")
            log_text.see(tk.END)
        except:
            pass

    try:
        root.after(0, _update)
    except:
        pass

def wait_and_finish(pcap_file):
    global tcpdump_proc
    if tcpdump_proc:
        tcpdump_proc.wait()
    
    if not running: return # 終了中なら何もしない
    
    log("[Capture] 完了")
    extract_macs(pcap_file)
    
    # 画面が生きている場合のみ更新
    try:
        if root.winfo_exists():
            root.after(0, lambda: status_label.config(text="完了"))
            root.after(0, lambda: start_btn.config(state="normal"))
    except:
        pass
        
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
    seen = set()
    with PcapReader(BEACON_PCAP) as packets:
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
    sta_records = {}
    sta_sessions = {}
    csv_buffer = []
    log("========== MAC + RSSI ==========")
    with PcapReader(pcap_file) as packets:
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            dot11 = pkt[Dot11]
            if dot11.type != 0 or dot11.subtype != 4:
                continue
            if not dot11.addr2:
                continue
            mac = dot11.addr2
            if mac in ap_bssid_set:
                continue
            pkt_time = float(pkt.time)
            rssi = getattr(pkt, "dBm_AntSignal", None)
            csv_buffer.append([
                datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f"),
                "STA", mac, rssi, selected_channel
            ])
            if mac not in sta_records:
                sta_records[mac] = {"first": pkt_time, "last": pkt_time, "rssi_sum": 0, "rssi_count": 0}
            else:
                sta_records[mac]["last"] = pkt_time
            if rssi is not None:
                sta_records[mac]["rssi_sum"] += rssi
                sta_records[mac]["rssi_count"] += 1
            if mac not in sta_sessions:
                sta_sessions[mac] = [[pkt_time, pkt_time]]
            else:
                last_session = sta_sessions[mac][-1]
                if pkt_time - last_session[1] <= GAP_THRESHOLD:
                    last_session[1] = pkt_time
                else:
                    sta_sessions[mac].append([pkt_time, pkt_time])

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_buffer)

    session_file = "sessions.csv"
    with open(session_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["mac", "start", "end", "duration"])
        for mac, sessions in sta_sessions.items():
            for start, end in sessions:
                writer.writerow([mac, datetime.fromtimestamp(start), datetime.fromtimestamp(end), end - start])
    
    for mac, data in sta_records.items():
        lifetime = data["last"] - data["first"]
        lifetime_str = f"{int(lifetime)}秒" if lifetime >= 1 else f"{lifetime:.4f}秒"
        avg_rssi = int(data["rssi_sum"] / data["rssi_count"]) if data["rssi_count"] > 0 else None
        mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"
        log(f"STA {mac} [{mac_type}] AVG_RSSI={avg_rssi} lifetime={lifetime_str}")
    log(f"STA数: {len(sta_records)}")

def generate_timeline():
    global current_fig
    from matplotlib.ticker import FuncFormatter, MultipleLocator
    plt.close("all")
    session_file = "sessions.csv"
    if not os.path.exists(session_file) or not os.path.exists(CSV_FILE):
        log("[Timeline] データがありません")
        return
    obs_df = pd.read_csv(CSV_FILE)
    avg_rssi_map = obs_df.groupby("mac")["rssi"].mean().to_dict()
    df = pd.read_csv(session_file)
    df["start"] = pd.to_datetime(df["start"])
    df = df[df["duration"] > 0] if exclude_zero_var.get() else df[df["duration"] >= 0]
    if df.empty: return
    df = df.sort_values("duration", ascending=False)
    unique_macs = df["mac"].unique()
    base_time = df["start"].min()
    fig, ax = plt.subplots(figsize=(13, max(6, len(unique_macs) * 0.4)))
    current_fig = fig

    # --- 設定：縦軸文字、1分ごとの目盛りと点線 ---
    ax.tick_params(axis='y', labelsize=5) 
    ax.xaxis.set_major_locator(MultipleLocator(60))
    ax.grid(axis='x', linestyle='--', alpha=0.5, zorder=0)

    for _, row in df.iterrows():
        start_sec = (row["start"] - base_time).total_seconds()
        mac = row["mac"]
        
        # 【重要】ここで定義しています
        is_target = (mac.lower() == TARGET_MAC.lower())
        
        color = "limegreen" if is_target else ("red" if is_local_mac(mac) else "black")

        # 特定MACの開始時間に垂直線を引く
        if is_target:
            ax.axvline(x=start_sec, color='limegreen', linestyle=':', linewidth=1.5, alpha=0.8, zorder=1)

        if row["duration"] == 0:
            ax.scatter(start_sec, mac, color=color, s=50, marker='o', zorder=5)
        else:
            ax.barh(mac, max(row["duration"], 1.0), left=start_sec, color=color, height=0.6, alpha=0.8, zorder=3)
    
    ax.set_yticks(range(len(unique_macs)))
    ax.set_yticklabels([f"{m} ({int(avg_rssi_map.get(m, 0))}dBm)" for m in unique_macs])
    
    # 上下の余白を完全にゼロにする
    ax.set_ylim(-0.5, len(unique_macs) - 0.5) 
    ax.margins(y=0)
    
    # 縦軸ラベルの色分け
    ytick_labels = ax.get_yticklabels()
    for i, mac in enumerate(unique_macs):
        if mac.lower() == TARGET_MAC.lower():
            ytick_labels[i].set_color("limegreen")
            ytick_labels[i].set_weight("bold")
        elif is_local_mac(mac):
            ytick_labels[i].set_color("red")
        else:
            ytick_labels[i].set_color("black")

    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x//60)}:{int(x%60):02d}"))
    ax.set_xlim(0, time_var.get() * 60)
    ax.set_title("WiFi STA Presence Timeline", fontsize=12)
    
    ax.text(0.5, 0.5, f"{time_var.get()} min Capture", 
            transform=ax.transAxes, 
            fontsize=40, color='gray', alpha=0.15, # alphaで透明度を調整
            ha='center', va='center', fontweight='bold', 
            zorder=0) # zorder=0 でデータの点や棒の下側に配置
            
    plt.tight_layout()
    plt.show()

def generate_grouped_rssi_timeline():
    """RSSIグループ表示 (青い境界線と背景色を完全に同期)"""
    global current_fig
    from matplotlib.ticker import FuncFormatter, MultipleLocator
    import numpy as np
    
    plt.close("all")
    session_file = "sessions.csv"
    if not os.path.exists(session_file) or not os.path.exists(CSV_FILE):
        log("[Group] データがありません")
        return

    obs_df = pd.read_csv(CSV_FILE)
    obs_df["timestamp"] = pd.to_datetime(obs_df["timestamp"])
    avg_rssi_map = obs_df.groupby("mac")["rssi"].mean().to_dict()
    
    df = pd.read_csv(session_file)
    df["start"] = pd.to_datetime(df["start"])
    df = df[df["duration"] > 0] if exclude_zero_var.get() else df[df["duration"] >= 0]

    sorted_macs = sorted(df["mac"].unique(), key=lambda x: avg_rssi_map.get(x, -100), reverse=True)
    if not sorted_macs: return

    base_time = obs_df["timestamp"].min()
    
    if show_density_var.get():
        fig, (ax_top, ax) = plt.subplots(2, 1, figsize=(14, max(8, len(sorted_macs) * 0.4)), 
                                         gridspec_kw={'height_ratios': [1, 5]}, sharex=True)
        obs_df["elapsed_sec"] = (obs_df["timestamp"] - base_time).dt.total_seconds()
        bin_width = 5
        bins = np.arange(0, time_var.get() * 60 + bin_width, bin_width)
        counts, _ = np.histogram(obs_df["elapsed_sec"], bins=bins)
        ax_top.bar(bins[:-1], counts, width=bin_width * 0.8, color='dimgray', alpha=0.7, 
                   align='edge', edgecolor='black', linewidth=0.5)
        ax_top.set_ylabel("Packets\n/ 5sec", fontsize=9)
        ax_top.grid(axis='y', linestyle=':', alpha=0.5)
        ax_top.set_title("Network Activity & RSSI Grouped Timeline", fontsize=14, pad=15)
        fig.subplots_adjust(hspace=0.05)
    else:
        fig, ax = plt.subplots(figsize=(14, max(6, len(sorted_macs) * 0.4)))
        ax.set_title(f"RSSI Grouped Timeline", fontsize=14)
    
    current_fig = fig

    # --- 境界線の数値に基づいた色定義 ---
    def get_color_by_threshold(th):
        if th >= -30: return "#c8e6c9" # -30dBm以上のエリア
        if th >= -40: return "#e8f5e9" # -30~-40
        if th >= -50: return "#fff9c4" # -40~-50
        if th >= -60: return "#ffe0b2" # -50~-60
        if th >= -70: return "#ffccbc" # -60~-70
        return "#ffcdd2"              # -70以下

    ax.tick_params(axis='y', labelsize=6)
    ax.xaxis.set_major_locator(MultipleLocator(60))
    ax.grid(axis='x', linestyle='--', alpha=0.3, zorder=0)

    # 初期設定：最初の行のRSSIに基づいた色
    first_rssi = avg_rssi_map.get(sorted_macs[0], -100)
    current_zone_th = -100
    for th in [-30, -40, -50, -60, -70, -80]:
        if first_rssi >= th:
            current_zone_th = th
            break
            
    last_rssi = first_rssi
    thresholds = [-30, -40, -50, -60, -70, -80]

    for i, mac in enumerate(sorted_macs):
        rssi = avg_rssi_map.get(mac, -100)
        
        # 境界線を跨いだ瞬間に、現在の「ゾーンしきい値」を更新する
        for th in thresholds:
            if i > 0 and last_rssi > th >= rssi:
                ax.axhline(i - 0.5, color="blue", linewidth=1.2, linestyle="-", alpha=0.8, zorder=4)
                ax.text(time_var.get() * 60 * 1.005, i - 0.5, f"{th}dBm", 
                        color="blue", va="center", fontweight="bold", fontsize=9)
                current_zone_th = th # ここで背景色用のしきい値を同期更新
        
        last_rssi = rssi

        # 現在のゾーンしきい値に基づいた背景色を塗る（MAC個別のRSSIは無視）
        ax.axhspan(i - 0.5, i + 0.5, color=get_color_by_threshold(current_zone_th), alpha=0.6, zorder=0)

        # データの描画
        mac_sessions = df[df["mac"] == mac]
        is_target = (mac.lower() == TARGET_MAC.lower())
        line_color = "limegreen" if is_target else ("red" if is_local_mac(mac) else "black")
        
        for _, row in mac_sessions.iterrows():
            start_sec = (row["start"] - base_time).total_seconds()
            if row["duration"] == 0:
                ax.scatter(start_sec, i, color=line_color, s=35, marker='o', zorder=5)
            else:
                ax.barh(i, max(row["duration"], 1.0), left=start_sec, color=line_color, height=0.6, alpha=0.8, zorder=3)

    ax.set_yticks(range(len(sorted_macs)))
    ax.set_yticklabels([f"{m} ({int(avg_rssi_map.get(m, 0))}dBm)" for m in sorted_macs])
    ax.set_ylim(-0.5, len(sorted_macs) - 0.5)
    ax.invert_yaxis()
    
    ytick_labels = ax.get_yticklabels()
    for i, mac in enumerate(sorted_macs):
        if mac.lower() == TARGET_MAC.lower():
            ytick_labels[i].set_color("limegreen")
            ytick_labels[i].set_weight("bold")
            ax.add_patch(plt.Rectangle((0, i-0.5), time_var.get()*60, 1, fill=False, edgecolor='limegreen', linewidth=1, alpha=0.5, zorder=6))
        elif is_local_mac(mac):
            ytick_labels[i].set_color("red")

    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x//60)}:{int(x%60):02d}"))
    ax.set_xlim(0, time_var.get() * 60)
    
    ax.text(0.5, 0.5, f"{time_var.get()} min Capture", transform=ax.transAxes, 
            fontsize=40, color='gray', alpha=0.1, ha='center', va='center', fontweight='bold', zorder=0)

    plt.tight_layout()
    plt.show()
    
def generate_target_rssi_graph():
    from matplotlib.ticker import FuncFormatter, MultipleLocator
    if not os.path.exists(CSV_FILE): return
    all_df = pd.read_csv(CSV_FILE)
    all_df["timestamp"] = pd.to_datetime(all_df["timestamp"])
    base_time = all_df["timestamp"].min()
    target_df = all_df[all_df["mac"].str.lower() == TARGET_MAC.lower()].copy()
    if target_df.empty: return
    target_df["elapsed_sec"] = (target_df["timestamp"] - base_time).dt.total_seconds()
    target_df["rssi_smooth"] = target_df["rssi"].rolling(window=5, min_periods=1, center=True).mean()
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.scatter(target_df["elapsed_sec"], target_df["rssi"], color="gray", alpha=0.4, s=20, label="Raw RSSI")
    ax.plot(target_df["elapsed_sec"], target_df["rssi_smooth"], color="limegreen", linewidth=3, label="Moving Average")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x//60)}:{int(x%60):02d}"))
    ax.set_xlim(0, time_var.get() * 60)
    ax.set_ylim(-105, -15); ax.grid(True, linestyle="--", alpha=0.5); ax.legend()
    plt.tight_layout(); plt.show()

def start_capture():
    global tcpdump_proc, current_fig
    current_fig = None
    if selected_channel is None:
        messagebox.showwarning("警告", "AP選択またはチャネル入力")
        return
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","type","mac","rssi","channel"])
    duration = time_var.get()
    subprocess.run(["iw","dev",INTERFACE,"set","channel",str(selected_channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pcap_file = f"capture_ch{selected_channel}_{duration}min.pcap"
    log(f"[Capture] 開始 CH{selected_channel} ({duration}分)")
    tcpdump_proc = subprocess.Popen(["tcpdump","-i",INTERFACE,"-w",pcap_file,"-G",str(duration*60),"-W","1"])
    status_label.config(text="キャプチャ中")
    start_btn.config(state="disabled")
    threading.Thread(target=wait_and_finish, args=(pcap_file,), daemon=True).start()

def wait_and_finish(pcap_file):
    global tcpdump_proc
    tcpdump_proc.wait()
    log("[Capture] 完了")
    extract_macs(pcap_file)
    if root.winfo_exists():
        root.after(0, lambda: status_label.config(text="完了"))
        root.after(0, lambda: start_btn.config(state="normal"))

def stop_and_exit():
    global tcpdump_proc, running
    running = False
    # プロセスが動いていたら止める
    if tcpdump_proc and tcpdump_proc.poll() is None:
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
    
    plt.close("all") # グラフを閉じる
    
    try:
        root.destroy() # ウィンドウ破棄
    except:
        pass
    
    # 強制終了（これで RuntimeError を回避する）
    import os
    os._exit(0)

def save_graph():
    global current_fig
    import getpass
    if current_fig is None:
        messagebox.showwarning("警告", "先にグラフを生成してください")
        return
    BASE_DIR = "/home/hatake/デスクトップ"
    save_dir = os.path.join(BASE_DIR, f"MAC_{time_var.get()}m")
    os.makedirs(save_dir, exist_ok=True)
    user = getpass.getuser()
    os.system(f"sudo chown -R {user}:{user} '{save_dir}'")
    filepath = os.path.join(save_dir, f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    current_fig.savefig(filepath)
    os.system(f"sudo chown {user}:{user} '{filepath}'")
    log(f"[保存] {filepath}")

# UI 構築
root = tk.Tk()
root.title("MAC_GUI")

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
for i, t in enumerate([1,2,3,5,10,15,30,60]):
    tk.Radiobutton(time_frame, text=f"{t}分", variable=time_var, value=t).grid(row=i//3, column=i%3, sticky="ew", padx=5)

mac_frame = tk.LabelFrame(option_frame, text="MAC表示")
mac_frame.pack(side="left", padx=5)
tk.Radiobutton(mac_frame, text="重複削除", variable=mac_mode, value="unique").pack(anchor="w")
tk.Radiobutton(mac_frame, text="複数表示", variable=mac_mode, value="multi").pack(anchor="w")

exclude_frame = tk.Frame(root)
exclude_frame.pack(pady=5)
tk.Checkbutton(exclude_frame, text="滞在時間0秒のMACを除外", variable=exclude_zero_var).pack()

show_density_var = tk.BooleanVar(value=True) # デフォルトでON
tk.Checkbutton(exclude_frame, text="パケット密度グラフを表示する", variable=show_density_var).pack()

main_frame = tk.Frame(root)
main_frame.pack(pady=5)
left_frame = tk.Frame(main_frame)
left_frame.pack(side="left", padx=10)
right_frame = tk.Frame(main_frame)
right_frame.pack(side="left", padx=20, anchor="n")

# ボタン
start_btn = tk.Button(left_frame, text="② キャプチャ開始", command=start_capture, state="disabled")
start_btn.pack(pady=5)
tk.Button(left_frame, text="③ 滞在時間グラフ生成", command=generate_timeline).pack(pady=5)
tk.Button(left_frame, text="④ RSSIグループ表示", command=generate_grouped_rssi_timeline, fg="purple").pack(pady=5)
tk.Button(left_frame, text="特定MACのRSSI解析", command=generate_target_rssi_graph, fg="darkgreen").pack(pady=5)
tk.Button(left_frame, text="⑤ グラフ保存", command=save_graph).pack(pady=5)

# 検索UI
search_var = tk.StringVar()
tk.Label(right_frame, text="ログ検索").pack()
entry = tk.Entry(right_frame, textvariable=search_var, width=25)
entry.pack(pady=5)

tk.Button(right_frame, text="終了する", fg="red", font=("", 10, "bold"), 
          command=stop_and_exit, width=15).pack(pady=65) 
          
def search_log(*args):
    keyword = search_var.get()
    log_text.tag_remove("highlight", "1.0", tk.END)
    if not keyword: return
    start = "1.0"
    while True:
        pos = log_text.search(keyword, start, stopindex=tk.END, nocase=True)
        if not pos: break
        end = f"{pos}+{len(keyword)}c"
        log_text.tag_add("highlight", pos, end)
        start = end
search_var.trace_add("write", search_log)

status_label = tk.Label(root, text="待機中")
status_label.pack()
log_frame = tk.LabelFrame(root, text="ログ")
log_frame.pack(padx=10, pady=5, fill="both")
log_text = tk.Text(log_frame, height=12)
log_text.pack(fill="both")
log_text.tag_config("green_mac", foreground="limegreen")
log_text.tag_config("highlight", background="yellow")

root.mainloop()

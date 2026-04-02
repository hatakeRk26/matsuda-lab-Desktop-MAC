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
    if not running:
        return

    try:
        if not root.winfo_exists():
            return
    except:
        return

    def _update():
        try:
            if TARGET_MAC in msg.lower():
                log_text.insert(tk.END, msg + "\n", "green_mac")
            else:
                log_text.insert(tk.END, msg + "\n")
            log_text.see(tk.END)
        except:
            pass  # ← UI消えてても落ちない

    try:
        root.after(0, _update)
    except:
        pass

#def save_csv(timestamp, mac_type, mac, rssi, ch):
#    with open(CSV_FILE, "a", newline="") as f:
#       writer = csv.writer(f)
#        writer.writerow([
#            timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
#            mac_type,
#            mac,
#            rssi,
#            ch
#        ])

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

    with PcapReader(BEACON_PCAP) as packets:   # ★変更
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

from scapy.all import PcapReader

def extract_macs(pcap_file):

    if not os.path.exists(pcap_file):
        log("[MAC抽出] pcap無し")
        return

    mode = mac_mode.get()
    sta_records = {}
    sta_sessions = {}

    csv_buffer = []   # ★追加（CSVまとめ用）

    log("========== MAC + RSSI ==========")

    with PcapReader(pcap_file) as packets:   # ★変更（超重要）
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

            # ★高速化：floatで保持
            pkt_time = float(pkt.time)
            rssi = getattr(pkt, "dBm_AntSignal", None)

            # ★CSVは貯めるだけ
            csv_buffer.append([
                datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f"),
                "STA",
                mac,
                rssi,
                selected_channel
            ])

            # ===== lifetime用 =====
            if mac not in sta_records:
                sta_records[mac] = {
                    "first": pkt_time,
                    "last": pkt_time,
                    "rssi_sum": 0,
                    "rssi_count": 0
                }
            else:
                sta_records[mac]["last"] = pkt_time

            if rssi is not None:
                sta_records[mac]["rssi_sum"] += rssi
                sta_records[mac]["rssi_count"] += 1

            # ===== セッション生成 =====
            if mac not in sta_sessions:
                sta_sessions[mac] = [[pkt_time, pkt_time]]
            else:
                last_session = sta_sessions[mac][-1]
                gap = pkt_time - last_session[1]

                if gap <= GAP_THRESHOLD:
                    last_session[1] = pkt_time
                else:
                    sta_sessions[mac].append([pkt_time, pkt_time])

    # ★CSVまとめ書き（超重要）
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_buffer)

    log(f"[CSV書き込み] {len(csv_buffer)}件")

    # ===== セッションCSV =====
    session_file = "sessions.csv"
    with open(session_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["mac", "start", "end", "duration"])

        for mac, sessions in sta_sessions.items():
            for start, end in sessions:
                duration = end - start
                writer.writerow([
                    mac,
                    datetime.fromtimestamp(start),
                    datetime.fromtimestamp(end),
                    duration
                ])

    log(f"[Session保存] → {session_file}")

    # ===== ログ出力（平均RSSI復活）=====
    for mac, data in sta_records.items():
        lifetime = data["last"] - data["first"]

        if lifetime >= 1:
            lifetime_str = f"{int(lifetime)}秒"
        else:
            lifetime_str = f"{lifetime:.4f}秒"

        # ★平均RSSI復活（軽量版）
        if data["rssi_count"] > 0:
            avg_rssi = int(data["rssi_sum"] / data["rssi_count"])
        else:
            avg_rssi = None

        mac_type = "LOCAL" if is_local_mac(mac) else "UNIVERSAL"

        log(f"STA {mac} [{mac_type}] AVG_RSSI={avg_rssi} lifetime={lifetime_str}")

    log(f"STA数: {len(sta_records)}")
    log("================================")

def generate_timeline():
    global current_fig
    import numpy as np
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter, MultipleLocator
    
    plt.close("all")

    session_file = "sessions.csv"
    if not os.path.exists(session_file):
        log("[Timeline] sessionデータがありません")
        return

    log(f"[Timeline] 使用データ: {session_file}")

    df = pd.read_csv(session_file)
    df["start"] = pd.to_datetime(df["start"])

    # 滞在時間0秒の除外設定
    if exclude_zero_var.get():
        df = df[df["duration"] > 0]   
    else:
        df = df[df["duration"] >= 0]

    if df.empty:
        log("[Timeline] 表示できるMAC無し")
        return

    # 滞在時間が長い順に並べる（グラフの下から上に並ぶ）
    df = df.sort_values("duration", ascending=False)

    base_time = df["start"].min()

    # グラフの高さ調整
    unique_mac_count = len(df["mac"].unique())
    fig_height = max(6, unique_mac_count * 0.4)
    fig, ax = plt.subplots(figsize=(12, fig_height))
    current_fig = fig

    for _, row in df.iterrows():
        start_sec = (row["start"] - base_time).total_seconds()
        mac = row["mac"]
        
        # --- 色の判定ロジック ---
        if mac.lower() == TARGET_MAC.lower():
            plot_color = "limegreen"  # 特定MAC（緑）
            z_order = 5               # 最前面に表示
        elif is_local_mac(mac):
            plot_color = "red"        # ローカルMAC（赤）
            z_order = 2
        else:
            plot_color = "black"      # グローバルMAC（黒）
            z_order = 3
        # ----------------------

        if row["duration"] == 0:
            # 0秒（一瞬だけ観測）は点で表示
            ax.scatter(
                start_sec,
                mac,
                color=plot_color,
                s=30,
                zorder=z_order,
                alpha=0.7
            )
        else:
            # 滞在時間は棒グラフで表示
            width = max(row["duration"], 0.5) # 見やすくするため最小幅を設定
            ax.barh(
                mac,
                width,
                left=start_sec,
                color=plot_color,
                zorder=z_order,
                height=0.6,
                alpha=0.8
            )

    # 軸の設定
    def sec_to_minsec(x, pos):
        return f"{int(x//60)}:{int(x%60):02d}"

    ax.xaxis.set_major_formatter(FuncFormatter(sec_to_minsec))
    ax.set_xlim(0, time_var.get() * 60)
    ax.xaxis.set_major_locator(MultipleLocator(60)) # 1分刻み

    ax.set_xlabel("Elapsed Time (mm:ss)")
    ax.set_ylabel("MAC Address")
    ax.set_title(f"WiFi STA Presence Timeline ({time_var.get()} min measurement)")

    # Y軸（MACアドレス名）の色設定
    for label in ax.get_yticklabels():
        mac_label = label.get_text()
        if mac_label.lower() == TARGET_MAC.lower():
            label.set_color("limegreen")
            label.set_weight("bold") # ターゲットは太字に
        elif is_local_mac(mac_label):
            label.set_color("red")
        else:
            label.set_color("black")
    
    ax.grid(axis="x", linestyle="--", alpha=0.3)
    plt.tight_layout(rect=[0, 0.05, 1, 0.95])
    plt.show()

    log(f"[Timeline] 表示MAC数: {unique_mac_count}")
    
def generate_target_rssi_graph():
    """特定MACアドレスのRSSI推移グラフを生成する"""
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    if not os.path.exists(CSV_FILE):
        log("[RSSI分析] CSVデータがありません")
        return

    # データの読み込み
    df = pd.read_csv(CSV_FILE)
    
    # ターゲットMACでフィルタリング (大文字小文字を区別しない)
    target_df = df[df["mac"].str.lower() == TARGET_MAC.lower()].copy()

    if target_df.empty:
        log(f"[RSSI分析] {TARGET_MAC} のデータが見つかりません")
        return

    # タイムスタンプの変換
    target_df["timestamp"] = pd.to_datetime(target_df["timestamp"])
    target_df = target_df.sort_values("timestamp")

    # 経過時間（秒）の計算
    base_time = pd.to_datetime(df["timestamp"]).min()
    target_df["elapsed_sec"] = (target_df["timestamp"] - base_time).dt.total_seconds()

    # 移動平均の計算（窓サイズ5：状況に合わせて調整）
    target_df["rssi_smooth"] = target_df["rssi"].rolling(window=5, min_periods=1, center=True).mean()

    # グラフ作成
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 生データ（点）
    ax.scatter(target_df["elapsed_sec"], target_df["rssi"], 
               color="gray", alpha=0.4, s=15, label="Raw RSSI")
    
    # 移動平均線（太線）
    ax.plot(target_df["elapsed_sec"], target_df["rssi_smooth"], 
             color="limegreen", linewidth=2, label="Moving Average (window=5)")

    # 軸の設定
    def sec_to_minsec(x, pos):
        return f"{int(x//60)}:{int(x%60):02d}"
    
    ax.xaxis.set_major_formatter(FuncFormatter(sec_to_minsec))
    ax.set_xlabel("Elapsed Time (mm:ss)")
    ax.set_ylabel("RSSI (dBm)")
    ax.set_title(f"RSSI Behavior Analysis: {TARGET_MAC}")
    ax.grid(True, linestyle="--", alpha=0.6)
    ax.legend()

    # RSSIの一般的な範囲に固定（見やすくするため）
    ax.set_ylim(-100, -20)

    plt.tight_layout()
    plt.show()
    
    log(f"[RSSI分析] {TARGET_MAC} のグラフを表示しました")

def start_capture():
    global tcpdump_proc, current_fig
    current_fig = None

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

    threading.Thread(
        target=wait_and_finish,
        args=(pcap_file,),
        daemon=True #フラグで止める
    ).start()

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

    if tcpdump_proc and tcpdump_proc.poll() is None:
        tcpdump_proc.terminate()
        tcpdump_proc.wait()

    plt.close("all")

    # すぐdestroyしない（超重要）
    try:
        root.after(0, root.quit)
        root.after(200, root.destroy)
    except:
        pass

def run_matlab():
    csv_path = os.path.abspath(CSV_FILE)

    matlab_cmd = (
        f"matlab -batch \"main('{csv_path}')\""
    )

    log("[MATLAB] 実行開始")
    subprocess.Popen(matlab_cmd, shell=True)

def save_graph():
    global current_fig

    import os
    import getpass

    if current_fig is None:
        messagebox.showwarning("警告", "先にグラフを生成してください")
        return

    BASE_DIR = "/home/hatake/デスクトップ"

    duration = time_var.get()
    folder_name = f"MAC_{duration}m"
    save_dir = os.path.join(BASE_DIR, folder_name)

    os.makedirs(save_dir, exist_ok=True)

    user = getpass.getuser()

    # ★ フォルダの所有者も変更
    os.system(f"sudo chown -R {user}:{user} '{save_dir}'")

    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(save_dir, f"timeline_{now_str}.png")

    current_fig.savefig(filepath)

    # ★ ファイルも念のため
    os.system(f"sudo chown {user}:{user} '{filepath}'")
    os.chmod(filepath, 0o644)

    log(f"[保存] {filepath}")
    
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
times = [1,2,3,5,10,15,30,60]

for i, t in enumerate(times):
    row = i // 3
    col = i % 3

    label = f"{t}分" if t < 60 else "60分"

    tk.Radiobutton(
        time_frame,
        text=label,
        variable=time_var,
        value=t
    ).grid(row=row, column=col, sticky="ew", padx=5, pady=2)

# 列幅を均等にする
for i in range(3):
    time_frame.grid_columnconfigure(i, weight=1)

mac_frame = tk.LabelFrame(option_frame, text="MAC表示")
mac_frame.pack(side="left", padx=5)
tk.Radiobutton(mac_frame, text="重複削除", variable=mac_mode, value="unique").pack(anchor="w")
tk.Radiobutton(mac_frame, text="複数表示", variable=mac_mode, value="multi").pack(anchor="w")

exclude_frame = tk.Frame(root)
exclude_frame.pack(pady=5)
tk.Checkbutton(exclude_frame, text="滞在時間0秒のMACを除外", variable=exclude_zero_var).pack(anchor="w")

# ===== 横並びの親フレーム =====
main_frame = tk.Frame(root)
main_frame.pack(pady=5)

left_frame = tk.Frame(main_frame)
left_frame.pack(side="left", padx=10)

right_frame = tk.Frame(main_frame)
right_frame.pack(side="left", padx=20, anchor="n")

# ===== 左：ボタン（←ここ重要）=====
start_btn = tk.Button(left_frame, text="② キャプチャ開始", command=start_capture, state="disabled")
start_btn.pack(pady=5)

tk.Button(left_frame, text="③ 滞在時間グラフ生成", command=generate_timeline).pack(pady=5)

tk.Button(left_frame, text="特定MACのRSSI解析", command=generate_target_rssi_graph, fg="darkgreen").pack(pady=5)

tk.Button(left_frame, text="④ グラフ保存", command=save_graph).pack(pady=5)

# ===== 右：検索UI（リアルタイム）=====
search_var = tk.StringVar()

tk.Label(right_frame, text="ログ検索").pack()
# ===== ステータス =====
status_label = tk.Label(root, text="待機中")
status_label.pack()

# ===== ログ表示 =====
log_frame = tk.LabelFrame(root, text="ログ")
log_frame.pack(padx=10, pady=5, fill="both")

log_text = tk.Text(log_frame, height=12)
log_text.pack(fill="both")

# 色設定
log_text.tag_config("green_mac", foreground="limegreen")
log_text.tag_config("highlight", background="yellow")

# ===== リアルタイム検索 =====
def search_log(*args):
    keyword = search_var.get()

    log_text.tag_remove("highlight", "1.0", tk.END)

    if not keyword:
        return

    start = "1.0"

    while True:
        pos = log_text.search(keyword, start, stopindex=tk.END, nocase=True)

        if not pos:
            break

        end = f"{pos}+{len(keyword)}c"
        log_text.tag_add("highlight", pos, end)

        start = end

# 入力で即検索
search_var.trace_add("write", search_log)
    
entry = tk.Entry(right_frame, textvariable=search_var, width=25)
entry.pack(pady=5)

# ===== 終了ボタン =====
tk.Button(root, text="終了", fg="red", command=stop_and_exit).pack(pady=15)

root.mainloop()

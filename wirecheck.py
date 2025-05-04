import os
import glob
import random
import pyshark
import pandas as pd
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import threading
import time
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP  # Add to your imports at the top

FLOW_TIMEOUT = 30  # seconds to forget inactive flows
MAX_SIG_LEN = 8


def normalize_flow(src_ip, src_port, dst_ip, dst_port):
    if (src_ip, int(src_port)) < (dst_ip, int(dst_port)):
        return (src_ip, int(src_port), dst_ip, int(dst_port)), "A"
    else:
        return (dst_ip, int(dst_port), src_ip, int(src_port)), "B"


def extract_aapdus_from_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, display_filter="tcp && tcp.len == 0")
    flows = {}

    try:
        for pkt in cap:
            if "IP" not in pkt or "TCP" not in pkt:
                continue

            try:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                ack = int(pkt.tcp.ack)
                seq = int(pkt.tcp.seq)

                flow_id, _ = normalize_flow(src_ip, src_port, dst_ip, dst_port)

                if flow_id not in flows:
                    flows[flow_id] = {
                        "records": [],
                        "init_ip": src_ip,
                        "init_port": int(src_port),
                        "last_dir": None
                    }

                flow = flows[flow_id]
                is_initiator = (src_ip == flow["init_ip"] and int(src_port) == flow["init_port"])
                current_dir = "A" if is_initiator else "B"

                if flow["last_dir"] != current_dir:
                    apdu = (ack, seq) if is_initiator else (seq, ack)
                    flow["records"].append(apdu)
                    flow["last_dir"] = current_dir

                if len(flow["records"]) >= MAX_SIG_LEN:
                    continue

            except AttributeError:
                continue
    finally:
        cap.close()

    return flows


def convert_flows_to_features(flows, label):
    features = []
    for _, flow in flows.items():
        apdus = flow["records"][:MAX_SIG_LEN]
        flat = [x for tup in apdus for x in tup]
        while len(flat) < MAX_SIG_LEN * 2:
            flat += [0, 0]
        flat.append(label)
        features.append(flat)
    return features


def process_all_pcaps(pcap_root, output_dir, max_pcaps_per_class=100):
    class_pcap_dict = {}

    # Step 1: Organize PCAPs by class (folder name)
    all_pcaps = glob.glob(os.path.join(pcap_root, "**/*.pcap*"), recursive=True)
    for pcap_path in all_pcaps:
        label = os.path.basename(os.path.dirname(pcap_path)).capitalize()
        class_pcap_dict.setdefault(label, []).append(pcap_path)

    # Step 2: Limit number of PCAPs per class
    selected_pcaps = []
    for label, pcaps in class_pcap_dict.items():
        random.shuffle(pcaps)
        selected_pcaps.extend(pcaps[:max_pcaps_per_class])
    
    random.shuffle(selected_pcaps)

    # Step 3: Process each selected pcap
    data = []
    for pcap_path in selected_pcaps:
        label = os.path.basename(os.path.dirname(pcap_path)).capitalize()
        print(f"📥 Processing {pcap_path} → {label}")
        try:
            flows = extract_aapdus_from_pcap(pcap_path)
            features = convert_flows_to_features(flows, label)
            data.extend(features)
        except Exception as e:
            print(f"⚠️ Failed to process {pcap_path}: {e}")

    # Step 4: Save and return
    df = pd.DataFrame(data, columns=[f"feat_{i}" for i in range(MAX_SIG_LEN * 2)] + ["label"])
    full_csv = os.path.join(output_dir, "all_features5.csv")
    df.to_csv(full_csv, index=False)
    print(f"✅ Full dataset saved to: {full_csv}")
    return df



def split_train_test(df, train_ratio=0.7):
    df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)
    split_idx = int(len(df_shuffled) * train_ratio)
    return df_shuffled[:split_idx], df_shuffled[split_idx:]


def train_model(train_df, model_path):
    X_train = train_df.drop("label", axis=1)
    y_train = train_df["label"]
    clf = RandomForestClassifier(criterion="entropy")
    clf.fit(X_train, y_train)
    joblib.dump(clf, model_path)
    print(f"✅ Model saved to: {model_path}")
    return clf


def evaluate_model(clf, test_df):
    X_test = test_df.drop("label", axis=1)
    y_test = test_df["label"]
    y_pred = clf.predict(X_test)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.2f}")


class LiveFlowClassifier:
    def __init__(self, interface, model_path):
        self.interface = interface
        self.model_path = model_path
        self.flows = {}
        self.lock = threading.Lock()
        self.model = joblib.load(self.model_path)
        self.running = True

    def start_capture(self):
        print(f"🚀 Starting Scapy live capture on {self.interface}...")
        sniff(
            iface=self.interface,
            filter="tcp",
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def process_packet(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return

        try: 
            ip = pkt[IP]
            tcp = pkt[TCP]
            

            if len(tcp.payload) > 0:
                return  # Skip non-zero-length payloads
            
            # print(f"Flags: {tcp.flags}")
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport
            ack = tcp.ack
            seq = tcp.seq
            timestamp = pkt.time

            flow_id, _ = normalize_flow(src_ip, src_port, dst_ip, dst_port)

            with self.lock:
                if flow_id not in self.flows:
                    self.flows[flow_id] = {
                        "records": [],
                        "init_ip": src_ip,
                        "init_port": int(src_port),
                        "last_dir": None,
                        "last_seen": timestamp
                    }

                flow = self.flows[flow_id]
                is_initiator = (src_ip == flow["init_ip"] and int(src_port) == flow["init_port"])
                current_dir = "A" if is_initiator else "B"

                if flow["last_dir"] != current_dir:
                    apdu = (ack, seq) if is_initiator else (seq, ack)
                    flow["records"].append(apdu)
                    flow["last_dir"] = current_dir

                flow["last_seen"] = timestamp

                if len(flow["records"]) >= MAX_SIG_LEN:
                    self.classify_flow(flow_id, flow)

        except Exception as e:
            print(f"⚠️ Error processing packet: {e}")
        

    def classify_flow(self, flow_id, flow):
        # Convert to feature using the same function as offline
        features = convert_flows_to_features({flow_id: flow}, label="__live__")
        flat = features[0][:-1]  # Drop label placeholder

        feature_cols = [f"feat_{i}" for i in range(MAX_SIG_LEN * 2)]
        X_live = pd.DataFrame([flat], columns=feature_cols)

        pred_label = self.model.predict(X_live)[0]
        print(f"📡 [Classified] Flow {flow_id} ➡️ Application: {pred_label}")

        # Optional: log the feature vector
        # print(f"🧪 Features: {flat}")

        # Optional: save to CSV
        # X_live["prediction"] = pred_label
        # X_live.to_csv("live_predictions.csv", mode="a", header=not os.path.exists("live_predictions.csv"), index=False)

        # After classification, remove the flow
        del self.flows[flow_id]


    def cleanup_old_flows(self):
        while self.running:
            time.sleep(10)
            now = time.time()
            with self.lock:
                to_remove = [fid for fid, flow in self.flows.items() if (now - flow["last_seen"]) > FLOW_TIMEOUT]
                for fid in to_remove:
                    print(f"🗑️ Cleaning up inactive flow {fid}")
                    del self.flows[fid]

    def stop(self):
        self.running = False

def evaluate_accuracy_vs_max_sig_len(pcap_root, output_dir, min_len=1, max_len=8, step=1, max_pcaps_per_class=50):
    accuracies = []
    sig_lens = []

    for sig_len in range(min_len, max_len+1, step):
        print(f"\n🧪 Evaluating for MAX_SIG_LEN = {sig_len}")

        global MAX_SIG_LEN
        MAX_SIG_LEN = sig_len  # Dynamically change MAX_SIG_LEN globally
        
        # Step 1: Process dataset with new MAX_SIG_LEN
        df = process_all_pcaps(pcap_root, output_dir, max_pcaps_per_class=max_pcaps_per_class)

        # Step 2: Train/test split
        train_df, test_df = split_train_test(df)

        # Step 3: Train model
        model_temp_path = os.path.join(output_dir, f"model_len_{sig_len}.pkl")
        clf = train_model(train_df, model_temp_path)

        # Step 4: Evaluate model
        X_test = test_df.drop("label", axis=1)
        y_test = test_df["label"]
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        
        print(f"✅ Accuracy for MAX_SIG_LEN = {sig_len}: {acc:.3f}")

        sig_lens.append(sig_len)
        accuracies.append(acc)

    # Step 5: Plotting
    plt.figure(figsize=(8,6))
    plt.plot(sig_lens, accuracies, marker='o')
    plt.title("Model Accuracy vs. MAX_SIG_LEN (Number of Direction Switches)")
    plt.xlabel("MAX_SIG_LEN (APDU count)")
    plt.ylabel("Accuracy")
    plt.grid(True)
    plt.xticks(sig_lens)
    plt.savefig("accuracy_vs_max_sig_len.png")

def classify_single_pcap(pcap_path, model_path):
    print(f"🔍 Classifying single pcap: {pcap_path}")
    clf = joblib.load(model_path)
    
    flows = extract_aapdus_from_pcap(pcap_path)
    features = convert_flows_to_features(flows, label="__unknown__")
    
    if not features:
        print("⚠️ No usable flows found in the pcap.")
        return
    
    feature_cols = [f"feat_{i}" for i in range(MAX_SIG_LEN * 2)]
    
    for i, feature in enumerate(features):
        flat = feature[:-1]  # Drop label
        df = pd.DataFrame([flat], columns=feature_cols)
        pred = clf.predict(df)[0]
        print(f"📡 Flow {i+1}: Predicted application ➡️ {pred}")

if __name__ == "__main__":
    mode = input("Choose mode: [train/live/plot/test]: ").strip().lower()
    
    pcap_dir = "/home/lab512/Network-Traffic-Dataset" 
    output_dir = "/home/lab512/dataset_csv"              
    model_path_train = os.path.join(output_dir, "model6.pkl")
    model_path = os.path.join(output_dir, "model4_91%.pkl")
    os.makedirs(output_dir, exist_ok=True)

    if mode == "train":
        print("🚀 Starting end-to-end PCAP classification pipeline...\n")
        pcacp_number = input("Enter number of PCAPs per class (default 100): ").strip()
        df = process_all_pcaps(pcap_dir, output_dir, max_pcaps_per_class=int(pcacp_number) if pcacp_number else 100)
        train_df, test_df = split_train_test(df)
        clf = train_model(train_df, model_path_train)
        evaluate_model(clf, test_df)

    elif mode == "live":
        # interface = input("Enter network interface (e.g., eth0, wlan0, any): ").strip()
        interface = "enp0s31f6"
        classifier = LiveFlowClassifier(interface, model_path)

        cleaner_thread = threading.Thread(target=classifier.cleanup_old_flows, daemon=True)
        cleaner_thread.start()

        try:
            classifier.start_capture()
        except KeyboardInterrupt:
            print("\n🛑 Stopping live capture...")
            classifier.stop()

    elif mode == "plot":
        evaluate_accuracy_vs_max_sig_len(
            pcap_root=pcap_dir,
            output_dir=output_dir,
            min_len=1,    # start from small number of packets
            max_len=10,   # up to longer packet flows
            step=1,       # step size
            max_pcaps_per_class=50
        )
    elif mode == "test":
        pcap_path = input("Enter path to the pcap file: ").strip()
        classify_single_pcap(pcap_path, model_path)

    else:
        print("❌ Invalid mode. Choose 'train', 'live', or 'plot_acc_vs_len'.")



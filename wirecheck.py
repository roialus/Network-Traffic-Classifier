import os
import glob
import random
import pyshark
import pandas as pd
import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

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


if __name__ == "__main__":
    pcap_dir = "/home/lab512/Network-Traffic-Dataset"  # Folder with subfolders like Zoom/, Skype/
    output_dir = "/home/lab512/dataset_csv"
    model_path = os.path.join(output_dir, "model5.pkl")
    os.makedirs(output_dir, exist_ok=True)

    print("🚀 Starting end-to-end PCAP classification pipeline...\n")

    df = process_all_pcaps(pcap_dir, output_dir,max_pcaps_per_class=100)
    train_df, test_df = split_train_test(df)

    clf = train_model(train_df, model_path)
    evaluate_model(clf, test_df)




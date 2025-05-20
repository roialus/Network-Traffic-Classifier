## Encrypted Traffic Classification Using Zero-Length TCP Packets

### This project implements a machine learning–based approach for classifying encrypted network traffic based solely on TCP zero-length packets. The goal is to identify application-level flows without inspecting payloads, using flow direction changes and TCP metadata.

### Features
- Extracts flow-based features from PCAP files using direction-switching zero-length packets (a-APDU)
- Trains a Random Forest classifier to recognize applications (e.g., Zoom, Discord, Facebook)
- Supports batch training, evaluation, and live classification from network interfaces or offline PCAPs
- Visualizes model performance and feature space using PCA and KDE plots

### Structure
- extract_aapdus_from_pcap() – Extracts direction-based flow features
- convert_flows_to_features() – Converts flows to ML-ready vectors
- train_model() / evaluate_model() – Train and test Random Forest classifier
- LiveFlowClassifier – Real-time flow tracking and classification
- classify_single_pcap() – Classifies flows from a PCAP using pre-trained model

### Usage
Run the main script and choose a mode:
```bash
python3 Classify.py
```



### Available modes:
- train – Train a model from a labeled PCAP dataset
- test – Classify flows from a PCAP file using a trained model
- live – Perform real-time classification from a network interface
- plot – Evaluate model accuracy for different flow signature lengths
- compare – Compare feature distributions of old vs. new flows

### Dataset Format
Place PCAP files in subdirectories named after the application (e.g., Zoom/, Discord/). The directory structure should be:

/path/to/dataset/
    ├── Zoom/
    │   ├── capture1.pcap
    │   └── ...
    ├── Discord/
    │   ├── capture1.pcap
    │   └── ...

### Requirements
- Python 3.8+
- scikit-learn
- joblib
- pandas
- pyshark
- scapy
- matplotlib
- seaborn

### Notes
- The classifier relies on consistent flow behavior; training and test captures should reflect realistic usage patterns.
- Only zero-length TCP packets are used to avoid relying on payloads or DPI.

### License
This project is for academic and research use.

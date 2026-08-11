#Anomaly_Detection_For_OT_Netwoeks
### Prerequisites
Make sure you have **Python 3.8+** installed on your system.

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/opc-ua-ids.git
cd opc-ua-ids
```

### 2. Install dependencies
It is recommended to use a virtual environment. Install the required packages using the provided `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 💻 Usage

The pipeline consists of two main steps: Data Generation and Intrusion Detection.

### Step 1: Generate the Synthetic Dataset
Run the data generator to create your synthetic ICS traffic. By default, it generates 3 million rows.
```bash
python opc_synthetic_data_generator_v11.py
```
*Note: This will output a large file named `opc_synthetic_dataset.csv`. Ensure you have sufficient disk space (approx. 2GB).*

### Step 2: Run the Intrusion Detection System
Once the data is generated, run the IDS pipeline to train the Machine Learning models and evaluate their performance.
```bash
python opc_ua_ids_v9.py
```
The script will process the data, train the classifiers, and output visual evaluation metrics (graphs and charts) to the configured output directory.

---

## 🎯 Simulated Attack Vectors

The generator creates a multi-class dataset containing the following network states:

| Label | Classification | Description |
| :---: | :--- | :--- |
| **0** | `Normal Traffic` | Standard read/write operations by known clients on typical industrial tags. |
| **1** | `Unauthorized Access` | Connection attempts by unknown/suspicious endpoints or unverified subnets. |
| **2** | `Tag Modification` | Malicious or accidental modification of critical/safety tags (e.g., emergency stops, high alarm levels). |
| **3** | `New Client Alert` | First-time appearances of unfamiliar client configurations exploring the network. |

---

## ⚙️ Customization

The framework is highly modular and designed for experimentation:
*   **Modify the Network**: Edit `opc_synthetic_data_generator_v11.py` to change client names, critical tags, error rates, and the distribution probabilities of different attacks.
*   **Tune the ML Models**: Adjust hyperparameters for the Random Forest model, cross-validation folds, and visual plotting styles in the configuration section of `opc_ua_ids_v9.py`.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! 
Feel free to check the [issues page](https://github.com/yourusername/opc-ua-ids/issues) if you want to contribute.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

---
<div align="center">
<i>Built with ❤️ for Industrial Cybersecurity</i>
</div>

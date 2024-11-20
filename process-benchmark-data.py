import matplotlib.pyplot as plt
import json

crypto_libs = [
    "p256",
    "sha2",
    "pem_rfc7468",
    "spki",
    "pkcs8",
    "der",
    "der?",
    "x509_cert",
    "serde_json",
    "const_oid",
    "ecdsa",
    "base64ct",
    "sec1",
    "crypto_bigint",
    "heapless",
    "smoltcp",
    "embassy_net",
    "fixed",
    "hash32",
]

def process_size_benchmarks(data_path:str):
    plt.style.use("Solarize_Light2")
    print("processing size benchmarks")
    with open(data_path) as f:
        raw_data = json.load(f)

    fig, ax = plt.subplots()

    file_size_data = [(name, data["raw_size"]/(1024**1)) for (name,data) in raw_data.items()]
    file_text_section = [(name, data["cargo_bloat_crates"]["text-section-size"]/(1024**1)) for (name,data) in raw_data.items()]
    tuf_no_std_size = []
    bt2x_size = []
    libs_size = []
    for (name, data) in raw_data.items():
        crates = data["cargo_bloat_crates"]["crates"]
        size_tuf_no_std = sum(c["size"] for c in crates if c["name"].startswith("tuf_no_std")) / (1024**1)
        size_bt2x = sum(c["size"] for c in crates if c["name"].startswith("bt2x")) / (1024**1)
        size_libs = sum(c["size"] for c in crates if any(c["name"].startswith(l) for l in crypto_libs)) / (1024**1)
        libs_size.append((name, size_libs, size_libs))
        bt2x_size.append((name, size_bt2x + size_libs, size_bt2x))
        tuf_no_std_size.append((name, size_tuf_no_std + size_bt2x + size_libs, size_tuf_no_std))

    tuf_no_std_size = list(zip(*tuf_no_std_size))
    bt2x_size = list(zip(*bt2x_size))
    libs_size = list(zip(*libs_size))
    
    ax.set_ylabel("size in KiB (1024B)")
    ax.bar(*zip(*file_size_data),align="edge", label="Entire Binary", width=0.8)
    ax.bar(*zip(*file_text_section),align="edge", label=".text section", width=0.75, hatch="o")
    ax.bar(tuf_no_std_size[0], tuf_no_std_size[1], align="edge", label="TUF", width=0.7, hatch="+")
    ax.bar(bt2x_size[0], bt2x_size[1],align="edge", label="BT²X", width=0.7, hatch="//")
    ax.bar(libs_size[0], libs_size[1],align="edge", label="Libs", width=0.7, hatch="\\\\")
    ax.legend(loc="upper right")
    
    table_data = {
        "Entire Binary": [f"{v:.2f} KiB" for (_, v) in file_size_data],
        ".text section": [f"{v:.2f} KiB" for (_, v) in file_text_section],
        "TUF": [f"{v:.2f} KiB" for v in  tuf_no_std_size[2]],
        "BT²X": [f"{v:.2f} KiB" for v in  bt2x_size[2]],
        "Libs": [f"{v:.2f} KiB" for v in  libs_size[2]],
    }
    
    table = plt.table(
        colWidths=[0.25, 0.25, 0.25, 0.25],
        cellText=list(table_data.values()),
        rowLabels=list(table_data.keys()),
        colLabels=list(raw_data.keys()),
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    plt.subplots_adjust(left=0.2, bottom=0.2)
    plt.xticks([])
    plt.show()


def process_benchmarks():
    process_size_benchmarks("benchmark-output/benchmarks-size.json")

if __name__ == "__main__":
    print("processing benchmarks")
    process_benchmarks()
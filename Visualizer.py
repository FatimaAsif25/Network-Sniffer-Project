import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load captured data
df = pd.read_csv('packets.csv')

# Plot 1: Protocol Distribution
plt.figure(figsize=(6, 4))
sns.countplot(x='Protocol', data=df)
plt.title("Protocol Distribution")
plt.savefig("report/protocol_distribution.png")
plt.close()

# Plot 2: Top 5 Source IPs
top_src = df['Source IP'].value_counts().nlargest(5)
top_src.plot(kind='bar', title='Top 5 Source IPs')
plt.ylabel('Packets')
plt.savefig("report/top_source_ips.png")
plt.close()

# Plot 3: Top 5 Destination Ports (TCP/UDP)
df['Dst Port'] = pd.to_numeric(df['Dst Port'], errors='coerce')
top_ports = df['Dst Port'].value_counts().nlargest(5)
top_ports.plot(kind='bar', title='Top 5 Destination Ports')
plt.ylabel('Packets')
plt.savefig("report/top_dst_ports.png")
plt.close()

print("[✓] Graphs saved to report/ folder.")

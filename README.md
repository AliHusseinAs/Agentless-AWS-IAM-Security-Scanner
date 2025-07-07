# AWS IAM Security Scanner


##  Overview

The **AWS IAM Security Scanner** is an agentless tool that scans your AWS account for IAM misconfigurations and maps each finding to its corresponding **MITRE ATT&CK techniques** and **CIS benchmarks**. It provides an easy-to-read **interactive graph-based report** to help cloud engineers and security professionals identify risks and improve their cloud security posture.

---

##  Features

1) Scans AWS IAM for common misconfigurations  
2) Maps findings to **MITRE ATT&CK** and **CIS benchmarks**  
3) Generates a **JSON report** for seamless integration with UIs  
4) Built in **Golang** with efficient concurrency (goroutines & mutexes)  
5) Fully **agentless** – no need to install anything on your cloud

---

## Usage

1. **Clone the repository**

```bash
git clone https://github.com/AliHusseinAs/Agentless-AWS-IAM-Security-Scanner.git

```
2. **Create a ReadOnlyAccess IAM user with one access key**
3. **Configure Your Terminal**
   ```bash
   aws configure
   AWS Access Key ID [None]: YOUR_ACCESS_KEY_ID
   AWS Secret Access Key [None]: YOUR_SECRET_ACCESS_KEY
   Default region name [None]: YOUR_REGION
   Default output format [None]: json
4. **Run the Go code then open the index.html page in the web**

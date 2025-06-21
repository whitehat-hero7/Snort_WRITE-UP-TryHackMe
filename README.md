###### ⚠️ `Disclaimer`: This write-up is intended solely for educational purposes to enhance the learner's understanding of cybersecurity concepts, tools, and methodologies. It is carefully written to encourage hands-on practice scripting/programming and using the terminal/shell to write complex commands and avoid revealing flags, specific answers, credentials, or any information that could spoil the learning experience. All credit for the lab content and challenge design goes to TryHackMe as the original source. Learners are encouraged to complete the lab independently before referring to this guide for support.

# Snort_Write-Up (TryHackMe)

<img src="https://github.com/user-attachments/assets/2d627e04-f12d-483d-9a5e-77f669534af0">

## 🔶 Introduction

### ✅ What is Snort?

`Snort` is an open-source, rule-based `Network Intrusion Detection System` (`NIDS`) and `Network Intrusion Prevention System` (`NIPS`). Originally developed by `Martin Roesch`, `Snort` is actively maintained by open-source contributors and the `Cisco Talos` security intelligence and research group.

This room assumes a basic understanding of `Linux` command-line operations, including system navigation and fundamental networking concepts such as ports, protocols, and traffic analysis. As you explore `Snort`, you'll dive into logging and analysis using real-time traffic, pre-captured (`PCAP`) traffic, and custom rule sets that help detect a wide variety of malicious patterns and anomalies.

`Snort` has three main use models:

•	`Sniffer Mode` - Read IP packets and prompt them in the console application.

•	`Packet Logger Mode` - Log all IP packets (inbound and outbound) that visit the network.

•	`NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes` - Log/drop the packets that are deemed as malicious according to the user-defined rules.

## 🔶 Interactive Material and VM

### ✅ Step 1: Machine Deployment

Deploy the machine attached to this room. Once the machine has fully started, you will see a folder named `“Task-Exercises”` on the `Desktop`, which has everything you need. Each exercise has an individual folder and files; use them according to the questions. 

<img width="643" alt="image" src="https://github.com/user-attachments/assets/5dc89012-94f6-4dc2-8842-4fdbb5241f87" />

There are two sub-folders available:

•	`Config-Sample`: Sample configuration and rule files. These files are provided to show what the configuration files look like. Installed `Snort` instance doesn't use them, so feel free to practice and modify them. `Snort's` original base files are located under *`/etc/snort`* folder.

•	`Exercise-Files`: There are separate folders for each task. Each folder contains `PCAP` logs and rule files ready to play with.

![image](https://github.com/user-attachments/assets/698b3ccf-facf-45ff-a5b3-80c0f127bbf2)

### ✅ Step 2: Traffic Generator

The machine is offline, but there is a script `“traffic-generator.sh”` for you to generate traffic to your `Snort` interface. You will use this script to trigger traffic to the `Snort` interface. Once you run the script, it will ask you to choose the exercise type and then automatically open another terminal to show you the output of the selected action.

**Note:** Each traffic is designed for a specific exercise. Make sure you start the `Snort` instance and wait until the end of the script execution. Don't stop the traffic flood unless you choose the wrong exercise. 

As shown below, explore the current directory environment and navigate to the `“Task-Exercises”` folder. Run the `"traffic-generator.sh"` file by executing it as `sudo`. The `“Traffic Generator”` menu with traffic pattern options will appear.

![image](https://github.com/user-attachments/assets/340603d7-c2de-4019-bfcc-885e060bc555)

Once you choose a traffic pattern option, the `“Traffic Generator”` menu disappears and opens a terminal instance with the output as shown below.

![image](https://github.com/user-attachments/assets/fe1549da-5c56-45a7-a62b-4f1d923d0030)

### ✅ Questions:

**`Navigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output.`**

![image](https://github.com/user-attachments/assets/5c98b68b-51ba-406f-a258-17a6e5bdb999)

## 🔶 Introduction to IDS/IPS

![image](https://github.com/user-attachments/assets/a9e2db5c-38dc-4ea3-9f8f-fd3b03ab32d4)

### ✅ Intrusion Detection System (IDS)

An `IDS` is a passive monitoring tool designed to detect potential malicious activity, unusual behavior, and policy violations. Its primary role is to analyze network or system traffic and generate alerts whenever suspicious events are identified.

There are two main types of `IDS` systems:

•	`Network Intrusion Detection System (NIDS)` - monitors traffic across different segments of a network, aiming to analyze the flow of data throughout an entire subnet. When a known signature or pattern is detected, it generates an alert to flag the potential threat.

•	`Host-based Intrusion Detection System (HIDS)` – monitors activity on a single endpoint device. Its purpose is to analyze traffic and behavior specific to that host. When a matching signature or suspicious pattern is detected, it triggers an alert to notify of a potential threat.

### ✅ Intrusion Prevention System (IPS)

An `IPS` is an active security solution designed to prevent malicious activity, abnormal behavior, and policy violations. Unlike `IDS`, it not only detects threats but also takes immediate action to block, stop, or terminate suspicious events upon detection.

There are four main types of `IPS` systems:

•	`Network Intrusion Prevention System (NIPS)` – monitors traffic across multiple segments of the network, with the goal of actively protecting the entire subnet. When a known threat signature is detected, `NIPS` immediately intervenes by blocking or terminating the malicious connection. 

•	`Behavior-based Intrusion Prevention System (Network Behavior Analysis - NBA)` - Behavior-based systems monitor network traffic across multiple segments to safeguard the entire subnet. Instead of relying on known signatures, they analyze patterns of behavior, and if an anomaly is detected, the system proactively terminates the suspicious connection.

`NBA` systems operate much like `NIPS`, but with a crucial difference: they undergo a training (or “`baselining`”) phase to learn what constitutes normal traffic. By establishing this baseline, they can more effectively identify new or unknown threats.

During training, the system learns to distinguish “`normal`” from “`abnormal`” behavior, which is essential for minimizing false positives. If a security breach occurs before the baseline is properly established, the model’s accuracy is severely compromised. Equally important is ensuring the system is well-trained on benign activity so that legitimate traffic isn’t mistakenly flagged as malicious.

•	`Wireless Intrusion Prevention System (WIPS)` - monitors traffic within a wireless network to safeguard against potential attacks targeting wireless communication. When a known threat signature is detected, the system promptly terminates the suspicious connection to prevent harm. 

•	`Host-based Intrusion Prevention System (HIPS)` - actively monitors and protects the activity on a single endpoint device. Its goal is to analyze traffic and behavior specific to that device, and when a malicious signature is detected, it immediately blocks or terminates the suspicious connection.

### ✅ Detection/Prevention Techniques

There are three main detection and prevention techniques used in `IDS` and `IPS` solutions:

| **Technique** | **Approach** |
|-|-|
| `Signature-Based` | This technique relies on rules that identify the specific patterns of the known malicious behavior. This model helps detect known threats. |
| `Behavior-Based` | This technique identifies new threats with new patterns that pass-through signatures. The model compares the known/normal with unknown/abnormal behaviours. This model helps detect previously unknown or new threats. |
| `Policy-Based` | This technique compares detected activities with system configuration and security policies. This model helps detect policy violations. |

### ✅ Questions:

**`Which IDS or IPS type can help you stop the threats on a local machine?`**

**`Which IDS or IPS type can help you detect threats on a local network?`**

**`Which IDS or IPS type can help you detect the threats on a local machine?`**

**`Which IDS or IPS type can help you stop the threats on a local network?`**

**`Which described solution works by detecting anomalies in the network?`**

**`According to the official description of the snort, what kind of NIPS is it?`**

**`NBA training period is also known as ...`**

## 🔶 First Interaction with Snort

### ✅ Step 1: Initiate by verifying the Snort installation and the instance version.

![image](https://github.com/user-attachments/assets/205894e2-72e3-42f1-83ba-96e249373559)

### ✅ Step 2: Before using Snort, ensure the configuration file is valid.

![image](https://github.com/user-attachments/assets/c5b7539c-3ff8-449d-970f-f5bfa7f7005c)

**Note:** "`-T`" is used for testing configuration, and "`-c`" is identifying the configuration file (`snort.conf`). It’s possible to use an additional configuration file by pointing it with "`-c`". 

If the configuration file is valid, you should see the message “`Snort successfully validated the configuration!`”, as shown below.

![image](https://github.com/user-attachments/assets/534e1143-f1b1-44a5-8b1f-24b85190b2b0)

The configuration file is an all-in-one management file of `Snort`. Rules, plugins, detection mechanisms, default actions and output settings are identified here. It is possible to have multiple configuration files for different purposes and cases but can only use one at runtime.

**Note:** Every time you start `Snort`, it automatically shows the default banner and initial information about your setup. You can prevent this by using the "`-q`" parameter.

Common parameters:

| **Parameter** | **Description** |
|-|-|
| *`-V`* | Provides information about current `Snort` instance version. |
| *`-c`* | Identifies the configuration file. |
| *`-T`* | `Snort’s` self-test parameter, you can test your setup with this parameter. |
| *`-q`* | Quiet mode prevents `Snort` from displaying the default banner and initial information about your setup. |

### ✅ Questions:

**`Run the Snort instance and check the build number.`**

(Run the command above that verifies `Snort's` instance version)

**`Test the current instance with "/etc/snort/snort.conf" file and check how many rules are loaded with the current build.`**

(Run the command above that validates the configuration file, then scroll up until you see “`Snort rules read`”, as shown below)

![image](https://github.com/user-attachments/assets/66043a10-7895-456e-a306-bfd281c2564d)

**`Test the current instance with "/etc/snort/snortv2.conf" file and check how many rules are loaded with the current build.`**

(Run the command above that validates the configuration file, this time with “`snortv2.conf`”, then scroll up until you see “`Snort rules read`”, as shown below)

![image](https://github.com/user-attachments/assets/a591c125-b648-4b06-b1fb-4ebddeceb167)

## 🔶 Operation Mode 1: **Sniffer Mode**

![image](https://github.com/user-attachments/assets/06934686-a950-469d-86ae-5fc845bb8091)

Like `tcpdump`, `Snort` has various flags/parameters capable of viewing various data about the packet it is ingesting.

`Sniffer` mode parameters are explained in the table below:

| **Parameter** | **Description** |
|-|-|
| *`-v`* | Verbose, Display the TCP/IP output in the console. |
| *`-d`* | Dump/Display the packet data (payload). |
| *`-e`* | Display the link-layer (TCP/IP/UDP/ICMP) headers. |
| *`-X`* | Display the full packet details in HEX. |
| *`-i`* | This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. |

Start using each parameter and see the difference between them. `Snort` needs active traffic on your interface, so you need to generate traffic to see `Snort` in action.

To do this, use the “`traffic-generator.sh`” script in the “`Task-Exercises`” folder.

### ✅ Sniffing with Parameter (`-i`)

Start the `Snort` instance in `verbose mode` (`-v`) and use the interface (`-i`) "`eth0`":

🔹 *`sudo snort -v -i eth0`*

In case you have only one interface, `Snort` uses it by default. The above example demonstrates to sniff on the interface named "`eth0`". Once you simulate the parameter (`-v`), you will notice it will automatically use the "`eth0`" interface and prompt it.

### ✅ Sniffing with Parameter (`-v`)

Start the `Snort` instance in `verbose mode` (`-v`):

🔹 *`sudo snort -v`*

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

`Verbosity mode` provides `tcpdump` like output information. Once you interrupt the sniffing process with “`CTRL+C`”, it stops and summarizes the sniffed packets.

### ✅ Sniffing with Parameter (`-d`)

Start the `Snort` instance in `dumping packet data mode` (`-d`):

🔹 *`sudo snort -d`*

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

`Packet data payload mode` covers the `verbose mode` and provides more data.

### ✅ Sniffing with Parameter (`-de`)

Start the `Snort` instance in dump (`-d`) and `link-layer header grabbing` (`-e`) mode:

🔹 *`sudo snort -de`*

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

`Packet data payload mode` and `link-layer header grabbing mode`, controls how much detail is printed about each packet to the console or log.

(`-d`): Dump the `application layer data (payload)` of packets in `hex` and `ASCII`. This allows you to see the actual data being transmitted.

(`-e`): Show the `data link layer headers` (such as Ethernet headers) in the packet output.

### ✅ Sniffing with Parameter (`-X`)

Start the `Snort` instance in `full packet dump mode` (`-X`):

🔹 *`sudo snort -X`*

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

Used to `dump the raw packet payload` in both `hex` and `ASCII`. It’s similar to (`-d`), but more detailed in output formatting.

## 🔶 Operation Mode 2: **Packet Logger Mode**

![image](https://github.com/user-attachments/assets/96918fcf-10c1-4e67-963c-889ec43655fd)

You can use `Snort` as a sniffer and log the sniffed packets via logger mode. You only need to use the packet logger mode parameters.

`Packet` logger parameters are explained in the table below:

| **Parameter** | **Description** |
|-|-|
| *`-l`* | Logger mode, target log and alert output directory. Default output folder is `/var/log/snort`. The default action is to dump as `tcpdump` format in `/var/log/snort`. |
| *`-K ASCII`* | Log packets in `ASCII` format. |
| *`-r`* | Reading option, read the dumped logs in `Snort`. |
| *`-n`*| Specify the number of packets that will process/read. `Snort` will stop after reading the specified number of packets. |

Start using each parameter and see the difference between them. `Snort` needs active traffic on your interface, so you need to generate traffic to see `Snort` in action.

To do this, use the “`traffic-generator.sh`” script in the “`Task-Exercises`” folder.

### ✅ Logfile Ownership

`Snort` needs `superuser` "`root`" rights to sniff the traffic, so once you run `Snort` with the "*`sudo`*" command, the "`root`" account will own the generated log files. Therefore you will need "`root`" rights to investigate the log files. 

There are two different approaches to investigate the generated log files: 

•	`Elevation of privileges` - You can elevate your privileges to examine the files. You can use "*`sudo`*" to execute your command as a `superuser`: *`sudo <command>`*. You can also elevate the session privileges and switch to the `superuser` account to examine the generated log files with the following command: *`sudo su`*

•	`Changing the ownership of files/directories` - You can also change the ownership of the file/folder to read it as your user: *`sudo chown <username> <file>`* or *`sudo chown username -R <directory>`*. The (`-R`) parameter helps recursively process the files and directories.

### ✅ Logging with Parameter (`-l`)

First, start the `Snort` instance in packet logger mode: 

🔹 *`sudo snort -dev -l .`*

**Note:** Don’t forget the period (`.`) at the end of the command.

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

Once the traffic is generated, `Snort` will start showing the packets and log them in the target directory. You can configure the default output directory in the `snort.config` file. However, you can use the (`-l`) parameter to set a target directory. Identifying the default log directory is useful for continuous monitoring operations, and the (`-l`) parameter is much more useful for testing purposes. 

The (`-l .`) part of the command creates the logs in the current directory.

![image](https://github.com/user-attachments/assets/54d6406b-d591-4f27-be7b-95d3fc49b06e)

Now, check the generated log file. Note that the log file names will be different in your case.

![image](https://github.com/user-attachments/assets/aaf12fdc-f933-4c27-a822-3a94e5a83e4d)

### ✅ Logging with Parameter (`-K ASCII`)

Start the `Snort` instance in packet logger mode: 

🔹 *`sudo snort -dev -K ASCII -l .`*

Now run the “`traffic-generator.sh`” script as *`sudo`* and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start showing the  packets in `verbosity mode`.

![image](https://github.com/user-attachments/assets/deec7aea-7ea0-4e35-b4c8-1383ec9d21fa)

Now, check the generated log file. Note that the log file names will be different in your case.

![image](https://github.com/user-attachments/assets/ad7ba627-6099-4f87-a9fa-ffc1f172426e)

The logs created with (`-K ASCII`) parameter is entirely different. There are two folders with IP address names. Look into them:

![image](https://github.com/user-attachments/assets/e4e13ba0-3fb6-493c-a6bd-44bf46ea0f12)

Once you look closer at the created folders, you can see that the logs are in `ASCII` and categorized format, so it is possible to read them without using a `Snort` instance.

This is what it looks like in the folder view:

![image](https://github.com/user-attachments/assets/81709562-b87b-4bbf-9c0a-d62c0df7302e)

In a nutshell, `ASCII` mode provides multiple files in human-readable format, so it is possible to read the logs easily by using a text editor. By contrast with `ASCII` format, `binary` format is not human-readable and requires analysis using `Snort` or an application like `tcpdump`.

You can compare the `ASCII` format with the `binary` format by opening both in a text editor. The difference between the `binary` log file and the `ASCII` log file is shown below. (Left side: `binary` format. Right side: `ASCII` format):

![image](https://github.com/user-attachments/assets/353c4a4f-0059-46d2-b0d1-0791f721c115)

### ✅ Reading Generated Logs with Parameter (`-r`)

Start the `Snort` instance in packet reader mode:

🔹 *`sudo snort -r <logname.log>`*

![image](https://github.com/user-attachments/assets/38c06563-5a4a-4e89-83cf-7322697f3258)

Note that `Snort` can read and handle the `binary` like output (`tcpdump` and `Wireshark` also can handle this log format). However, if you create logs with (`-K ASCII`) parameter, `Snort` will not read them. `Snort` will read and display the log file just like in the `sniffer` mode.

Opening log file with `tcpdump`:

![image](https://github.com/user-attachments/assets/18fc7ba4-9e3c-4a81-8cdb-de5cb613712a)

Opening log file with `Wireshark`:

![image](https://github.com/user-attachments/assets/2502d082-3e7d-40ca-a69d-6310eca1c056)

(`-r`) parameter also allows users to filter the `binary` log files. You can filter the processed log to see specific packets with the (`-r`) parameter and `Berkeley Packet Filters` (`BPF`). 

🔹 *`sudo snort -r <logname.log> -X`*

🔹 *`sudo snort -r <logname.log> icmp`*

🔹 *`sudo snort -r <logname.log> tcp`*

🔹 *`sudo snort -r <logname.log> 'udp and port 53'`*

The output will be the same as the above, but only packets with the chosen protocol will be shown. Additionally, you can specify the number of processes with the parameter (`-n`). The following command will process only the first 10 packets:

🔹 *`sudo snort -dvr <logname.log> -n 10`*

### ✅ Questions:

Now, use the attached `VM` and navigate to the `Task-Exercises/Exercise-Files/TASK-6` folder to answer the questions!

![image](https://github.com/user-attachments/assets/15ff8150-79b4-4079-92de-7ce94848eb70)

Investigate the traffic with the default configuration file with `ASCII` mode.

🔹 *`sudo snort -dev -K ASCII -l .`*

![image](https://github.com/user-attachments/assets/06143adc-7597-471e-b9b0-38f9f38c5f10)

Open another tab and navigate to the “`Task-Exercises`”, then execute the `traffic generator` script and choose "`TASK-6 Exercise`", as shown below. Wait until the traffic ends, then stop the `Snort` instance with “`CTRL+C`”. Now analyze the output summary and answer the question.

🔹 *`sudo ./traffic-generator.sh`*

![image](https://github.com/user-attachments/assets/c6ad22f1-c941-4e40-b2ca-a502641193fd)

**`Now, you should have the logs in the current directory. Navigate to folder "145.254.160.237". What is the source port used to connect port 53?`**

![image](https://github.com/user-attachments/assets/5f506f3b-f23e-4178-a006-a338c36f3477)

![image](https://github.com/user-attachments/assets/e577a769-56e9-4034-97d3-f32641a793a3)

**`Use snort.log.1640048004 
Read the snort.log file with Snort; what is the IP ID of the 10th packet?`**

🔹 *`snort -r snort.log.1640048004 -n 10`*

![image](https://github.com/user-attachments/assets/ca12bdcc-a936-44b0-a2b7-3ca1e5b26065)

(Scroll up to the `10th packet` to get its ID)

![image](https://github.com/user-attachments/assets/c81cc9bf-6ad5-475c-bb39-e2452e96eb56)

**`Read the "snort.log.1640048004" file with Snort; what is the referer of the 4th packet?`**

![image](https://github.com/user-attachments/assets/7c68cad4-bf54-4e52-9587-b81d8aae4238)

(Scroll up to the `4th packet` to get the referer)

![image](https://github.com/user-attachments/assets/402c2de0-a03c-4fd5-90e9-de97f139f8e5)

**`Read the "snort.log.1640048004" file with Snort; what is the Ack number of the 8th packet?`**

![image](https://github.com/user-attachments/assets/acea19b1-20ca-4941-813b-f34117bb08ea)

(Scroll up to the `8th packet` to get the Ack number)

![image](https://github.com/user-attachments/assets/3cdcefb3-ad1f-40ae-a551-44ea0d7ff3de)

**`Read the "snort.log.1640048004" file with Snort; what is the number of the "TCP port 80" packets?`**

**Note:** We are not looking at a specific number of packets anymore with “`-n`”.

![image](https://github.com/user-attachments/assets/6a549a0f-007e-42e1-92c2-a116faa69a5f)

![image](https://github.com/user-attachments/assets/eb21be80-3172-46f4-9d2c-6762e045ee1c)

## 🔶 Operation Mode 3: **IDS/IPS**

![image](https://github.com/user-attachments/assets/524d4df8-7537-4bb5-9aa0-89c3a2cd2105)

The capability of `Snort` is not limited to `sniffing` and `logging` the traffic. `IDS/IPS` mode helps you manage the traffic according to user-defined rules.

**Note:** `(N)IDS/IPS` mode depends on the rules and configuration. `TASK-10` summarizes the essential paths, files and variables. Also, `TASK-3` covers configuration testing. Here, we need to understand the operating logic first, and then we will be going into rules in `TASK-9`.

### ✅ Let’s Run Snort in IDS/IPS Mode

`NIDS` mode parameters are explained in the table below:

| **Parameter** | **Description** |
|-|-|
| *`-c`* | Defines the configuration file. |
| *`-T`* | Tests the configuration file. |
| *`-N`* | Disable logging. |
| *`-D`* | Background mode. |
| *`-A`* | Alert modes: 
| | **`full`:** `Full alert` mode, providing all possible information about the alert. This one also is the default mode; once you use (`-A`) and don't specify any mode, `Snort` uses this mode. |
| | **`fast`:** `Fast` mode shows the alert message, timestamp, source and destination IP, along with port numbers. |
| | **`console`:** Provides fast style alerts on the console screen. |
| | **`cmg`:** `CMG` style, basic header details with payload in `hex` and `text` format. |
| | **`none`:** `Disabling alerting`. |

Use each parameter and see the difference between them. `Snort` needs active traffic on your interface, so you need to generate traffic to see `Snort` in action. To do this, use the "`traffic-generator.sh`" script in the "`Task-Exercises`" folder. 

Once you start running `IDS/IPS` mode, you need to use rules. Using a pre-defined `ICMP` rule as an example. The defined rule below will only generate alerts in any direction of `ICMP` packet activity.

*`alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`*

This rule is located in **`/etc/snort/rules/local.rules`**

This module will focus only on the operating modes. `Snort` will create an "`alert`" file if the traffic flow triggers an alert. One last note; once you start running `IDS/IPS` mode, the `sniffing` and `logging` mode will be semi-passive. However, you can activate the functions using the parameters discussed in previous tasks. **`(-i, -v, -d, -e, -X, -l, -K ASCII)`**.

### ✅ IDS/IPS Mode with Parameter (`-c` and `-T`)

🔹 *`sudo snort -c /etc/snort/snort.conf -T`*

This command will check your configuration file and prompt it if there is any misconfiguration in your current setting.

### ✅ IDS/IPS Mode with Parameter (`-N`)

Start the `Snort` instance and `disable logging` by running the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -N`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. This command will `disable logging` mode. The rest of the other functions will still be available (if activated).

The command-line output will provide the information requested with the parameters. So, if you activate `verbosity` (`-v`) or `full packet dump` (`-X`) you will still have the output in the console, but there will be no logs in the log folder.

### ✅ IDS/IPS Mode with Parameter (`-D`)

Start the `Snort` instance in `background` mode with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -D`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start processing the packets and accomplish the given task with additional parameters.

![image](https://github.com/user-attachments/assets/dd4ffb08-9c68-47b7-a059-dc093c722653)

The command-line output will provide the information requested with the parameters. So, if you activate `verbosity` (`-v`) or `full packet dump` (`-X`) with `packet logger` mode (`-l`) you will still have the logs in the logs folder, but there will be no output in the console.

Once you start the `background` mode and want to check the corresponding `process`, you can easily use the "`ps`" command as shown below:

![image](https://github.com/user-attachments/assets/66f7a635-0a84-4a5d-957d-6b87b8f891e6)

If you want to stop the `daemon`, you can easily use the "`kill`" command to stop the process.

![image](https://github.com/user-attachments/assets/aa7ed057-0629-47f0-8d76-f6f57bfba7ab)

Note that `daemon` mode is mainly used to automate `Snort`. This parameter is mainly used in scripts to start the `Snort` service in the `background`. It is not recommended to use this mode unless you have a working knowledge of `Snort` and stable configuration.

### ✅ IDS/IPS Mode with Parameter (`-A`)

There are several alert modes available in `Snort`:

`console` -- Provides fast style alerts on the console screen.

`cmg`-- Provides basic header details with payload in `hex` and `text` format.

`full`-- `Full alert` mode, providing all possible information about the alert.

`fast`-- `Fast` mode, shows the alert message, timestamp, source and destination ıp along with port numbers.

`none`-- Disabling alerting.

In this section, only the "`console`" and "`cmg`" parameters provide alert information in the `console`. It is impossible to identify the difference between the rest of the alert modes via `terminal`. Differences can be identified by looking at generated `logs`. 

"`full`", "`fast`" and "`none`" modes don't provide `console` output, so differences should be identified through `log` formats.

### ✅ IDS/IPS Mode with Parameter (`-A console`)

`Console` mode provides fast style alerts on the console screen. Start the `Snort` instance in `console alert` mode (`-A console`) with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -A console`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start generating alerts according to the provided ruleset defined in the `configuration file`. 

![image](https://github.com/user-attachments/assets/b62b3e79-1477-44d8-b88c-2c23ba6887c3)

### ✅ IDS/IPS Mode with Parameter (`-A cmg`)

`Cmg` mode provides basic header details with payload in `hex` and `text` format. Start the `Snort` instance in `cmg alert` mode (`-A cmg`) with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -A cmg`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start generating alerts according to the provided ruleset defined in the `configuration file`. 

![image](https://github.com/user-attachments/assets/07540f99-61ac-40eb-967a-eb7a86876927)

Compare the `console` and `cmg` outputs before moving on to other alarm types. As you can see in the given outputs above, `console` mode provides basic header and rule information. `Cmg` mode provides full packet details along with rule information. 

### ✅ IDS/IPS Mode with Parameter (`-A fast`)

`Fast` mode provides alert messages, timestamps, and source and destination IP addresses. Remember, there is no `console` output in this mode. Start the `Snort` instance in `fast alert` mode (`-A fast`) with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -A fast`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start generating alerts according to the provided ruleset defined in the `configuration file`. 

![image](https://github.com/user-attachments/assets/cd36b956-345c-4b3e-b0c9-b582884c8569)

Check the alarm file:

![image](https://github.com/user-attachments/assets/e660fc0b-cfed-4cc4-820c-60c43b6e0146)

As seen above, `fast` style alerts contain summary information on the action like direction and alert header.

### ✅ IDS/IPS Mode with Parameter (`-A full`)

`Full` alert mode provides all possible information about the alert. Remember, there is no `console` output in this mode. Start the `Snort` instance in `full` alert mode (`-A full`) with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -A full`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start generating alerts according to the provided ruleset defined in the `configuration file`. 

![image](https://github.com/user-attachments/assets/3486becb-cf79-464a-a29f-13605944369a)

Check the alarm file:

![image](https://github.com/user-attachments/assets/0cf065cf-061e-4ffc-9ac4-1ba32289c928)

 As seen above, `full` style alerts contain all possible information on the action.

### ✅ IDS/IPS Mode with Parameter (`-A none`)

`Disable alerting`. This mode doesn't create the `alert file`. However, it still logs the traffic and creates a `log file` in `binary dump format`. Remember, there is no `console` output in this mode. Start the `Snort` instance in `none alert mode` (`-A none`) with the following command:

🔹 *`sudo snort -c /etc/snort/snort.conf -A none`*

Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic. Once the traffic is generated, `Snort` will start generating alerts according to the provided ruleset defined in the `configuration file`. 

![image](https://github.com/user-attachments/assets/32953d8c-4af1-4294-bc05-bca5517c4408)

As seen in the picture below, there is no `alert file`. `Snort` only generated the `log file`.

![image](https://github.com/user-attachments/assets/141147a6-b789-4fa6-8d18-d02143e70bed)

### ✅ IDS/IPS Mode: “Using rule file without configuration file”

It is possible to run `Snort` only with rules without a `configuration file`. Running the `Snort` in this mode will help you test the user-created rules. However, this mode will provide less performance.

![image](https://github.com/user-attachments/assets/838bfcde-98a5-41b8-8ccf-2ca43ae53a98)

### ✅ IPS Mode and Dropping Packets

`Snort` `IPS mode` activated with *`-Q --daq afpacket`* parameters. You can also activate this mode by editing **`snort.conf`** file. However, you don't need to edit **`snort.conf`** file in the scope of this room. Review the bonus task or `Snort` manual for further information on `daq` and advanced configuration settings: *`-Q --daq afpacket`*

Activate the `Data Acquisition (DAQ)` modules and use the `afpacket` module to use `Snort` as an `IPS`: *`-i eth0:eth1`*

Identifying interfaces note that `Snort` `IPS` requires at least two interfaces to work. Now run the "`traffic-generator.sh`" script as `sudo` and start `ICMP/HTTP` traffic.

![image](https://github.com/user-attachments/assets/a4b539ce-6191-4d60-af7d-8f3a268c72e9)

As seen above, `Snort` blocked the packets this time. We used the same rule with a different action (`drop/reject`). Remember, for the scope of this task; our point is the operating mode, not the rule.

### ✅ Questions:

Investigate the traffic with the default configuration file.

*`sudo snort -c /etc/snort/snort.conf -A full -l .`*

![image](https://github.com/user-attachments/assets/8fb300a9-86d5-4605-b885-d30b9c90c18d)

Open another tab and execute the traffic generator script and choose "`TASK-7 Exercise`". Wait until the traffic stops, then stop the `Snort` instance with "`CTRL+C`". Now analyze the output summary and answer the question.

![image](https://github.com/user-attachments/assets/cd4b637a-7604-449a-bf17-9b7f8f6ffa05)

**`What is the number of the detected HTTP GET methods?`**

(Scroll up and analyze the output summary, search for the `HTTP GET methods`)

![image](https://github.com/user-attachments/assets/44336424-7433-45f3-950b-da671b36de18)

## 🔶 Operation Mode 4: **PCAP Investigation**

![image](https://github.com/user-attachments/assets/4a29831c-00cc-4793-b1f4-61865f118f2a)

Capabilities of `Snort` are not limited to `sniffing`, `logging` and detecting/preventing the threats. `PCAP` read/investigate mode helps you work with `PCAP` files. Once you have a `PCAP` file and process it with `Snort`, you will receive default traffic statistics with alerts depending on your ruleset.

Reading a `PCAP` without using any additional parameters discussed before will only overview the packets and provide statistics about the file. In most cases, this is not very handy. We are investigating the `PCAP` with `Snort` to benefit from the rules and speed up our investigation process by using the known patterns of threats. 

Note that we are close to starting to create rules. Therefore, you need to grasp the working mechanism of the `Snort`, learn the discussed parameters and begin combining the parameters for different purposes.

`PCAP` mode parameters are explained below:

| **Parameter** | **Description** |
|-|-|
| *`-r / --pcap-single=`* | Read a single PCAP |
| *`--pcap-list=""`* | Read PCAPs provided in command (sapce separated) |
| *`--pcap-show`* | Show PCAP name on console during processing |

### ✅ Investigating Single PCAP with Parameter “-r”

For test purposes, you can still test the default reading option with `PCAP` by using the following command:

🔹 *`snort -r icmp-test.pcap`*

Investigate the `PCAP` with the `configuration file` and see what will happen, as shown below.

![image](https://github.com/user-attachments/assets/28bd15e8-ae51-4abd-a820-43e16d5e6183)

The `ICMP` rule got a hit! As seen in the output given, `Snort` identified the traffic and prompted the alerts according to our ruleset.

### ✅ Investigating Multiple PCAPs with Parameter “--pcap-list”

Investigate multiple `PCAPs` with our configuration file and see what will happen:

![image](https://github.com/user-attachments/assets/11215f81-d10b-4ae4-b1df-602bb0db36f4)

Our `ICMP` rule got a hit! As seen in the output given, `Snort` identified the traffic and prompted the alerts according to our ruleset.

Here is one point to notice: we've processed two `PCAPs`, and there are lots of alerts, so it is impossible to match the alerts with provided `PCAPs` without `Snort's` help. We needed to separate the `PCAP` process to identify the source of the alerts, as shown above.

### ✅ Investigating Multiple PCAPs with Parameter “--pcap-show”

Investigate multiple `PCAPs`, distinguish each one, and see what will happen:

![image](https://github.com/user-attachments/assets/525f906b-68e3-4e03-aeac-b6c969131dfd)

Our `ICMP` rule got a hit! As seen in the given output, `Snort` identified the traffic, distinguished each `PCAP` file and prompted the alerts according to our ruleset.

### ✅ Questions:

Now, use the attached `VM` and navigate to the `Task-Exercises/Exercise-Files/TASK-8` folder to answer the questions!

Investigate the `mx-1.pcap` file with the `default configuration` file by running the command shown below:

![image](https://github.com/user-attachments/assets/180d7125-2df8-46ee-b14f-17091cefeb0b)

**`What is the number of the generated alerts?`**

(Scroll up to the “`Action Stats`” section)

![image](https://github.com/user-attachments/assets/f11046ee-e1b5-44d1-8c1b-9acda0fa741d)

**`Keep reading the output. How many TCP Segments are Queued?`**

(Scroll up to the “`Stream Statistics`” section)

![image](https://github.com/user-attachments/assets/6973c794-b019-41de-b2c6-c5e891d73d13)

**`Keep reading the output. How many "HTTP response headers" were extracted?`**

(Scroll up to the “`HTTP Inspect`” section)

![image](https://github.com/user-attachments/assets/16149ead-aa13-4bb1-8dd0-f7cbd17c414a)

Investigate the `mx-1.pcap` file with the `second configuration` file.

![image](https://github.com/user-attachments/assets/646bf53d-e059-442d-910d-cee83cdb2a12)

**`What is the number of the generated alerts?`**

(Scroll up to the “`Action Stats`” section)

![image](https://github.com/user-attachments/assets/5f26fbb5-b878-4819-9fe2-278dfb90b04e)

Investigate the `mx-2.pcap` file with the `default configuration` file.

![image](https://github.com/user-attachments/assets/9f058b27-cb71-48de-baa2-c402bc29e394)

**`What is the number of the generated alerts?`**

(Scroll up to the “`Action Stats`” section)

![image](https://github.com/user-attachments/assets/6b0cdb78-8b9d-4f34-a021-5ba52e103637)

**`Keep reading the output. What is the number of the detected TCP packets?`**

(Scroll up to the “`Breakdown by protocol`” section)

![image](https://github.com/user-attachments/assets/7d92901c-12c2-4b9a-b3ae-aabf4408b1d0)

Investigate the `mx-2.pcap` and `mx-3.pcap` files with the `default configuration` file.

![image](https://github.com/user-attachments/assets/a09b2e6b-baae-47de-bd34-6130fc4ae20b)

**`What is the number of the generated alerts?`**

(Scroll up to the “`Action Stats`” section)

![image](https://github.com/user-attachments/assets/8832991c-bd38-4573-9972-9a475440b911)

## 🔶 Snort Rule Structure

![image](https://github.com/user-attachments/assets/68261607-9ad0-48d1-831d-71f697e217d2)

Remember, once you create a rule, it is a `local rule` and should be in your "`local.rules`" file. This file is located under "`/etc/snort/rules/local.rules`". 

![image](https://github.com/user-attachments/assets/ef0c0a09-550e-477b-9da8-5d23f971575d)

Each rule should have a type of `action`, `protocol`, `source and destination IP`, `source and destination port` and an `option`. Remember, `Snort` is in `passive mode` by default. So most of the time, you will use `Snort` as an `IDS`. You will need to start "`inline mode`" to turn on `IPS mode`. But before you start playing with `inline mode`, you should be familiar with `Snort` features and rules.

The `Snort` rule structure is easy to understand but difficult to produce. You should be familiar with rule options and related details to create efficient rules. It is recommended to practice `Snort` rules and option details for different use cases.

You can always advance your rule creation skills with different rule options by practicing different use cases and studying `rule option` details in depth. We will focus on two actions: "`alert`" for `IDS mode` and "`reject`" for `IPS mode`.

Rules cannot be processed without a header. `Rule options` are "`optional`" parts. However, it is almost impossible to detect sophisticated attacks without using the `rule options`.

![image](https://github.com/user-attachments/assets/be52dbe2-58b8-4b61-b8f6-8c94ad9b4279)

### ✅ IP and Port Numbers

These parameters identify the `source` and `destination IP` addresses and associated `port numbers` filtered for the rule.

| **Filter** | **Rule** | **Description** |
|-|-|-|
| IP Filtering | alert icmp 192.168.1.56 any <> any any (msg: "ICMP Packet From "; sid: 100001; rev:1;) | This rule will create an alert for each ICMP packet originating from the 192.168.1.56 IP address. |
| Filter an IP Range | alert icmp 192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;) | This rule will create an alert for each ICMP packet originating from the 192.168.1.0/24 subnet. |
| Filter multiple IP Ranges | alert icmp [192.168.1.0/24, 10.1.1.0/24] any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;) | This rule will create an alert for each ICMP packet originating from the 192.168.1.0/24 and 10.1.1.0/24 subnets. |
| Exclude IP addresses/ranges | alert icmp !192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;) | "negation operator" is used for excluding specific addresses and ports. Negation operator is indicated with "!". This rule will create an alert for each ICMP packet not originating from the 192.168.1.0/24 subnet. |
| Port Filtering | alert tcp any any <> any 21  (msg: "FTP Port 21 Command Activity Detected"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet sent to port 21. |
| Exclude a specific port | alert tcp any any <> any !21  (msg: "Traffic Activity Without FTP Port 21 Command Channel"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet not sent to port 21. |
| Filter a port range (Type 1) | alert tcp any any <> any 1:1024   (msg: "TCP 1-1024 System Port Activity"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet sent to ports between 1-1024. |
| Filter a port range (Type 2) | alert tcp any any <> any :1024   (msg: "TCP 0-1024 System Port Activity"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet sent to ports less than or equal to 1024. |
| Filter a port range (Type 3) | alert tcp any any <> any 1025: (msg: "TCP Non-System Port Activity"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet sent to source port higher than or equal to 1025. |
| Filter a port range (Type 4) | alert tcp any any <> any [21,23] (msg: "FTP and Telnet Port 21-23 Activity Detected"; sid: 100001; rev:1;) | This rule will create an alert for each TCP packet sent to port 21 and 23. |

### ✅ There are Three Main Rule Options in Snort

**`General Rule Options`** - Fundamental rule options for Snort. 

**`Payload Rule Options`** - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.

**`Non-Payload Rule Options`** - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

### ✅ General Rule Options

🔹 **`msg`**: The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarizes the event.

🔹 **`sid`**: `Snort rule IDs` (`SID`) come with a pre-defined scope, and each rule must have a `SID` in a proper format. There are three different scopes for `SIDs` shown below.

`<100`: Reserved rules

`100-999,999`: Rules came with the build.

`>=1,000,000`: Rules created by user.

Briefly, the rules we create should have `SID` greater than `100,000,000`. Another important point is; `SIDs` should not overlap and must be unique. 

🔹 **`Reference`**: Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a `Common Vulnerabilities and Exposures` (`CVE`) ID or external information. Having references for the rules will always help analysts during the alert and incident investigation.

🔹 **`rev`**: `Snort` rules can be modified and updated for performance and efficiency issues. `Rev` option helps analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique `rev` number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. `Rev` option is only an indicator of how many times the rule had revisions.

### ✅ Payload Detection Rule Options

🔹 **`Content`**: `Payload data`. It matches specific payload data by `ASCII`, `HEX` or both. It is possible to use this option multiple times in a single rule. However, the more you create specific pattern match features, the more it takes time to investigate a packet.

The following rules will create an alert for each `HTTP` packet containing the keyword "`GET`". This rule option is case sensitive!

•	**`ASCII mode`** - *`alert tcp any any <> any 80 (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)`*

•	**`HEX mode`** - *`alert tcp any any <> any 80 (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)`*

🔹 **`Nocase`**: Disabling case sensitivity. Used for enhancing the content searches.

*`alert tcp any any <> any 80 (msg: "GET Request Found"; content:"GET"; nocase; sid: 100001; rev:1;)`*

🔹 **`Fast_pattern`**: Prioritize content search to speed up the payload search operation. By default, `Snort` uses the biggest content and evaluates it against the rules. "`fast_pattern`" option helps you select the initial packet match with the specific value for further investigation. This option always works case insensitive and can be used once per rule. Note that this option is required when using multiple "`content`" options. 

The following rule has two `content options`, and the `fast_pattern` option tells `Snort` to use the first content option (in this case, "`GET`") for the initial packet match.

*`alert tcp any any <> any 80 (msg: "GET Request Found"; content:"GET"; fast_pattern; content:"www"; sid:100001; rev:1;)`*

### ✅ Non-Payload Detection Rule Options

There are rule options that focus on `non-payload data`. These options will help create specific patterns and identify network issues.

🔹 **`ID`**: Filtering the IP id field.

*`alert tcp any any <> any any (msg: "ID TEST"; id:123456; sid: 100001; rev:1;)`*

🔹 **`Flags`**: Filtering the `TCP` flags.

`F - FIN`

`S - SYN`

`R - RST`

`P - PSH`

`A - ACK`

`U - URG`

*`alert tcp any any <> any any (msg: "FLAG TEST"; flags:S; sid: 100001; rev:1;)`*

*`alert tcp any any <> any any (msg: "FLAG TEST"; flags:PA; sid: 100002; rev:1;)`*

🔹 **`Dsize`**: Filtering the packet payload size. `dsize:min<>max`:

`dsize:>100`

`dsize:<100`

*`alert ip any any <> any any (msg: "SEQ TEST"; dsize:100<>300; sid: 100001; rev:1;)`*

🔹 **`Sameip`**: Filtering the source and destination IP addresses for duplication.

*`alert ip any any <> any any (msg: "SAME-IP TEST"; sameip; sid: 100001; rev:1;)`*








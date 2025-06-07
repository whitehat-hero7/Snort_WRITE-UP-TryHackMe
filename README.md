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

•	`Signature-Based` - this technique relies on rules that identify the specific patterns of the known malicious behavior. This model helps detect known threats.

•	`Behavior-Based` - this technique identifies new threats with new patterns that pass-through signatures. The model compares the known/normal with unknown/abnormal behaviours. This model helps detect previously unknown or new threats.

•	`Policy-Based` - this technique compares detected activities with system configuration and security policies. This model helps detect policy violations.

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

`-V` (Provides information about current `Snort` instance version)

`-c` (Identifies the configuration file)

`-T` (`Snort’s` self-test parameter, you can test your setup with this parameter)

`-q` (Quiet mode prevents `Snort` from displaying the default banner and initial information about your setup)

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

(`-v`) -- Verbose, Display the TCP/IP output in the console.

(`-d`) -- Dump/Display the packet data (payload).

(`-e`) -- Display the link-layer (TCP/IP/UDP/ICMP) headers.

(`-X`) -- Display the full packet details in HEX.

(`-i`) -- This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff.

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

(`-l`) -- Logger mode, target log and alert output directory. Default output folder is `/var/log/snort`. The default action is to dump as `tcpdump` format in `/var/log/snort`.

(`-K ASCII`) -- Log packets in `ASCII` format.

(`-r`) -- Reading option, read the dumped logs in `Snort`.

(`-n`) -- Specify the number of packets that will process/read. `Snort` will stop after reading the specified number of packets.

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






# Description
Tool to monitor, scan and analyze network devices

**Contents:**
  - [Technical details](#technical-details)
  - [Requirements](#requirements)
  - [Run](#run)
    - [Pre-launch](#pre-launch)
    - [Launch](#launch)
  - [Custom modules](#custom-modules)
  - [Output](#output)
  - [Docker container](#docker-container)
  - [Acknowledgements](#acknowledgements)
  - [License](#license)


# Technical details
The current implementation take care of the following cases:

- New devices:
  - netauditor is monitoring the network looking for arp packets.

- Current devices:
  - netauditor launches every 5 minutes a burst of arp ping to every
    device in the subnets netauditor is connected to.

On new device detection, netuauditor will execute nmap using cvescannerv2.nse
script.

# Requirements
- nmap
- [CVEScannerV2](https://github.com/scmanjarrez/CVEScannerV2)
- python

# Run
## Pre-launch
In order to execute the script from CVEScannerV2, is it mandatory to have
the following files in your working directory: cvescannerv2.nse, cve.db,
http-paths-vulnerscom.json and http-regex-vulnerscom.json.

> A symbolic link is enough to work

Install the required packages with:
```bash
$ pip install -r requirements.txt
```

## Launch
After required files are in the working directory, launch the tool with:

```bash
$ sudo python netauditor.py
```

> **Note:** Due to arp (packets sent), super user is needed

# Custom modules
In order to create custom logic, create a python file in **extras** folder
with a **main** function, it will be called automatically on launch.

# Output
Scan analysis are generated in **output** folder. Output is divided
in three folders:
- log: containing CVEScannerV2 log output
- json: containing CVEScannerV2 log output as json, for easy processing
- raw: containing NMAP output

# Docker container
We have prepared a container with all dependencies to run netauditor.
```bash
$ docker run -v $PWD/output:/CVEScannerV2/output registry.gast.it.uc3m.es/kubernetesdockerimages/netauditor:latest
```
> **Note**: The output will be stored in $PWD/output.


# Acknowledgements
**This work has been supported by National R&D Project TEC2017-84197-C4-1-R and by
the Comunidad de Madrid project CYNAMON P2018/TCS-4566 and co-financed by European
Structural Funds (ESF and FEDER)**

# License
    netauditor  Copyright (C) 2022-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)

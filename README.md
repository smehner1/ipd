# Ingress Point Detection - IPD 

IPD is an efficient algorithm that accurately identifies traffic ingress points in ISPs of any size using flow-level traces. 
It identifies the specific router and interface through which a particular segment of Internet address space enters the network.
We have deployed IPD for over six years at a major tier-1 ISP with an international network that handles multi-digit Tbit/s traffic levels, and our experience shows that IPD can accurately identify ingress points and scale to high traffic loads on a commodity server. 
IPD enabled the ISP to improve network operations by identifying performance issues and realizing advanced traffic engineering practices.

With the paper's acceptance, we plan to release the IPD implementation, including a prototype ISP scenario within the educational [Mini
Internet environment](https://www.mini-inter.net) environment, to facilitate quick exploration. 
This repository is part of that and contains a Python3 implementation of IPD, optimized for use within the Mini Internet framework. 
Finally, there will be a repository that loads both the Mini Internet repository and this one as git submodules to run a fully automated ISP scenario.

For production deployment, the ISP uses an optimized version written in a different programming language.



### Algorithm

`ipd.py` contains the core implementation. You can adjust parameters or paths using the `ipd.config file or via CLI parameters, with the latter overriding the config file's default settings. The algorithm expects Netflow data via stdin. Here's an example command:

`zcat netflow_file.gz |python3 ipd.py`

IPD generates output in the following format:

```
ts  ip_version	range  confidence  samples/samples_needed  range ingress_router.in_interface
1678191900	4	range	1.000	4112/4096	4.0.0.0/8	SANF.ext_4_SANF
1678192200	4	range	0.997	5793/4096	2.0.0.0/8	BERL.ext_2_MIAM
1678192500	4	range	0.956	8493/4096	4.0.0.0/8	SANF.ext_4_SANF
```


### Router Lookup Tables

For clarity, there's a router lookup table that maps router IPs to names. For example:

```
ip name
179.0.1.1 LOND
179.0.2.1 BARC
179.0.3.1 BER
```



### Ingress Links

IPD requires information about the links through which traffic enters the network. 

```
PEER_SRC_IP=NEWY,IN_IFACE=ext_3_MIAM,&=3
PEER_SRC_IP=SANF,IN_IFACE=ext_3_BARC,&=3
PEER_SRC_IP=NEWY,IN_IFACE=ext_4_BERL,&=4
PEER_SRC_IP=SANF,IN_IFACE=ext_4_BERL,&=4
```

The configuration file for the Mini Internet scenario is located in `ingresslink/mini-internet.gz`.

### Tools

The `tools` directory contains additional scripts needed for preprocessing and integration with the Mini Internet environment.







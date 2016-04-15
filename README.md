# DPDKCap
DPDK-based packet capture tool

## Getting started

dpdkcap works as a standard DPDK application. Thus it needs Environment
Abstraction Layer (EAL) arguments before dpdkcap specific ones:

```bash
./dpdkcap [EAL args] -- [dpdkcap args]
```

Here are dpdkcap available options:

```
  -c, --per_port_c_cores=NB_CORES_PER_PORT
                             Number of cores per port used for capture
                             (default: 1)
  -C, --limit_file_size=SIZE Before writing a packet, check whether the target
                             file excess SIZE bytes. If so, creates a new file.
                             Use "%FCOUNT" within the output file template to
                             index each new file.
  -G, --rotate_seconds=T     Create a new set of files every T seconds. Use
                             strftime formats within the output file template
                             to rename each file accordingly.
  -o, --output=FILE          Output FILE template (don't add the extension).
                             Use "%COREID" for inserting the lcore id into the
                             file name (automatically added if not used).
                             (default: output_%COREID)
  -p, --portmask=PORTMASK    Ethernet ports mask (default: 0x1)
  -s, --snaplen=LENGTH       Snap the capture to snaplen bytes (default:
                             65535).
  -S, --statistics           Print statistics every few seconds
  -w, --num_w_cores=NB_CORES Total number of cores used for writing (default:
                             1)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

```

Check out the [dpdk documentation](http://dpdk.org/doc/guides/index.html) for
more information on EAL arguments.

## Sofware License Agreements

DPDKCap is distributed under the BSD License, see LICENSE.txt.


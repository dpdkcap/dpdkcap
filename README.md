# DPDKCap

DPDKCap is packet capture tool based on DPDK. It provides a multi-port,
multi-core optimized capture with on the fly compression.

## Software License Agreements

DPDKCap is distributed under the BSD License, see LICENSE.txt.

## Getting started

DPDKCap works as a standard DPDK application. Thus it needs Environment
Abstraction Layer (EAL) arguments before dpdkcap specific ones:

```bash
./dpdkcap [EAL args] -- [dpdkcap args]
```

To get a list of available options, run
```bash
./dpdkcap [EAL args] -- --help
```

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
      --logs=FILE            Writes the logs into FILE instead of stderr
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

### Selecting captured cores

From the available ports detected by DPDK, you can select ports to capture by
using the `-p, --portmask` option. This option takes as argument an hexadecimal
mask whose bits represent each port. By default, DPDKCap uses only the first
port (portmask=0x1).

For example, if you want to capture ports 1, 2 and 4, use: `--portmask 0xb`

### Allocating lcores

DPDKCap assigns two different tasks to lcores:
- Capturing cores enqueue packets from Ethernet ports queues into a main
  buffer. Each captured port must be assigned at least a core.
- Writing cores extract packets from this buffer and write them into LZO
  compressed pcap capture files. Each writing core writes into a different
  file.

As a consequence, DPDKCap needs, at least, a single writing core and as many
capturing cores as ports you want to capture. A last master core must be kept
to display logs and display statistics. However, depending on your traffic
bandwidth and your system capabilities, you might need to use more cores.

The `-c, --per_port_c_cores` option allocates `NB_CORES_PER_PORT` capturing
cores **per selected port**.

The `-w, --num_w_cores` option allocates a **total** of `NB_CORES` writing
cores.

Note that the writing task requires more computational power than the capture
one (due to compression), thus you will probably need to allow more writing
cores than capture ones. This being said, size your storage system accordingly,
as thousands cores could not achieve a full capture with a too low storage
system bandwidth.

### Limiting file size or duration

Depending on the data you want to capture, you might need to split the capture
into several files. Two options are available to limit file size/duration:
- The `-G, --rotate_seconds` option creates a new file every `T` seconds.
- The `-C, --limit_file_size` option creates a new file when the current file
  size goes over the specified `SIZE`.

You can specify the output file template using the `-o, --output` option. This
is necessary with the `-G, --rotate_seconds` option if you do not want to erase
the same file again and again. See the following section.

### Output template

The `-o,--output` let you provide a template for the output file. This template
is formatted according to the following tokens:

- `%COREID` this is replaced by the writing core id into the filename. This
  token is mandatory and will be automatically appended to the output file
  template if not present.

- `%FCOUNT` this is replaced by a counter that allows distinguishing files
  created by the `-C, --limit_file_size` option. If this option is used, this
  token is mandatory and will be automatically appended to the output file
  template if not present.

- Date *strftime* tokens. These tokens are replaced according to *strftime*
  standard. This date is updated every time the `-G, --rotate_seconds` option
  triggers a file change. These tokens are not mandatory with this option, but
  you might overwrite previously created files.

### Other options
- `-s, --snaplen` limits the packet capture to LENGTH bytes.
- `-S, --statistics` prints a set of running statistics while the capture is
  running.
- `--logs` output logs into the specified file instead of stderr.



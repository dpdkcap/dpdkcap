# dpdkcap
DPDK-based packet capture tool

## Getting started

dpdkcap works as a standard DPDK application. Thus it needs Environment
Abstraction Layer (EAL) arguments before dpdkcap specific ones:

```bash
./dpdkcap [EAL args] -- [dpdkcap args]
```

Here are dpdkcap available options:

```
  -c, --num_c_cores=NUM      Number of cores used for capture (default: 1)
  -o, --output=FILE          Output to FILE (don't add the extension) (default:
                             output)
  -s, --snaplen=NUM          Snap the capture to snaplen bytes (default:
                             65535).
  -S, --statistics           Print statistics every few seconds
  -w, --num_w_cores=NUM      Number of cores used for writing (default: 1)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

Check out the [dpdk documentation](http://dpdk.org/doc/guides/index.html) for
more information on EAL arguments.



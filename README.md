# goebpf - eBPF library in Go

This package provides a very simple library for handling eBPF programs. It
provides a header file that have to be used to compile eBPF elf binary.

## Dependencies

There is no dependency to use the Go library but there are dependencies to build
eBPF elf binaries. In order to build an eBPF program this package provides the
header file libbpf.h. LLVM/Clang with the support of bpf as target must
be available.

 * clang >= version 3.4.0
 * llvm >= version 3.7.0

## Install

You can use go get command to retrieve the package:

```console
go get github.com/safchain/goebpf
```

## Examples

In the examples folder there is a test file in Go and there is also a eBPF
C file that will be loaded by the Go file once compiled. The Makefile in the
examples folder will show to compile eBPF program.

In order to simply build the examples :

```
make examples
```

## Documentation

Further informations can be found here :

https://github.com/torvalds/linux/tree/master/samples/bpf


## License
This software is licensed under the Apache License, Version 2.0 (the
"License"); you may not use this software except in compliance with the
License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

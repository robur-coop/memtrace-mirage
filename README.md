# memtrace-mirage

A streaming client for OCaml's Memprof, which generates compact traces
of a program's memory use. The trace is transferred to a TCP listener.

To profile the memory use of a unikernel, start by putting this line
somewhere at the unikernel start:

```OCaml
module Memtrace = Memtrace.Make(Pclock)(S.TCPV4)

let start () s =
  S.TCPV4.create_connection (S.tcpv4 s) (Ipaddr.V4.of_string_exn "10.0.0.1", 1234) >|= function
  | Ok flow -> Memtrace.start_tracing ~sampling_rate:1e-4 ~context:"my unikernel" flow
  | Error _ -> ()
```

The ~context parameter is optional, and can be set to any string that
helps to identify the trace file.

The resulting trace files can be analysed with some simple
command-line tools from the memtrace opam package, or the memtrace_viewer opam
package.

Code based on [memtrace](https://github.com/janestreet/memtrace.git).

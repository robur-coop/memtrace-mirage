# memtrace-mirage

A streaming client for OCaml's Memprof, which generates compact traces
of a program's memory use. The trace is transferred via TCP.

To profile the memory use of a unikernel, there are two options. Either the
unikernel establishes a TCP connection to a listener which dumps the trace into
a file, or the unikernel offers a service where upon connection of a client,
the trace is dumped to.

As preparation in both cases, you need to install this package by executing
`opam install memtrace-mirage` and add `~packages:[ package "memtrace-mirage" ]`
to your `config.ml` where you call `Mirage.foreign`.

## From the start: establish a client connection from the unikernel

To trace the entire lifetime of the unikernel, create a client connection at
startup where the trace is dumped to disk:

Run `nc -l 1234 > my-unikernel.trace` to dump the trace into a file before
starting the unikernel.

In the `unikernel.ml`, add the following code to the `start` function:

```OCaml
module Memtrace = Memtrace.Make(Pclock)(S.TCP)

let start () s =
  (S.TCP.create_connection (S.tcp s) (Ipaddr.of_string_exn "10.0.0.1", 1234) >|= function
   | Ok flow -> ignore (Memtrace.start_tracing ~context:None ~sampling_rate:1e-4 flow)
   | Error e -> Logs.warn (fun m -> m "couldn't connect to tracing sink %a"
                             S.TCP.pp_error e)) >>= fun () ->
  ... rest of start ...
```

## The unikernel provides a service for a single client

As soon as a client connects, tracing is started. The tracing is only stopped
when the client disconnects. Only a single client is permitted.

First start the unikernel, then execute `nc 10.0.0.2 1234 > my-unikernel.trace`.
Quit the `nc` process once you like to stop tracing.

In the `unikernel.ml`, add the following code:

```OCaml
module Memtrace = Memtrace.Make(Pclock)(S.TCP)

let start () s =
  let tracing = ref false in
  S.TCP.listen (S.tcp s) ~port:1234
    (fun f ->
       (* only allow a single tracing client *)
       if !tracing then begin
         Logs.warn (fun m -> m "tracing already active");
         S.TCP.close f
       end else begin
         Logs.info (fun m -> m "starting tracing");
         let tracer = Memtrace.start_tracing ~context:None ~sampling_rate:1e-4 f in
         tracing := true;
         Lwt.async (fun () ->
           S.TCP.read f >|= fun _ ->
           Logs.warn (fun m -> m "tracing read returned, closing");
           Memtrace.stop_tracing tracer;
           tracing := false);
         Lwt.return_unit
       end);
  ... rest of start ...
```

# Trace file analysis

The resulting trace files can be analysed with some simple command-line tools
from the `memtrace` opam package, but the recommended interface is the memtrace
viewer, which lives at:

    https://github.com/janestreet/memtrace_viewer

This repository code is based on
[memtrace](https://github.com/janestreet/memtrace.git).

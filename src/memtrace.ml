module Make (P : Mirage_clock.PCLOCK) (F : Mirage_flow.S) = struct

module Trace = Trace.Make(P)

(** Use Memprof_tracer in conjunction with Trace.Writer for more manual
    control over trace collection *)
module Memprof_tracer = Memprof_tracer.Make(Trace)

type tracer = Memprof_tracer.t

let getpid64 () = -1L

let default_sampling_rate = 1e-6

let start_tracing ~context ?(sampling_rate = default_sampling_rate) flow =
  if Memprof_tracer.active_tracer () <> None then
    failwith "Only one Memtrace instance may be active at a time";
  let info : Trace.Info.t =
    { sample_rate = sampling_rate;
      word_size = Sys.word_size;
      executable_name = Sys.executable_name;
      host_name = "mirage_unikernel";
      ocaml_runtime_params = Sys.runtime_parameters ();
      pid = getpid64 ();
      start_time = Trace.Timestamp.now ();
      context;
    } in
  let stream, pushf = Lwt_stream.create () in
  let trace = Trace.Writer.create pushf ~getpid:getpid64 info in
  let tracer = Memprof_tracer.start ~sampling_rate trace in
  Lwt.async (fun () ->
      let open Lwt.Infix in
      let rec go () =
        (* print_endline "go"; *)
        Lwt_stream.get stream >>= function
        | None -> F.close flow
        | Some ev ->
          F.write flow ev >>= function
          | Ok () -> go ()
          | Error we ->
            print_endline ("tracing stopped due to write error: " ^
                            Fmt.to_to_string F.pp_write_error we);
            Memprof_tracer.stop tracer;
            Lwt.return_unit
      in
      go ());
  tracer

let stop_tracing t =
  Memprof_tracer.stop t

let () =
  at_exit (fun () -> Option.iter stop_tracing (Memprof_tracer.active_tracer ()))

module External = struct
  type token = Memprof_tracer.ext_token
  let alloc = Memprof_tracer.ext_alloc
  let free = Memprof_tracer.ext_free
end
end

module Geometric_sampler = Geometric_sampler

module Make (P : Mirage_clock.PCLOCK) (F : Mirage_flow.S) = struct

  module Trace = Trace.Make(P)

  type tracer =
    { mutable locked : bool;
      mutable failed : bool;
      mutable stopped : bool;
      report_exn : exn -> unit;
      trace : Trace.Writer.t }

  let[@inline never] lock_tracer s =
    (* This is a maximally unfair spinlock. *)
    if s.locked then Printf.fprintf stderr "contention\n%!";
    (* while s.locked do Thread.yield () done; *)
    if s.failed then
      false
    else
      (s.locked <- true; true)

  let[@inline never] unlock_tracer s =
    assert (s.locked && not s.failed);
    s.locked <- false

  let[@inline never] mark_failed s e =
    assert (s.locked && not s.failed);
    s.failed <- true;
    s.locked <- false;
    s.report_exn e

  let default_report_exn e =
    let msg = Printf.sprintf "Memtrace failure: %s\n" (Printexc.to_string e) in
    output_string stderr msg;
    Printexc.print_backtrace stderr;
    flush stderr

  let start ?(report_exn=default_report_exn) ~sampling_rate trace =
    let s = { trace; locked = false; stopped = false; failed = false; report_exn } in
    let tracker : (_,_) Gc.Memprof.tracker = {
      alloc_minor = (fun info ->
          if lock_tracer s then begin
            match Trace.Writer.put_alloc_with_raw_backtrace trace (Trace.Timestamp.now ())
                    ~length:info.size
                    ~nsamples:info.n_samples
                    ~is_major:false
                    ~callstack:info.callstack
            with
            | r -> unlock_tracer s; Some r
            | exception e -> mark_failed s e; None
          end else None);
      alloc_major = (fun info ->
          if lock_tracer s then begin
            match Trace.Writer.put_alloc_with_raw_backtrace trace (Trace.Timestamp.now ())
                    ~length:info.size
                    ~nsamples:info.n_samples
                    ~is_major:true
                    ~callstack:info.callstack
            with
            | r -> unlock_tracer s; Some r
            | exception e -> mark_failed s e; None
          end else None);
      promote = (fun id ->
          if lock_tracer s then
            match Trace.Writer.put_promote trace (Trace.Timestamp.now ()) id with
            | () -> unlock_tracer s; Some id
            | exception e -> mark_failed s e; None
          else None);
      dealloc_minor = (fun id ->
          if lock_tracer s then
            match Trace.Writer.put_collect trace (Trace.Timestamp.now ()) id with
            | () -> unlock_tracer s
            | exception e -> mark_failed s e);
      dealloc_major = (fun id ->
          if lock_tracer s then
            match Trace.Writer.put_collect trace (Trace.Timestamp.now ()) id with
            | () -> unlock_tracer s
            | exception e -> mark_failed s e) } in
    Gc.Memprof.start
      ~sampling_rate
      ~callstack_size:max_int
      tracker;
    s

  let stop s =
    if not s.stopped then begin
      s.stopped <- true;
      Gc.Memprof.stop ();
      if lock_tracer s then
        Trace.Writer.close s.trace
    end

  let getpid64 () = -1L

  let active_tracer : tracer option ref = ref None

  let default_sampling_rate = 1e-6

  let start_tracing ~context ?(sampling_rate = default_sampling_rate) flow =
    if !active_tracer <> None then
      failwith "Only one Memtrace instance may be active at a time";
    let info : Trace.Info.t =
      { sample_rate = sampling_rate;
        word_size = Sys.word_size;
        executable_name = Sys.executable_name;
        host_name = "mirage_unikernel"; (* TODO *)
        ocaml_runtime_params = Sys.runtime_parameters ();
        pid = getpid64 ();
        start_time = Trace.Timestamp.now ();
        context;
      } in
    let stream, pushf = Lwt_stream.create () in
    Lwt.async (fun () ->
        let open Lwt.Infix in
        let rec go () =
          Lwt_stream.get stream >>= function
          | None -> F.close flow
          | Some ev ->
            F.write flow ev >>= function
            | Ok () -> go ()
            | Error we -> Lwt.fail_with (Fmt.to_to_string F.pp_write_error we)
        in
        go ());
    let trace = Trace.Writer.create pushf ~getpid:getpid64 info in
    let tracer = start ~sampling_rate trace in
    active_tracer := Some tracer;
    tracer

  let stop_tracing t =
    stop t;
    active_tracer := None

  let () =
    at_exit (fun () -> Option.iter stop_tracing !active_tracer)
end

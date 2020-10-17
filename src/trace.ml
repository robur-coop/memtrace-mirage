module Make (P : Mirage_clock.PCLOCK) = struct

  (* This is the implementation of the encoder/decoder for the memtrace
     format. This format is quite involved, and to understand it it's
     best to read the CTF specification and comments in memtrace.tsl
     first. *)

  (* Increment this when the format changes in an incompatible way *)
  let memtrace_version = 2

  (* If this is true, then all backtraces are immediately decoded and
     verified after encoding. This is slow, but helpful for debugging. *)
  let cache_enable_debug = false

  open Buf
  (* Utility types *)

  (* Time since the epoch *)
  module Timestamp = struct
    type t = int64

    let of_int64 t = t
    let to_int64 t = t

    let to_float t =
      (Int64.to_float t) /. 1_000_000.

    let of_float f =
      f *. 1_000_000. |> Int64.of_float

    let now () =
      of_float Ptime.(to_float_s (v (P.now_d_ps ())))
  end

  (* Time since the start of the trace *)
  module Timedelta = struct
    type t = int64

    let to_int64 t = t
    let offset = Int64.add
  end

  (** CTF packet headers *)

  (* Small enough that Unix.write still does single writes.
     (i.e. below 64k) *)
  let max_packet_size = 1 lsl 15

  (* When writing a packet, some fields can be filled in only once the
     packet is complete. *)
  type ctf_header_offsets =
    { off_packet_size : Write.position_32;
      off_timestamp_begin : Write.position_64;
      off_timestamp_end : Write.position_64;
      off_flush_duration : Write.position_32;
      off_alloc_begin : Write.position_64;
      off_alloc_end : Write.position_64 }

  let put_ctf_header b getpid cache =
    let open Write in
    put_32 b 0xc1fc1fc1l;
    let off_packet_size = skip_32 b in
    let off_timestamp_begin = skip_64 b in
    let off_timestamp_end = skip_64 b in
    let off_flush_duration = skip_32 b in
    put_16 b memtrace_version;
    put_64 b (getpid ());
    begin match cache with
      | Some c -> Backtrace_codec.Writer.put_cache_verifier c b
      | None -> Backtrace_codec.Writer.put_dummy_verifier b
    end;
    let off_alloc_begin = skip_64 b in
    let off_alloc_end = skip_64 b in
    {off_packet_size;
     off_timestamp_begin;
     off_timestamp_end;
     off_flush_duration;
     off_alloc_begin;
     off_alloc_end}

  let finish_ctf_header hdr b
      ~timestamp_begin ~timestamp_end ~alloc_id_begin ~alloc_id_end =
    let open Write in
    let size = b.pos in
    update_32 b hdr.off_packet_size (Int32.mul (Int32.of_int size) 8l);
    update_64 b hdr.off_timestamp_begin timestamp_begin;
    update_64 b hdr.off_timestamp_end timestamp_end;
    (* CR-someday sdolan: is flush duration useful? *)
    update_32 b hdr.off_flush_duration 0l;
    update_64 b hdr.off_alloc_begin (Int64.of_int alloc_id_begin);
    update_64 b hdr.off_alloc_end (Int64.of_int alloc_id_end)


  (** Event headers *)

  type evcode =
    | Ev_trace_info
    | Ev_location
    | Ev_alloc
    | Ev_promote
    | Ev_collect
    | Ev_short_alloc of int
  let event_code = function
    | Ev_trace_info -> 0
    | Ev_location -> 1
    | Ev_alloc -> 2
    | Ev_promote -> 3
    | Ev_collect -> 4
    | Ev_short_alloc n ->
      assert (1 <= n && n <= 16);
      100 + n

  let event_header_time_len = 25
  let event_header_time_mask = 0x1ffffffl
  (* NB: packet_max_time is less than (1 lsl event_header_time_len) microsecs *)
  let packet_max_time = 30 * 1_000_000


  let put_event_header b ev time =
    let open Write in
    let code =
      Int32.(logor (shift_left (of_int (event_code ev))
                      event_header_time_len)
               (logand (Int64.to_int32 time) event_header_time_mask)) in
    put_32 b code

  module Location = Location_codec.Location


  (** Trace info *)

  module Info = struct
    type t = {
      sample_rate : float;
      word_size : int;
      executable_name : string;
      host_name : string;
      ocaml_runtime_params : string;
      pid : Int64.t;
      start_time : Timestamp.t;
      context : string option;
    }
  end

  let put_trace_info b (info : Info.t) =
    let open Write in
    put_event_header b Ev_trace_info info.start_time;
    put_float b info.sample_rate;
    put_8 b info.word_size;
    put_string b info.executable_name;
    put_string b info.host_name;
    put_string b info.ocaml_runtime_params;
    put_64 b info.pid;
    let context = match info.context with None -> "" | Some s -> s in
    put_string b context


  (** Trace writer *)

  type writer = {
    dest : Cstruct.t option -> unit;
    getpid : unit -> int64;
    loc_writer : Location_codec.Writer.t;
    cache : Backtrace_codec.Writer.t;
    debug_reader_cache : Backtrace_codec.Reader.t option;

    (* Locations that missed cache in this packet *)
    mutable new_locs : (int * Location.t list) array;
    mutable new_locs_len : int;
    new_locs_buf : Bytes.t;

    (* Last allocation callstack *)
    mutable last_callstack : int array;

    mutable start_alloc_id : int; (* alloc ID at start of packet *)
    mutable next_alloc_id : int;
    mutable packet_time_start : Timestamp.t;
    mutable packet_time_end : Timestamp.t;
    mutable packet_header : ctf_header_offsets;
    mutable packet : Write.t;
  }

  let write_fd fd b =
    let open Write in
    fd (Some (Cstruct.of_bytes ~len:b.pos b.buf))

  let make_writer dest ?getpid (info : Info.t) =
    let open Write in
    let getpid = match getpid with
      | Some getpid -> getpid
      | None -> fun () -> info.pid in
    let packet = Write.of_bytes (Bytes.make max_packet_size '\042') in
    begin
      (* Write the trace info packet *)
      let hdr = put_ctf_header packet getpid None in
      put_trace_info packet info;
      finish_ctf_header hdr packet
        ~timestamp_begin:info.start_time
        ~timestamp_end:info.start_time
        ~alloc_id_begin:0
        ~alloc_id_end:0;
      write_fd dest packet;
    end;
    let packet = Write.of_bytes packet.buf in
    let packet_header = put_ctf_header packet getpid None in
    let cache = Backtrace_codec.Writer.create () in
    let debug_reader_cache =
      if cache_enable_debug then
        Some (Backtrace_codec.Reader.create ())
      else
        None in
    let s =
      { dest;
        getpid;
        loc_writer = Location_codec.Writer.create ();
        new_locs = [| |];
        new_locs_len = 0;
        new_locs_buf = Bytes.make max_packet_size '\042';
        cache = cache;
        debug_reader_cache;
        last_callstack = [| |];
        next_alloc_id = 0;
        start_alloc_id = 0;
        packet_time_start = info.start_time;
        packet_time_end = info.start_time;
        packet_header;
        packet } in
    s

  module IntTbl = Hashtbl.MakeSeeded (struct
      type t = int
      let hash _seed (id : t) =
        let h = id * 189696287 in
        h lxor (h lsr 23)
      let equal (a : t) (b : t) = a = b
    end)

  module Obj_id = struct
    type t = int
    module Tbl = IntTbl
  end

  module Location_code = struct
    type t = int
    module Tbl = IntTbl
  end

  module Event = struct
    type t =
      | Alloc of {
          obj_id : Obj_id.t;
          length : int;
          nsamples : int;
          is_major : bool;
          backtrace_buffer : Location_code.t array;
          backtrace_length : int;
          common_prefix : int;
        }
      | Promote of Obj_id.t
      | Collect of Obj_id.t

    let to_string decode_loc = function
      | Alloc {obj_id; length; nsamples; is_major;
               backtrace_buffer; backtrace_length; common_prefix} ->
        let backtrace =
          List.init backtrace_length (fun i ->
              let s = backtrace_buffer.(i) in
              match decode_loc s with
              | [] -> Printf.sprintf "$%d" (s :> int)
              | ls -> String.concat " " (List.map Location.to_string ls))
          |> String.concat " " in
        Printf.sprintf "%010d %s %d len=%d % 4d: %s"
          (obj_id :> int) (if is_major then "alloc_major" else "alloc")
          nsamples length common_prefix
          backtrace;
      | Promote id ->
        Printf.sprintf "%010d promote" (id :> int)
      | Collect id ->
        Printf.sprintf "%010d collect" (id :> int)
  end

  let log_new_loc s loc =
    let alen = Array.length s.new_locs in
    assert (s.new_locs_len <= alen);
    if s.new_locs_len = alen then begin
      let new_len = if alen = 0 then 32 else alen * 2 in
      let locs = Array.make new_len loc in
      Array.blit s.new_locs 0 locs 0 alen;
      s.new_locs <- locs;
      s.new_locs_len <- alen + 1
    end else begin
      s.new_locs.(s.new_locs_len) <- loc;
      s.new_locs_len <- s.new_locs_len + 1
    end

  (** Flushing *)

  let flush_at s ~now =
    let open Write in
    (* First, flush newly-seen locations.
       These must be emitted before any events that might refer to them *)
    let i = ref 0 in
    while !i < s.new_locs_len do
      let b = Write.of_bytes s.new_locs_buf in
      let hdr = put_ctf_header b s.getpid None in
      while !i < s.new_locs_len
            && remaining b > Location_codec.Writer.max_length do
        put_event_header b Ev_location s.packet_time_start;
        Location_codec.Writer.put_location s.loc_writer b s.new_locs.(!i);
        incr i
      done;
      finish_ctf_header hdr b
        ~timestamp_begin:s.packet_time_start
        ~timestamp_end:s.packet_time_start
        ~alloc_id_begin:s.start_alloc_id
        ~alloc_id_end:s.start_alloc_id;
      write_fd s.dest b
    done;
    (* Next, flush the actual events *)
    finish_ctf_header s.packet_header s.packet
      ~timestamp_begin:s.packet_time_start
      ~timestamp_end:s.packet_time_end
      ~alloc_id_begin:s.start_alloc_id
      ~alloc_id_end:s.next_alloc_id;
    write_fd s.dest s.packet;
    (* Finally, reset the buffer *)
    s.packet_time_start <- now;
    s.packet_time_end <- now;
    s.new_locs_len <- 0;
    s.packet <- Write.of_bytes s.packet.buf;
    s.start_alloc_id <- s.next_alloc_id;
    s.packet_header <- put_ctf_header s.packet s.getpid (Some s.cache)

  let max_ev_size =
    100 (* upper bound on fixed-size portion of events
           (i.e. not backtraces or locations) *)
    + max Location_codec.Writer.max_length Backtrace_codec.Writer.max_length

  let begin_event s ev ~(now : Timestamp.t) =
    let open Write in
    if remaining s.packet < max_ev_size
       || s.new_locs_len > 128
       || Int64.(sub now s.packet_time_start > of_int packet_max_time) then
      flush_at s ~now;
    s.packet_time_end <- now;
    put_event_header s.packet ev now

  let flush s = flush_at s ~now:s.packet_time_end

  let find_common_suffix (prev : int array) (curr : int array) =
    let i = ref (Array.length curr - 1)
    and j = ref (Array.length prev - 1) in
    while !i >= 0 && !j >= 0 do
      if Array.unsafe_get curr !i = Array.unsafe_get prev !j then begin
        decr i;
        decr j
      end else begin
        j := -1
      end
    done;
    !i

  type alloc_length_format =
    | Len_short of Write.position_8
    | Len_long of Write.position_16

  let put_alloc s now ~length ~nsamples ~is_major
      ~callstack ~callstack_as_ints ~decode_callstack_entry =
    let open Write in
    let suff = find_common_suffix s.last_callstack callstack_as_ints in
    s.last_callstack <- callstack_as_ints;
    let is_short =
      1 <= length && length <= 16
      && not is_major
      && nsamples = 1
      && suff < 255 in
    begin_event s (if is_short then Ev_short_alloc length else Ev_alloc) ~now;
    let id = s.next_alloc_id in
    s.next_alloc_id <- id + 1;
    let cache = s.cache in
    let b = s.packet in
    let common_pfx_len = Array.length callstack_as_ints - 1 - suff in
    let bt_len_off =
      if is_short then begin
        put_vint b common_pfx_len;
        Len_short (skip_8 b)
      end else begin
        put_vint b length;
        put_vint b nsamples;
        put_8 b (if is_major then 1 else 0);
        put_vint b common_pfx_len;
        Len_long (skip_16 b)
      end in
    let bt_elem_off = b.pos in
    let log_new_location ~index =
      log_new_loc s (callstack_as_ints.(index),
                     decode_callstack_entry callstack index) in
    let nencoded =
      Backtrace_codec.Writer.put_backtrace cache b ~alloc_id:id
        ~callstack:callstack_as_ints ~callstack_len:suff ~log_new_location in
    begin match bt_len_off with
      | Len_short p ->
        assert (nencoded <= 0xff);
        update_8 b p nencoded
      | Len_long p ->
        (* This can't overflow because there isn't room in a packet for more than
           0xffff entries. (See max_packet_size) *)
        assert (nencoded <= 0xffff);
        update_16 b p nencoded
    end;
    begin match s.debug_reader_cache with
      | None -> ()
      | Some c ->
        (* Decode the backtrace and check that it matches *)
        let b' = Read.of_bytes_sub b.buf ~pos:bt_elem_off ~pos_end:b.pos in
        let decoded, decoded_len =
          Backtrace_codec.Reader.get_backtrace c b' ~nencoded ~common_pfx_len in
        assert (Read.remaining b' = 0);
        let rev_callstack =
          callstack_as_ints |> Array.to_list |> List.rev |> Array.of_list
        in
        if (Array.sub decoded 0 decoded_len) <> rev_callstack then begin
          rev_callstack
          |> Array.map Int64.of_int
          |> Array.iter (Printf.printf " %08Lx");
          Printf.printf " !\n%!";
          Array.sub decoded 0 decoded_len
          |> Array.iter (Printf.printf " %08x");
          Printf.printf " !\n%!";
          failwith "bad coded backtrace"
        end
    end;
    id

  (* The other events are much simpler *)

  let put_promote s now id =
    let open Write in
    if id >= s.next_alloc_id then
      raise (Invalid_argument "Invalid ID in promotion");
    begin_event s Ev_promote ~now;
    let b = s.packet in
    put_vint b (s.next_alloc_id - 1 - id)

  let put_collect s now id =
    let open Write in
    if id >= s.next_alloc_id then
      raise (Invalid_argument "Invalid ID in collection");
    begin_event s Ev_collect ~now;
    let b = s.packet in
    put_vint b (s.next_alloc_id - 1 - id)

  module Writer = struct
    type t = writer

    let create = make_writer

    (* Unfortunately, efficient access to the backtrace is not possible
       with the current Printexc API, even though internally it's an int
       array. For now, wave the Obj.magic wand. There's a PR to fix this:
       https://github.com/ocaml/ocaml/pull/9663 *)
    let location_code_array_of_raw_backtrace (b : Printexc.raw_backtrace) =
      (Obj.magic b : Location_code.t array)

    let decode_raw_backtrace_entry callstack i : Location.t list =
      let open Printexc in
      let rec get_locations slot : Location.t list =
        let tail =
          match get_raw_backtrace_next_slot slot with
          | None -> []
          | Some slot -> get_locations slot in
        let slot = convert_raw_backtrace_slot slot in
        match Slot.location slot with
        | None -> tail
        | Some { filename; line_number; start_char; end_char } ->
          let defname = match Slot.name slot with Some n -> n | _ -> "??" in
          { filename; line=line_number; start_char; end_char; defname }::tail in
      get_locations (get_raw_backtrace_slot callstack i) |> List.rev

    let put_alloc_with_raw_backtrace t now ~length ~nsamples
        ~is_major ~callstack =
      let callstack_as_ints = location_code_array_of_raw_backtrace callstack in
      put_alloc t now ~length ~nsamples ~is_major
        ~callstack ~callstack_as_ints
        ~decode_callstack_entry:decode_raw_backtrace_entry

    let put_alloc t now ~length ~nsamples ~is_major
        ~callstack ~decode_callstack_entry =
      let decode_callstack_entry cs i =
        decode_callstack_entry cs.(i) in
      put_alloc t now ~length ~nsamples ~is_major
        ~callstack ~callstack_as_ints:callstack ~decode_callstack_entry
    let put_collect = put_collect
    let put_promote = put_promote
    let flush = flush
    let close t = flush t; t.dest None

    let put_event w ~decode_callstack_entry now (ev : Event.t) =
      match ev with
      | Alloc { obj_id; length; nsamples; is_major;
                backtrace_buffer; backtrace_length; common_prefix = _ } ->
        let btrev = Array.init backtrace_length (fun i ->
            backtrace_buffer.(backtrace_length - 1 - i)) in
        let id = put_alloc w now ~length ~nsamples ~is_major
            ~callstack:btrev
            ~decode_callstack_entry in
        if id <> obj_id then
          raise (Invalid_argument "Incorrect allocation ID")
      | Promote id ->
        put_promote w now id
      | Collect id ->
        put_collect w now id
  end
end

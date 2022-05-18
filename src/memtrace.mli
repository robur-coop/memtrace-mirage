(** The sampling_rate is the proportion of allocated words that should be
    sampled. Values larger than about 1e-4 will have some performance impact. *)

module Make (P : Mirage_clock.PCLOCK) (F : Mirage_flow.S) : sig

(** Tracing can also be manually started and stopped. *)
type tracer

(** Manually start tracing *)
val start_tracing :
  context:string option ->
  ?sampling_rate:float ->
  F.flow ->
  tracer

(** Manually stop tracing *)
val stop_tracing : tracer -> unit

val default_sampling_rate : float

(** Use the Trace module to read and write trace files *)
module Trace : Trace.S

(** Use Memprof_tracer in conjunction with Trace.Writer for more manual
    control over trace collection *)
module Memprof_tracer : module type of Memprof_tracer.Make(Trace)

(** Use External to track non-GC-heap allocations in a Memtrace trace *)
module External : sig
  type token [@@immediate]

  (** [alloc ~bytes] reports an allocation of a given number of bytes.

      If tracing is enabled, a small fraction of the calls to this function
      will return [Some tok], where [tok] should be passed to [free] when
      the object is freed.

      This function is very fast in the common case where it returns [None] *)
  val alloc : bytes:int -> token option
  val free : token -> unit
end
end

(** (For testing) *)
module Geometric_sampler = Geometric_sampler

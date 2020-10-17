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
end

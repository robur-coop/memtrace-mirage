(lang dune 2.3)
(name memtrace-mirage)

(generate_opam_files true)

(source (github hannesm/memtrace-mirage))
(license MIT)
(authors "Jane Street Group, LLC <opensource@janestreet.com>")
(maintainers "opensource@janestreet.com")

(package
 (name memtrace-mirage)
 (synopsis "Streaming client for Memprof")
 (description "Generates compact traces of a program's memory use.")
 (depends
  (ocaml (>= 4.11.0))
  mirage-flow
  mirage-clock
  ptime
  lwt))

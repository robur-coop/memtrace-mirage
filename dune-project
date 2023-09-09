(lang dune 2.3)
(name memtrace-mirage)

(generate_opam_files true)

(source (github robur-coop/memtrace-mirage))
(license MIT)
(authors "Jane Street Group, LLC <opensource@janestreet.com>" "Robur Team <team@robur.coop>" "Hannes Mehnert <hannes@mehnert.org>")
(maintainers "team@robur.coop")

(package
 (name memtrace-mirage)
 (synopsis "Streaming client for Memprof using MirageOS API")
 (description "Generates compact traces of a program's memory use.")
 (depends
  (ocaml (>= 4.11.0))
  (mirage-flow (>= 3.0.0))
  (mirage-clock (>= 4.0.0))
  (ptime (>= 1.0.0))
  (lwt (>= 5.5.0))))


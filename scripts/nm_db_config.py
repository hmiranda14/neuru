# NetMon Python DB config — generated for this container.
# time_zone pins the poller session to UTC so recorded_at matches PHP (which also runs SET time_zone='+00:00').
# Without it, on a host whose system TZ is not UTC (e.g. NEURU-in-a-Box with TZ=America/Puerto_Rico), the
# Python pollers write local-time timestamps while PHP reads in UTC → every poll looks hours "stale" → nodes
# render DOWN and realtime/traffic views see no recent rows. Canonical NEURU storage is UTC.
DB = dict(
    host      = 'db',
    user      = 'sisuser',
    password  = 'sispass',
    database  = 'netmon',
    time_zone = '+00:00',
)

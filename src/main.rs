use std::io::Write as _;

fn main() {
    if let Err(err) = pincer::run() {
        // `pincer flows file | head` closes our stdout early; exiting quietly
        // on a broken pipe is standard CLI behavior (grep, cat do the same).
        if let pincer::Error::Io(io_err) = &err
            && io_err.kind() == std::io::ErrorKind::BrokenPipe
        {
            return;
        }
        // Best-effort: even reporting the error must not panic (stderr may
        // itself be closed). eprintln! would.
        let _ = writeln!(std::io::stderr(), "pincer: {err}");
        std::process::exit(1);
    }
}

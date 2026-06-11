use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    match pincer::run() {
        // 0, or EXIT_DEGRADED (3) under --strict for a degraded analysis.
        Ok(code) => code,
        Err(err) => {
            // `pincer flows file | head` closes our stdout early. Classic
            // utilities die of SIGPIPE (exit 141); we trap the error instead
            // and exit 0 deliberately — the consumer got every byte it asked
            // for, which is not a failure of this process.
            if let pincer::Error::Io(io_err) = &err
                && io_err.kind() == std::io::ErrorKind::BrokenPipe
            {
                return ExitCode::SUCCESS;
            }
            // Best-effort: even reporting the error must not panic (stderr
            // may itself be closed). eprintln! would.
            let _ = writeln!(std::io::stderr(), "pincer: {err}");
            ExitCode::FAILURE
        }
    }
}

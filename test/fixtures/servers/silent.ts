/** Fixture that starts but never answers `initialize` (startup-timeout test). */
process.stdin.resume();
setInterval(() => {}, 1 << 30);

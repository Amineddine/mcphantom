# Demo GIF

`demo.gif` (shown at the top of the main README) is rendered from [`demo.tape`](demo.tape) with
[VHS](https://github.com/charmbracelet/vhs). It records `npm run demo` (the deterministic
side-by-side demo described in [../DEMO.md](../DEMO.md)) followed by `mcphantom trace` on the blocked
call.

Regenerate it:

- **CI (reference rendering):** run the `demo-gif` workflow (Actions → demo-gif → Run workflow, or push
  to the `demo-gif` branch), download the `demo-gif` artifact, and commit it here. VHS 0.12.1 and
  ttyd 1.7.7 are pinned by SHA-256 in `.github/workflows/demo-gif.yml`.
- **Locally:** install VHS, ttyd and ffmpeg, then from the repository root:
  `npm ci && npm run build && npm link && vhs docs/demo/demo.tape`.

The demo binds random loopback ports, so those numbers differ between renderings; everything else is
deterministic.

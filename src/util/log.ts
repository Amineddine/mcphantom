/**
 * Diagnostic logging. Always stderr: in `mcphantom run`, stdout is the MCP channel and any stray
 * byte written there corrupts the JSON-RPC stream.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface Logger {
  debug(msg: string): void;
  info(msg: string): void;
  warn(msg: string): void;
  error(msg: string): void;
}

export function createLogger(level: LogLevel = 'info', sink: (line: string) => void = defaultSink): Logger {
  const min = ORDER[level];
  const emit = (lvl: LogLevel, msg: string): void => {
    if (ORDER[lvl] >= min) sink(`[mcphantom] ${lvl}: ${msg}`);
  };
  return {
    debug: (m) => { emit('debug', m); },
    info: (m) => { emit('info', m); },
    warn: (m) => { emit('warn', m); },
    error: (m) => { emit('error', m); },
  };
}

function defaultSink(line: string): void {
  process.stderr.write(line + '\n');
}

export const silentLogger: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

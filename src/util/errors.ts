/**
 * An error caused by user input or environment (bad config, missing file, refused permission).
 * The CLI prints these without a stack trace, followed by the hint if present.
 */
export class UserError extends Error {
  readonly hint: string | undefined;

  constructor(message: string, hint?: string) {
    super(message);
    this.name = 'UserError';
    this.hint = hint;
  }
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

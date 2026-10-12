import os from 'node:os';
import path from 'node:path';

export interface Paths {
  /** Config, profiles, policy, lockfile. */
  configDir: string;
  /** Event database and other runtime state. */
  dataDir: string;
  profilesDir: string;
}

/**
 * Per-OS locations. `MCPHANTOM_HOME` overrides both (used by tests and portable installs).
 */
export function resolvePaths(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): Paths {
  const home = env.MCPHANTOM_HOME;
  if (home) {
    const root = path.resolve(home);
    return { configDir: path.join(root, 'config'), dataDir: path.join(root, 'data'), profilesDir: path.join(root, 'config', 'profiles') };
  }
  const userHome = os.homedir();
  let configDir: string;
  let dataDir: string;
  if (platform === 'win32') {
    configDir = path.join(env.APPDATA ?? path.join(userHome, 'AppData', 'Roaming'), 'mcphantom');
    dataDir = path.join(env.LOCALAPPDATA ?? path.join(userHome, 'AppData', 'Local'), 'mcphantom');
  } else if (platform === 'darwin') {
    configDir = path.join(userHome, 'Library', 'Application Support', 'mcphantom');
    dataDir = path.join(configDir, 'data');
  } else {
    configDir = path.join(env.XDG_CONFIG_HOME ?? path.join(userHome, '.config'), 'mcphantom');
    dataDir = path.join(env.XDG_STATE_HOME ?? path.join(userHome, '.local', 'state'), 'mcphantom');
  }
  return { configDir, dataDir, profilesDir: path.join(configDir, 'profiles') };
}

export function profilePath(paths: Paths, profile: string): string {
  return path.join(paths.profilesDir, `${profile}.yaml`);
}

export const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

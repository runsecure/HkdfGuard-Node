import os from 'node:os';
import { AbstractHkdfGuardKmsLibrary } from './interop/abstractHkdfGuardKmsLibrary.js';
import { LinuxHkdfGuardKmsLibrary } from './interop/linuxHkdfGuardKmsLibrary.js';
import { MacOsHkdfGuardKmsLibrary } from './interop/macOsHkdfGuardKmsLibrary.js';
import { WindowsHkdfGuardKmsLibrary } from './interop/windowsHkdfGuardKmsLibrary.js';

export type Platform = 'windows' | 'linux' | 'macos';

/**
 * Maps a Node `os.platform()` value to the matching platform, without touching any native
 * library - kept separate from the library construction below so this selection logic can be
 * exercised without a native library present.
 */
export function resolvePlatform(platform: NodeJS.Platform): Platform {
  switch (platform) {
    case 'win32':
      return 'windows';
    case 'linux':
      return 'linux';
    case 'darwin':
      return 'macos';
    default:
      throw new Error(`HkdfGuard.KeyWrapping.V1 has no native KMS library for '${platform}'.`);
  }
}

function construct(platform: Platform): AbstractHkdfGuardKmsLibrary {
  switch (platform) {
    case 'windows':
      return new WindowsHkdfGuardKmsLibrary();
    case 'linux':
      return new LinuxHkdfGuardKmsLibrary();
    case 'macos':
      return new MacOsHkdfGuardKmsLibrary();
  }
}

let cachedLibrary: AbstractHkdfGuardKmsLibrary | undefined;

/**
 * Resolves the current OS's native HkdfGuard KMS library exactly once per process (binding the
 * wrong platform's library would fail on first native call anyway, so there's nothing to gain by
 * re-resolving per instance).
 */
export const NativeHost = {
  getLibrary(): AbstractHkdfGuardKmsLibrary {
    cachedLibrary ??= construct(resolvePlatform(os.platform()));
    return cachedLibrary;
  },
};

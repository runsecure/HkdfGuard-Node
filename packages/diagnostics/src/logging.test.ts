import { describe, it, expect, vi } from 'vitest';
import { sensitiveOperationLogged, operationFailed, type Logger } from './logging.js';

type LoggerMethod = (message: string, meta?: Record<string, unknown>) => void;

function fakeLogger(): { debug: ReturnType<typeof vi.fn<LoggerMethod>>; error: ReturnType<typeof vi.fn<LoggerMethod>> } {
  return { debug: vi.fn<LoggerMethod>(), error: vi.fn<LoggerMethod>() };
}

describe('sensitiveOperationLogged', () => {
  it('does nothing when logger is omitted', () => {
    expect(() => sensitiveOperationLogged(undefined, 'op', 'name')).not.toThrow();
  });

  it('logs a debug message naming the operation and the item', () => {
    const logger = fakeLogger();

    sensitiveOperationLogged(logger, 'hkdfguard.cache.add', 'item-1');

    expect(logger.debug).toHaveBeenCalledWith('hkdfguard.cache.add completed for item-1.', {
      operation: 'hkdfguard.cache.add',
      name: 'item-1',
    });
    expect(logger.error).not.toHaveBeenCalled();
  });
});

describe('operationFailed', () => {
  it('does nothing when logger is omitted', () => {
    expect(() => operationFailed(undefined, 'op', new Error('boom'))).not.toThrow();
  });

  it('logs an error message naming the operation, unconditionally', () => {
    const logger = fakeLogger();
    const error = new Error('boom');

    operationFailed(logger, 'hkdfguard.cache.add', error);

    expect(logger.error).toHaveBeenCalledWith('hkdfguard.cache.add failed.', {
      operation: 'hkdfguard.cache.add',
      error,
    });
    expect(logger.debug).not.toHaveBeenCalled();
  });
});

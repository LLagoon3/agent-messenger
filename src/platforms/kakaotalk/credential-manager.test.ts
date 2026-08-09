import { afterAll, describe, expect, it, mock } from 'bun:test'
import { rmSync } from 'node:fs'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'

import { KakaoCredentialManager } from './credential-manager'
import type { KakaoAccountCredentials } from './types'

const testDirs: string[] = []

function setup(): KakaoCredentialManager {
  const testConfigDir = join(import.meta.dir, `.test-kakao-config-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  testDirs.push(testConfigDir)
  return new KakaoCredentialManager(testConfigDir)
}

function makeAccount(overrides?: Partial<KakaoAccountCredentials>): KakaoAccountCredentials {
  return {
    account_id: 'test-account',
    oauth_token: 'oauth-token-123',
    user_id: 'user-123',
    refresh_token: 'refresh-token-123',
    device_uuid: 'device-uuid-123',
    device_type: 'tablet',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  }
}

afterAll(() => {
  for (const dir of testDirs) {
    rmSync(dir, { recursive: true, force: true })
  }
})

describe('KakaoCredentialManager', () => {
  describe('load', () => {
    it('returns default config when file does not exist', async () => {
      const manager = setup()
      const config = await manager.load()

      expect(config).toEqual({ current_account: null, accounts: {} })
    })
  })

  describe('save/load round-trip', () => {
    it('creates file and can be re-read via load', async () => {
      const manager = setup()
      const account = makeAccount()
      const config = {
        current_account: 'test-account',
        accounts: {
          'test-account': account,
        },
      }

      await manager.save(config)
      const loaded = await manager.load()

      expect(loaded).toEqual(config)
    })
  })

  describe('getAccount', () => {
    it('returns null when no accounts exist', async () => {
      const manager = setup()
      const account = await manager.getAccount()

      expect(account).toBeNull()
    })

    it('returns null for nonexistent account ID', async () => {
      const manager = setup()
      const account = await manager.getAccount('nonexistent')

      expect(account).toBeNull()
    })

    it('returns account by explicit ID', async () => {
      const manager = setup()
      const account = makeAccount()

      await manager.setAccount(account)
      const retrieved = await manager.getAccount('test-account')

      expect(retrieved).toEqual(account)
    })

    it('returns current account when no ID given', async () => {
      const manager = setup()
      const account = makeAccount()

      await manager.setAccount(account)
      const current = await manager.getAccount()

      expect(current).toEqual(account)
    })
  })

  describe('setAccount', () => {
    it('stores account and auto-sets current_account if null', async () => {
      const manager = setup()
      const account = makeAccount()

      await manager.setAccount(account)
      const config = await manager.load()

      expect(config.current_account).toBe('test-account')
      expect(config.accounts['test-account']).toEqual(account)
    })

    it('does NOT override existing current_account', async () => {
      const manager = setup()
      const first = makeAccount({ account_id: 'first-account' })
      const second = makeAccount({ account_id: 'second-account' })

      await manager.setAccount(first)
      await manager.setAccount(second)

      const config = await manager.load()
      expect(config.current_account).toBe('first-account')
    })
  })

  describe('refreshAccountTokens', () => {
    it('atomically updates the access token while retaining an unrotated refresh token', async () => {
      const manager = setup()
      const account = makeAccount({ created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' })
      await manager.setAccount(account)

      const updated = await manager.refreshAccountTokens('test-account', async () => ({
        accessToken: 'new-oauth-token',
        refreshToken: undefined,
      }))

      expect(updated).toMatchObject({
        account_id: account.account_id,
        oauth_token: 'new-oauth-token',
        refresh_token: account.refresh_token,
        device_uuid: account.device_uuid,
        device_type: account.device_type,
        created_at: account.created_at,
      })
      expect(updated.updated_at).not.toBe(account.updated_at)
      await expect(manager.getAccount('test-account')).resolves.toEqual(updated)
    })

    it('persists a rotated refresh token', async () => {
      const manager = setup()
      await manager.setAccount(makeAccount())

      const updated = await manager.refreshAccountTokens('test-account', async () => ({
        accessToken: 'new-oauth-token',
        refreshToken: 'new-refresh-token',
      }))

      expect(updated.oauth_token).toBe('new-oauth-token')
      expect(updated.refresh_token).toBe('new-refresh-token')
    })

    it('shares one refresh operation across concurrent callers for the same account', async () => {
      const manager = setup()
      await manager.setAccount(makeAccount())
      let release!: () => void
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const refresher = async () => {
        await gate
        return { accessToken: 'shared-oauth-token', refreshToken: 'shared-refresh-token' }
      }
      const firstRefresher = mock(refresher)
      const secondRefresher = mock(refresher)

      const first = manager.refreshAccountTokens('test-account', firstRefresher)
      const second = manager.refreshAccountTokens('test-account', secondRefresher)
      await Bun.sleep(1)
      release()

      const [firstResult, secondResult] = await Promise.all([first, second])
      expect(firstResult).toEqual(secondResult)
      expect(firstRefresher.mock.calls.length + secondRefresher.mock.calls.length).toBe(1)
    })

    it('does not overwrite credentials changed while refresh was in flight', async () => {
      const manager = setup()
      const original = makeAccount()
      await manager.setAccount(original)
      let release!: () => void
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const refresh = manager.refreshAccountTokens('test-account', async () => {
        await gate
        return { accessToken: 'stale-refreshed-token' }
      })
      await Bun.sleep(1)
      await manager.setAccount({ ...original, oauth_token: 'manual-login-token', updated_at: new Date().toISOString() })
      release()

      await expect(refresh).rejects.toMatchObject({ code: 'credential_conflict' })
      expect((await manager.getAccount('test-account'))?.oauth_token).toBe('manual-login-token')
    })

    it('keeps the previous complete file when the atomic replacement fails', async () => {
      const manager = setup()
      const original = makeAccount()
      await manager.setAccount(original)
      ;(manager as unknown as { atomicWrite: () => Promise<void> }).atomicWrite = async () => {
        throw new Error('simulated rename failure')
      }

      await expect(
        manager.refreshAccountTokens('test-account', async () => ({ accessToken: 'must-not-be-visible' })),
      ).rejects.toThrow('simulated rename failure')
      await expect(manager.getAccount('test-account')).resolves.toEqual(original)
    })

    it('preserves credentials file mode 0600 after token rotation', async () => {
      const manager = setup()
      await manager.setAccount(makeAccount())
      await manager.refreshAccountTokens('test-account', async () => ({ accessToken: 'new-oauth-token' }))

      const credentialsPath = join(
        (manager as unknown as { configDir: string }).configDir,
        'kakaotalk-credentials.json',
      )
      expect((await stat(credentialsPath)).mode & 0o777).toBe(0o600)
    })
  })

  describe('listAccounts', () => {
    it('returns empty array for empty config', async () => {
      const manager = setup()
      const accounts = await manager.listAccounts()

      expect(accounts).toEqual([])
    })

    it('returns all accounts with correct is_current flag', async () => {
      const manager = setup()
      const first = makeAccount({ account_id: 'first-account' })
      const second = makeAccount({ account_id: 'second-account' })

      await manager.setAccount(first)
      await manager.setAccount(second)

      const accounts = await manager.listAccounts()

      expect(accounts).toHaveLength(2)
      const firstResult = accounts.find((a) => a.account_id === 'first-account')
      const secondResult = accounts.find((a) => a.account_id === 'second-account')
      expect(firstResult?.is_current).toBe(true)
      expect(secondResult?.is_current).toBe(false)
    })
  })

  describe('setCurrentAccount', () => {
    it('switches active account', async () => {
      const manager = setup()
      const first = makeAccount({ account_id: 'first-account' })
      const second = makeAccount({ account_id: 'second-account' })

      await manager.setAccount(first)
      await manager.setAccount(second)
      await manager.setCurrentAccount('second-account')

      const current = await manager.getAccount()
      expect(current?.account_id).toBe('second-account')
    })
  })

  describe('removeAccount', () => {
    it('removes and rotates current to next available', async () => {
      const manager = setup()
      const first = makeAccount({ account_id: 'first-account' })
      const second = makeAccount({ account_id: 'second-account' })

      await manager.setAccount(first)
      await manager.setAccount(second)
      await manager.removeAccount('first-account')

      const accounts = await manager.listAccounts()
      expect(accounts).toHaveLength(1)
      expect(accounts[0]?.account_id).toBe('second-account')

      const current = await manager.getAccount()
      expect(current?.account_id).toBe('second-account')
    })

    it('handles removing non-current account', async () => {
      const manager = setup()
      const first = makeAccount({ account_id: 'first-account' })
      const second = makeAccount({ account_id: 'second-account' })

      await manager.setAccount(first)
      await manager.setAccount(second)
      await manager.removeAccount('second-account')

      const accounts = await manager.listAccounts()
      expect(accounts).toHaveLength(1)
      expect(accounts[0]?.account_id).toBe('first-account')

      // current_account should still be first-account
      const config = await manager.load()
      expect(config.current_account).toBe('first-account')
    })
  })

  describe('savePendingLogin/loadPendingLogin/clearPendingLogin', () => {
    it('handles full save, load, and clear lifecycle', async () => {
      const manager = setup()
      const state = {
        device_uuid: 'uuid-abc',
        device_type: 'tablet' as const,
        email: 'user@example.com',
        created_at: new Date().toISOString(),
      }

      // given nothing saved
      const initial = await manager.loadPendingLogin()
      expect(initial).toBeNull()

      // when saved
      await manager.savePendingLogin(state)
      const loaded = await manager.loadPendingLogin()
      expect(loaded).toEqual(state)

      // when cleared
      await manager.clearPendingLogin()
      const afterClear = await manager.loadPendingLogin()
      expect(afterClear).toBeNull()
    })
  })
})

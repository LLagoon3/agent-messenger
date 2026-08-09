import { randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

import { getConfigDir } from '../../shared/utils/config-dir'
import type { KakaoOAuthRefreshResult } from './auth/oauth-refresh'
import type { KakaoAccountCredentials, KakaoConfig, KakaoDeviceType } from './types'

const mutationTails = new Map<string, Promise<void>>()
const refreshFlights = new Map<string, Promise<KakaoAccountCredentials>>()

async function withMutationLock<T>(key: string, operation: () => Promise<T>): Promise<T> {
  const previous = mutationTails.get(key) ?? Promise.resolve()
  let release!: () => void
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const tail = previous.catch(() => {}).then(() => gate)
  mutationTails.set(key, tail)

  await previous.catch(() => {})
  try {
    return await operation()
  } finally {
    release()
    if (mutationTails.get(key) === tail) mutationTails.delete(key)
  }
}

export class KakaoCredentialError extends Error {
  readonly code: 'credential_conflict' | 'credential_not_found'

  constructor(code: 'credential_conflict' | 'credential_not_found') {
    super(`KakaoTalk credential update failed (${code})`)
    this.name = 'KakaoCredentialError'
    this.code = code
  }
}

export interface PendingLoginState {
  device_uuid: string
  device_type: KakaoDeviceType
  email: string
  created_at: string
}

export class KakaoCredentialManager {
  private configDir: string
  private credentialsPath: string
  private pendingLoginPath: string

  constructor(configDir?: string) {
    this.configDir = configDir ?? getConfigDir()
    this.credentialsPath = join(this.configDir, 'kakaotalk-credentials.json')
    this.pendingLoginPath = join(this.configDir, 'kakaotalk-pending-login.json')
  }

  async load(): Promise<KakaoConfig> {
    if (!existsSync(this.credentialsPath)) {
      return { current_account: null, accounts: {} }
    }

    const content = await readFile(this.credentialsPath, 'utf-8')
    return JSON.parse(content) as KakaoConfig
  }

  async save(config: KakaoConfig): Promise<void> {
    await withMutationLock(this.credentialsPath, () => this.atomicWrite(config))
  }

  async getAccount(id?: string): Promise<KakaoAccountCredentials | null> {
    const config = await this.load()

    if (id) {
      return config.accounts[id] ?? null
    }

    if (!config.current_account) {
      return null
    }

    return config.accounts[config.current_account] ?? null
  }

  async setAccount(account: KakaoAccountCredentials): Promise<void> {
    await withMutationLock(this.credentialsPath, async () => {
      const config = await this.load()
      config.accounts[account.account_id] = account

      if (!config.current_account) {
        config.current_account = account.account_id
      }

      await this.atomicWrite(config)
    })
  }

  async removeAccount(id: string): Promise<void> {
    await withMutationLock(this.credentialsPath, async () => {
      const config = await this.load()
      delete config.accounts[id]

      if (config.current_account === id) {
        config.current_account = Object.keys(config.accounts)[0] ?? null
      }

      await this.atomicWrite(config)
    })
  }

  async listAccounts(): Promise<Array<KakaoAccountCredentials & { is_current: boolean }>> {
    const config = await this.load()
    return Object.values(config.accounts).map((account) => ({
      ...account,
      is_current: account.account_id === config.current_account,
    }))
  }

  async setCurrentAccount(id: string): Promise<void> {
    await withMutationLock(this.credentialsPath, async () => {
      const config = await this.load()
      config.current_account = id
      await this.atomicWrite(config)
    })
  }

  async refreshAccountTokens(
    id: string | undefined,
    refresher: (account: Readonly<KakaoAccountCredentials>) => Promise<KakaoOAuthRefreshResult>,
  ): Promise<KakaoAccountCredentials> {
    const account = await this.getAccount(id)
    if (!account) throw new KakaoCredentialError('credential_not_found')

    const flightKey = `${this.credentialsPath}:${account.account_id}`
    const existing = refreshFlights.get(flightKey)
    if (existing) return existing

    const flight = this.performTokenRefresh(account, refresher)
    refreshFlights.set(flightKey, flight)
    try {
      return await flight
    } finally {
      if (refreshFlights.get(flightKey) === flight) refreshFlights.delete(flightKey)
    }
  }

  async savePendingLogin(state: PendingLoginState): Promise<void> {
    await mkdir(this.configDir, { recursive: true })
    await writeFile(this.pendingLoginPath, JSON.stringify(state, null, 2))
    await chmod(this.pendingLoginPath, 0o600)
  }

  async loadPendingLogin(): Promise<PendingLoginState | null> {
    if (!existsSync(this.pendingLoginPath)) return null
    const content = await readFile(this.pendingLoginPath, 'utf-8')
    return JSON.parse(content) as PendingLoginState
  }

  async clearPendingLogin(): Promise<void> {
    if (existsSync(this.pendingLoginPath)) {
      await rm(this.pendingLoginPath, { force: true })
    }
  }

  private async performTokenRefresh(
    baseline: KakaoAccountCredentials,
    refresher: (account: Readonly<KakaoAccountCredentials>) => Promise<KakaoOAuthRefreshResult>,
  ): Promise<KakaoAccountCredentials> {
    const tokens = await refresher({ ...baseline })

    return withMutationLock(this.credentialsPath, async () => {
      const config = await this.load()
      const current = config.accounts[baseline.account_id]
      if (!current) throw new KakaoCredentialError('credential_not_found')
      if (current.oauth_token !== baseline.oauth_token || current.refresh_token !== baseline.refresh_token) {
        throw new KakaoCredentialError('credential_conflict')
      }

      const updated: KakaoAccountCredentials = {
        ...current,
        oauth_token: tokens.accessToken,
        refresh_token: tokens.refreshToken ?? current.refresh_token,
        updated_at: new Date().toISOString(),
      }
      config.accounts[baseline.account_id] = updated
      await this.atomicWrite(config)
      return updated
    })
  }

  private async atomicWrite(config: KakaoConfig): Promise<void> {
    await mkdir(this.configDir, { recursive: true })
    const temporaryPath = `${this.credentialsPath}.tmp-${process.pid}-${randomUUID()}`
    try {
      // TODO: Windows does not honor mode 0o600 — consider platform-specific credential storage
      await writeFile(temporaryPath, JSON.stringify(config, null, 2), { mode: 0o600, flag: 'wx' })
      await chmod(temporaryPath, 0o600)
      await rename(temporaryPath, this.credentialsPath)
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => {})
      throw error
    }
  }
}

export { KakaoCredentialManager as CredentialManager }

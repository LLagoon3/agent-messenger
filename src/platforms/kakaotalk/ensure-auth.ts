import { refreshKakaoOAuthToken } from './auth/oauth-refresh'
import { CredentialManager } from './credential-manager'
import type { KakaoAccountCredentials } from './types'

export class KakaoAuthRequiredError extends Error {
  readonly code = 'auth_required'

  constructor() {
    super('KakaoTalk authentication must be renewed. Run: agent-kakaotalk auth login')
    this.name = 'KakaoAuthRequiredError'
  }
}

export async function ensureKakaoAuth(accountId?: string): Promise<KakaoAccountCredentials> {
  const credManager = new CredentialManager()
  const account = await credManager.getAccount(accountId)

  if (account?.oauth_token) {
    return account
  }

  throw new Error(
    'No KakaoTalk credentials found. Run:\n' +
      '  agent-kakaotalk auth login     (recommended — registers as sub-device, desktop app stays running)',
  )
}

export async function refreshKakaoAuth(accountId?: string): Promise<KakaoAccountCredentials> {
  const credentialManager = new CredentialManager()
  try {
    return await credentialManager.refreshAccountTokens(accountId, async (account) => {
      if (!account.refresh_token) throw new KakaoAuthRequiredError()
      return refreshKakaoOAuthToken({
        accessToken: account.oauth_token,
        refreshToken: account.refresh_token,
        deviceUuid: account.device_uuid,
      })
    })
  } catch {
    throw new KakaoAuthRequiredError()
  }
}

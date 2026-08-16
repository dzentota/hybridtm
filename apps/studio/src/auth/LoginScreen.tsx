import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { login } from '../api/client'

export function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const { t } = useTranslation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(email, password)
      onLoggedIn()
    } catch {
      setError(t('login.invalid'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="w-full h-full flex items-center justify-center">
      <form onSubmit={submit} className="w-72 flex flex-col gap-3 p-6 rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-0)' }}>
        <div className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          {t('login.title')}
        </div>
        <input
          type="email"
          required
          placeholder={t('login.email')}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="text-sm px-2 py-1.5 rounded border"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        />
        <input
          type="password"
          required
          placeholder={t('login.password')}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="text-sm px-2 py-1.5 rounded border"
          style={{ background: 'var(--surface-1)', borderColor: 'var(--border)' }}
        />
        {error && <div className="text-xs" style={{ color: 'var(--severity-critical)' }}>{error}</div>}
        <button
          type="submit"
          disabled={busy}
          className="text-sm font-medium px-3 py-1.5 rounded"
          style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}
        >
          {busy ? t('login.signingIn') : t('login.signIn')}
        </button>
      </form>
    </div>
  )
}

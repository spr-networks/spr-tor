import React, { useCallback, useEffect, useState } from 'react'
import {
  api,
  useAlert,
  timeAgo,
  Page,
  ListHeader,
  Card,
  SectionHeader,
  StatTile,
  StatusDot,
  Toggle,
  TextField,
  Loading,
  EmptyState,
  Badge,
  BadgeText,
  Box,
  Button,
  ButtonText,
  HStack,
  VStack,
  Text,
  Textarea,
  TextareaInput
} from '@spr-networks/plugin-ui'

const PLUGIN_BASE = `/plugins/${api.pluginURI() || 'spr-tor'}`

// ---- helpers ----

const fmtBytes = (n) => {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`
}

// tor reports TIME_CREATED as UTC without a timezone suffix
const circuitAge = (ts) => {
  if (!ts) return null
  return timeAgo(/[zZ+]/.test(ts.slice(10)) ? ts : ts + 'Z')
}

const circuitAction = (s) =>
  s === 'BUILT'
    ? 'success'
    : ['LAUNCHED', 'EXTENDED', 'GUARD_WAIT'].includes(s)
    ? 'warning'
    : s === 'FAILED'
    ? 'error'
    : 'muted'

const formFromConfig = (c) => ({
  ExitCountry: c?.ExitCountry || '',
  TransPortEnabled: !!c?.TransPortEnabled,
  DNSPortEnabled: !!c?.DNSPortEnabled,
  SafeSocks: !!c?.SafeSocks,
  UseBridges: !!c?.UseBridges,
  Bridges: (c?.Bridges || []).join('\n'),
  SocksPolicy: (c?.SocksPolicy || []).join('\n')
})

const splitLines = (s) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length)

// ---- small presentational pieces ----

const ProgressBar = ({ value }) => (
  <Box
    h={6}
    borderRadius="$full"
    bg="$muted200"
    overflow="hidden"
    sx={{ _dark: { bg: '$muted700' } }}
  >
    <Box
      h="100%"
      borderRadius="$full"
      bg="$primary600"
      style={{ width: `${Math.max(2, Math.min(100, value))}%` }}
      sx={{
        '@base': { transition: 'width 400ms ease' },
        _dark: { bg: '$primary500' }
      }}
    />
  </Box>
)

const OnOffPill = ({ on }) => (
  <Badge action={on ? 'success' : 'muted'} variant="outline" borderRadius="$full" size="sm">
    <BadgeText>{on ? 'On' : 'Off'}</BadgeText>
  </Badge>
)

const EndpointRow = ({ label, desc, value, on, onCopy }) => (
  <HStack
    justifyContent="space-between"
    alignItems="center"
    flexWrap="wrap"
    gap="$2"
    py="$2"
    borderBottomWidth={1}
    borderColor="$borderColorCardLight"
    sx={{ _dark: { borderColor: '$borderColorCardDark' } }}
  >
    <VStack flexShrink={1} minWidth={160}>
      <Text size="sm" bold>
        {label}
      </Text>
      <Text size="xs" color="$muted500">
        {desc}
      </Text>
    </VStack>
    <HStack space="sm" alignItems="center" flexWrap="wrap">
      <Text
        size="sm"
        color={on ? '$textLight900' : '$muted400'}
        sx={{ '@base': { fontFamily: 'monospace' }, _dark: { color: on ? '$textDark100' : '$muted600' } }}
      >
        {value || '—'}
      </Text>
      <OnOffPill on={on} />
      <Button size="xs" variant="outline" action="secondary" onPress={onCopy} isDisabled={!on || !value}>
        <ButtonText>Copy</ButtonText>
      </Button>
    </HStack>
  </HStack>
)

const ToggleRow = ({ title, desc, value, onPress }) => (
  <HStack justifyContent="space-between" alignItems="center">
    <VStack flex={1} pr="$2">
      <Text size="sm" bold>
        {title}
      </Text>
      <Text size="xs" color="$muted500">
        {desc}
      </Text>
    </VStack>
    <Toggle value={value} onPress={onPress} label={title} />
  </HStack>
)

const LabeledArea = ({ label, helper, error, value, onChangeText, placeholder }) => (
  <VStack space="xs">
    <Text size="sm" bold>
      {label}
    </Text>
    <Textarea h="$24" borderColor={error ? '$red500' : '$muted300'} sx={{ _dark: { borderColor: error ? '$red500' : '$muted700' } }}>
      <TextareaInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        fontFamily="monospace"
        fontSize="$xs"
      />
    </Textarea>
    {error ? (
      <Text size="xs" color="$red600">
        {error}
      </Text>
    ) : helper ? (
      <Text size="xs" color="$muted500">
        {helper}
      </Text>
    ) : null}
  </VStack>
)

// ---- main ----

export default function Plugin() {
  const alert = useAlert()
  const [status, setStatus] = useState(null)
  const [config, setConfig] = useState(null)
  const [circuits, setCircuits] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [nymBusy, setNymBusy] = useState(false)
  const [form, setForm] = useState(formFromConfig(null))

  const refreshStatus = useCallback(() => {
    return api
      .get(`${PLUGIN_BASE}/status`)
      .then(setStatus)
      .catch(() => setStatus((prev) => prev || null))
  }, [])

  const refreshCircuits = useCallback(() => {
    return api
      .get(`${PLUGIN_BASE}/circuits`)
      .then((c) => setCircuits(Array.isArray(c) ? c : []))
      .catch(() => setCircuits([]))
  }, [])

  const loadConfig = useCallback(() => {
    return api.get(`${PLUGIN_BASE}/config`).then((c) => {
      setConfig(c)
      setForm(formFromConfig(c))
    })
  }, [])

  const loadAll = useCallback(() => {
    return Promise.allSettled([loadConfig(), refreshStatus(), refreshCircuits()])
  }, [loadConfig, refreshStatus, refreshCircuits])

  useEffect(() => {
    loadAll().finally(() => setLoading(false))
  }, [loadAll])

  const running = !!status?.Running
  const established = !!status?.CircuitEstablished
  const bootstrap = status?.BootstrapProgress ?? 0
  const bootstrapping = running && !established

  // poll /status (+ circuits); faster while tor is still bootstrapping
  useEffect(() => {
    const t = setInterval(
      () => {
        refreshStatus()
        refreshCircuits()
      },
      bootstrapping ? 2000 : 5000
    )
    return () => clearInterval(t)
  }, [bootstrapping, refreshStatus, refreshCircuits])

  // ---- form state ----

  const setField = (k) => (v) => setForm((f) => ({ ...f, [k]: v }))
  const toggleField = (k) => () => setForm((f) => ({ ...f, [k]: !f[k] }))

  const dirty =
    config && JSON.stringify(form) !== JSON.stringify(formFromConfig(config))

  const country = form.ExitCountry.trim()
  const countryError =
    country && !/^[a-zA-Z]{2}$/.test(country)
      ? 'Use a 2-letter country code, e.g. de'
      : ''
  const bridgesError =
    form.UseBridges && splitLines(form.Bridges).length === 0
      ? 'Add at least one bridge line, or turn off Use bridges'
      : ''
  const formValid = !countryError && !bridgesError

  const save = () => {
    const newConfig = {
      ...config,
      ExitCountry: country.toLowerCase(),
      TransPortEnabled: form.TransPortEnabled,
      DNSPortEnabled: form.DNSPortEnabled,
      SafeSocks: form.SafeSocks,
      UseBridges: form.UseBridges,
      Bridges: splitLines(form.Bridges),
      SocksPolicy: splitLines(form.SocksPolicy)
    }
    setSaving(true)
    api
      .put(`${PLUGIN_BASE}/config`, newConfig)
      .then((saved) => {
        setConfig(saved)
        setForm(formFromConfig(saved))
        alert.success('Saved — tor is reloading its configuration')
        setTimeout(refreshStatus, 1500)
      })
      .catch((err) => alert.error('Failed to save', err))
      .finally(() => setSaving(false))
  }

  const newIdentity = () => {
    setNymBusy(true)
    api
      .post(`${PLUGIN_BASE}/newnym`)
      .then(() => {
        alert.success('New identity requested — tor will switch to fresh circuits')
        setTimeout(refreshCircuits, 1200)
      })
      .catch((err) => alert.error('Failed to request a new identity', err))
      .finally(() => setNymBusy(false))
  }

  const copyValue = (v) => {
    if (!v) return
    if (navigator.clipboard?.writeText) {
      navigator.clipboard
        .writeText(v)
        .then(() => alert.success('Copied'))
        .catch(() => alert.error('Copy failed'))
    } else {
      alert.error('Copy is not available in this browser')
    }
  }

  // ---- render ----

  if (loading) {
    return (
      <Page>
        <Loading />
      </Page>
    )
  }

  if (!config) {
    return (
      <Page>
        <ListHeader title="Tor" description="Route traffic through the Tor anonymity network" mark="to" />
        <Card>
          <EmptyState
            title="Plugin backend unreachable"
            description="The spr-tor container did not answer. Make sure the plugin container is running, then retry."
          >
            <Button
              size="sm"
              onPress={() => {
                setLoading(true)
                loadAll().finally(() => setLoading(false))
              }}
            >
              <ButtonText>Retry</ButtonText>
            </Button>
          </EmptyState>
        </Card>
      </Page>
    )
  }

  const ip = status?.ContainerIP || ''
  const socksAddr = status?.SocksPort || (ip ? `${ip}:9050` : '')
  const transAddr = status?.TransPort || (ip ? `${ip}:9040` : '')
  const dnsAddr = status?.DNSPort || (ip ? `${ip}:9053` : '')

  const heroWord = established
    ? `Bootstrapped ${bootstrap}% · Connected`
    : running
    ? `Bootstrapping ${bootstrap}%`
    : 'Tor is not running'
  const heroDetail = established
    ? 'Circuits are established — traffic can flow through Tor'
    : running
    ? status?.BootstrapSummary || 'Connecting to the Tor network…'
    : 'The daemon is starting up or has exited; it restarts automatically'

  return (
    <Page>
      <ListHeader
        title="Tor"
        description="Route traffic through the Tor anonymity network"
        mark="to"
        status={established ? 'Connected' : running ? `Bootstrapping ${bootstrap}%` : 'Stopped'}
        statusAction={established ? 'success' : running ? 'warning' : 'muted'}
      >
        <Button
          size="sm"
          variant="outline"
          onPress={newIdentity}
          isDisabled={!running || nymBusy}
        >
          <ButtonText>{nymBusy ? 'Requesting…' : 'New identity'}</ButtonText>
        </Button>
      </ListHeader>

      <Card>
        <HStack space="md" alignItems="center" mb={bootstrapping ? '$3' : '$4'}>
          <StatusDot online={established} warn={bootstrapping} />
          <VStack flexShrink={1}>
            <Text size="md" bold>
              {heroWord}
            </Text>
            <Text size="xs" color="$muted500">
              {heroDetail}
            </Text>
          </VStack>
        </HStack>
        {bootstrapping ? (
          <Box mb="$4">
            <ProgressBar value={bootstrap} />
          </Box>
        ) : null}
        <HStack flexWrap="wrap" gap="$2">
          <StatTile label="Daemon" value={running ? 'Running' : 'Stopped'} />
          <StatTile label="Version" value={status?.Version || '—'} mono />
          <StatTile label="Downloaded" value={fmtBytes(status?.BytesRead)} mono />
          <StatTile label="Uploaded" value={fmtBytes(status?.BytesWritten)} mono />
        </HStack>
      </Card>

      <Card>
        <SectionHeader title="Proxy endpoints" />
        <VStack>
          <EndpointRow
            label="SOCKS5 proxy"
            desc="Point apps at this proxy"
            value={socksAddr}
            on={running}
            onCopy={() => copyValue(socksAddr)}
          />
          <EndpointRow
            label="Transparent proxy"
            desc="For routing SPR devices or groups through Tor"
            value={transAddr}
            on={running && !!config.TransPortEnabled}
            onCopy={() => copyValue(transAddr)}
          />
          <EndpointRow
            label="DNS resolver"
            desc="Resolves DNS queries through Tor"
            value={dnsAddr}
            on={running && !!config.DNSPortEnabled}
            onCopy={() => copyValue(dnsAddr)}
          />
        </VStack>
        <Text size="xs" color="$muted500" mt="$3">
          Only devices in the SPR “tor” group can reach these endpoints. Turn the optional
          ports on or off under Configuration.
        </Text>
      </Card>

      <Card>
        <SectionHeader
          title="Circuits"
          count={circuits.length}
          right={
            <Button size="xs" variant="outline" action="secondary" onPress={refreshCircuits}>
              <ButtonText>Refresh</ButtonText>
            </Button>
          }
        />
        {circuits.length === 0 ? (
          <EmptyState
            title="No circuits yet"
            description={
              running
                ? 'Circuits appear once tor finishes bootstrapping and builds paths through the network.'
                : 'Circuits appear after the tor daemon starts and bootstraps.'
            }
          />
        ) : (
          <VStack>
            {circuits.map((c, i) => (
              <HStack
                key={c.ID}
                justifyContent="space-between"
                alignItems="center"
                flexWrap="wrap"
                gap="$2"
                py="$2"
                borderBottomWidth={i < circuits.length - 1 ? 1 : 0}
                borderColor="$borderColorCardLight"
                sx={{ _dark: { borderColor: '$borderColorCardDark' } }}
              >
                <HStack space="sm" alignItems="center" flexShrink={1} flexWrap="wrap">
                  <Badge
                    action={circuitAction(c.Status)}
                    variant="outline"
                    borderRadius="$full"
                    size="sm"
                  >
                    <BadgeText>{c.Status}</BadgeText>
                  </Badge>
                  <Text size="sm" sx={{ '@base': { fontFamily: 'monospace' } }}>
                    {(c.Path || []).join(' → ') || '(building path)'}
                  </Text>
                </HStack>
                <Text size="xs" color="$muted500">
                  {[c.Purpose, circuitAge(c.TimeCreated)].filter(Boolean).join(' · ') || '—'}
                </Text>
              </HStack>
            ))}
          </VStack>
        )}
      </Card>

      <Card>
        <SectionHeader
          title="Configuration"
          right={
            <HStack space="sm" alignItems="center">
              <Text size="xs" color="$muted500">
                Applying reloads tor
              </Text>
              <Button size="xs" onPress={save} isDisabled={!dirty || !formValid || saving}>
                <ButtonText>{saving ? 'Saving…' : 'Save'}</ButtonText>
              </Button>
            </HStack>
          }
        />
        <VStack space="md">
          <TextField
            label="Exit country"
            value={form.ExitCountry}
            onChangeText={setField('ExitCountry')}
            placeholder="e.g. de — empty for automatic"
            helper="2-letter country code; restricts exit relays (StrictNodes)"
            error={countryError}
          />

          <ToggleRow
            title="Transparent proxy port (9040)"
            desc="For routing SPR devices or groups through Tor"
            value={form.TransPortEnabled}
            onPress={toggleField('TransPortEnabled')}
          />
          <ToggleRow
            title="DNS-over-Tor port (9053)"
            desc="Resolves DNS queries through the Tor network"
            value={form.DNSPortEnabled}
            onPress={toggleField('DNSPortEnabled')}
          />
          <ToggleRow
            title="SafeSocks"
            desc="Reject SOCKS connections that leak DNS (breaks some apps)"
            value={form.SafeSocks}
            onPress={toggleField('SafeSocks')}
          />
          <ToggleRow
            title="Use bridges"
            desc="Connect via bridge relays (censored networks)"
            value={form.UseBridges}
            onPress={toggleField('UseBridges')}
          />

          <LabeledArea
            label="Bridges"
            value={form.Bridges}
            onChangeText={setField('Bridges')}
            placeholder={'obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0'}
            helper="One bridge per line: plain (ip:port [fingerprint]) or obfs4. Get bridges at bridges.torproject.org"
            error={bridgesError}
          />

          <LabeledArea
            label="SOCKS policy (advanced)"
            value={form.SocksPolicy}
            onChangeText={setField('SocksPolicy')}
            placeholder={'accept 192.168.2.0/24\nreject *'}
            helper="One accept/reject rule per line; empty allows all clients the SPR firewall lets through"
          />
        </VStack>
      </Card>
    </Page>
  )
}

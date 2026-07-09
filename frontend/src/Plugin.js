import React, { useCallback, useEffect, useRef, useState } from 'react'
import {
  api,
  useAlert,
  Page,
  ListHeader,
  Card,
  SectionHeader,
  StatTile,
  KeyVal,
  StatusDot,
  Toggle,
  TextField,
  Loading,
  EmptyState,
  Button,
  ButtonText,
  HStack,
  VStack,
  Text,
  Textarea,
  TextareaInput
} from '@spr-networks/plugin-ui'

const PLUGIN_BASE = `/plugins/${api.pluginURI() || 'spr-tor'}`

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

const LabeledArea = ({ label, helper, value, onChangeText, placeholder }) => (
  <VStack space="xs">
    <Text size="sm" bold>
      {label}
    </Text>
    <Textarea h="$24">
      <TextareaInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        fontFamily="monospace"
        fontSize="$xs"
      />
    </Textarea>
    {helper ? (
      <Text size="xs" color="$muted500">
        {helper}
      </Text>
    ) : null}
  </VStack>
)

export default function Plugin() {
  const alert = useAlert()
  const [status, setStatus] = useState(null)
  const [config, setConfig] = useState(null)
  const [circuits, setCircuits] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  // editable form state (strings for the textareas)
  const [exitCountry, setExitCountry] = useState('')
  const [bridgesText, setBridgesText] = useState('')
  const [policyText, setPolicyText] = useState('')

  const timer = useRef(null)

  const refreshStatus = useCallback(() => {
    api
      .get(`${PLUGIN_BASE}/status`)
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  const refreshCircuits = useCallback(() => {
    api
      .get(`${PLUGIN_BASE}/circuits`)
      .then((c) => setCircuits(Array.isArray(c) ? c : []))
      .catch(() => setCircuits([]))
  }, [])

  const loadConfig = useCallback(() => {
    return api.get(`${PLUGIN_BASE}/config`).then((c) => {
      setConfig(c)
      setExitCountry(c?.ExitCountry || '')
      setBridgesText((c?.Bridges || []).join('\n'))
      setPolicyText((c?.SocksPolicy || []).join('\n'))
    })
  }, [])

  useEffect(() => {
    Promise.all([loadConfig().catch((err) => alert.error('Failed to load config', err))])
      .finally(() => setLoading(false))
    refreshStatus()
    refreshCircuits()
    timer.current = setInterval(() => {
      refreshStatus()
      refreshCircuits()
    }, 5000)
    return () => clearInterval(timer.current)
  }, [])

  const save = () => {
    const newConfig = {
      ...config,
      ExitCountry: exitCountry.trim(),
      Bridges: bridgesText.split('\n').map((s) => s.trim()).filter((s) => s.length),
      SocksPolicy: policyText.split('\n').map((s) => s.trim()).filter((s) => s.length)
    }
    setSaving(true)
    api
      .put(`${PLUGIN_BASE}/config`, newConfig)
      .then((saved) => {
        setConfig(saved)
        setBridgesText((saved?.Bridges || []).join('\n'))
        setPolicyText((saved?.SocksPolicy || []).join('\n'))
        alert.success('Saved — tor is reloading its configuration')
        setTimeout(refreshStatus, 1500)
      })
      .catch((err) => alert.error('Failed to save', err))
      .finally(() => setSaving(false))
  }

  const newIdentity = () => {
    api
      .post(`${PLUGIN_BASE}/newnym`)
      .then(() => alert.success('New identity requested (NEWNYM)'))
      .catch((err) => alert.error('Failed to request new identity', err))
  }

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
        <EmptyState
          title="Not available"
          description="Could not reach the spr-tor backend."
        >
          <Button size="sm" onPress={() => loadConfig().catch(() => {})}>
            <ButtonText>Retry</ButtonText>
          </Button>
        </EmptyState>
      </Page>
    )
  }

  const running = !!status?.Running
  const established = !!status?.CircuitEstablished
  const bootstrap = status?.BootstrapProgress ?? 0

  return (
    <Page>
      <ListHeader
        title="Tor"
        description="Route traffic through the Tor anonymity network"
        mark="to"
        status={established ? 'Circuit ready' : running ? 'Bootstrapping' : 'Stopped'}
        statusAction={established ? 'success' : running ? 'warning' : 'muted'}
      >
        <Button size="sm" variant="outline" onPress={newIdentity} isDisabled={!running}>
          <ButtonText>New Identity</ButtonText>
        </Button>
      </ListHeader>

      <Card>
        <SectionHeader
          title="Status"
          right={<StatusDot online={established} warn={running && !established} />}
        />
        <HStack flexWrap="wrap" gap="$2">
          <StatTile label="Daemon" value={running ? 'Running' : 'Starting…'} />
          <StatTile
            label="Bootstrap"
            value={running ? `${bootstrap}%` : '—'}
          />
          <StatTile
            label="Circuit"
            value={running ? (established ? 'Established' : 'Building…') : '—'}
          />
          <StatTile label="Version" value={status?.Version || '—'} mono />
          <StatTile label="Downloaded" value={fmtBytes(status?.BytesRead)} mono />
          <StatTile label="Uploaded" value={fmtBytes(status?.BytesWritten)} mono />
        </HStack>
        <VStack mt="$2" space="xs">
          {running && !established && status?.BootstrapSummary ? (
            <Text size="xs" color="$muted500">
              {status.BootstrapSummary}
            </Text>
          ) : null}
          <KeyVal label="SOCKS5 proxy" value={status?.SocksPort || '—'} mono />
          {status?.TransPort ? (
            <KeyVal label="Transparent proxy" value={status.TransPort} mono />
          ) : null}
          {status?.DNSPort ? (
            <KeyVal label="DNS resolver" value={status.DNSPort} mono />
          ) : null}
        </VStack>
      </Card>

      <Card>
        <SectionHeader
          title="Configuration"
          right={
            <Button size="xs" onPress={save} isDisabled={saving}>
              <ButtonText>{saving ? 'Saving…' : 'Save'}</ButtonText>
            </Button>
          }
        />
        <VStack space="md">
          <TextField
            label="Exit country"
            value={exitCountry}
            onChangeText={setExitCountry}
            placeholder="e.g. de, us — empty for automatic"
            helper="2-letter country code; restricts exit relays (StrictNodes)"
          />

          <HStack justifyContent="space-between" alignItems="center">
            <VStack flex={1} pr="$2">
              <Text size="sm" bold>
                Transparent proxy port (9040)
              </Text>
              <Text size="xs" color="$muted500">
                For routing SPR devices/groups through Tor
              </Text>
            </VStack>
            <Toggle
              value={!!config.TransPortEnabled}
              onPress={() =>
                setConfig({ ...config, TransPortEnabled: !config.TransPortEnabled })
              }
            />
          </HStack>

          <HStack justifyContent="space-between" alignItems="center">
            <VStack flex={1} pr="$2">
              <Text size="sm" bold>
                DNS-over-Tor port (9053)
              </Text>
              <Text size="xs" color="$muted500">
                Resolves DNS queries through the Tor network
              </Text>
            </VStack>
            <Toggle
              value={!!config.DNSPortEnabled}
              onPress={() =>
                setConfig({ ...config, DNSPortEnabled: !config.DNSPortEnabled })
              }
            />
          </HStack>

          <HStack justifyContent="space-between" alignItems="center">
            <VStack flex={1} pr="$2">
              <Text size="sm" bold>
                SafeSocks
              </Text>
              <Text size="xs" color="$muted500">
                Reject SOCKS connections that leak DNS (breaks some apps)
              </Text>
            </VStack>
            <Toggle
              value={!!config.SafeSocks}
              onPress={() => setConfig({ ...config, SafeSocks: !config.SafeSocks })}
            />
          </HStack>

          <HStack justifyContent="space-between" alignItems="center">
            <VStack flex={1} pr="$2">
              <Text size="sm" bold>
                Use bridges
              </Text>
              <Text size="xs" color="$muted500">
                Connect via bridge relays (censored networks)
              </Text>
            </VStack>
            <Toggle
              value={!!config.UseBridges}
              onPress={() => setConfig({ ...config, UseBridges: !config.UseBridges })}
            />
          </HStack>

          <LabeledArea
            label="Bridges"
            value={bridgesText}
            onChangeText={setBridgesText}
            placeholder={'obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0'}
            helper="One bridge per line: plain (ip:port [fingerprint]) or obfs4. Get bridges at bridges.torproject.org"
          />

          <LabeledArea
            label="SOCKS policy (advanced)"
            value={policyText}
            onChangeText={setPolicyText}
            placeholder={'accept 192.168.2.0/24\nreject *'}
            helper="One accept/reject rule per line; empty allows all clients the SPR firewall lets through"
          />
        </VStack>
      </Card>

      <Card>
        <SectionHeader
          title="Circuits"
          count={circuits.length}
          right={
            <Button size="xs" variant="outline" onPress={refreshCircuits}>
              <ButtonText>Refresh</ButtonText>
            </Button>
          }
        />
        {circuits.length === 0 ? (
          <Text size="sm" color="$muted500">
            No open circuits
          </Text>
        ) : (
          <VStack space="sm">
            {circuits.map((c) => (
              <HStack key={c.ID} justifyContent="space-between" flexWrap="wrap" gap="$2">
                <Text size="sm" fontFamily="monospace">
                  #{c.ID} {(c.Path || []).join(' → ') || '(building)'}
                </Text>
                <Text size="xs" color="$muted500">
                  {c.Status}
                  {c.Purpose ? ` · ${c.Purpose}` : ''}
                </Text>
              </HStack>
            ))}
          </VStack>
        )}
      </Card>
    </Page>
  )
}

import { useState } from 'react'
import { useModelStore } from '../store/model.store'
import { DATA_CLASSIFICATIONS } from '../canvas/domainEnums'

const inputStyle = { border: '1px solid var(--border)', background: 'var(--surface-0)', color: 'var(--text-primary)' }

/** Which data assets a flow carries, and in which direction — per-asset
 * Sent/Received checkboxes rather than one edge-level direction field,
 * matching CommunicationLink.dataSent/dataReceived (src/DSL/CommunicationLink.php):
 * a checkout flow might *send* a payment request and *receive* a
 * confirmation token back, two different assets going opposite ways on the
 * same edge. */
export function DataFlowAssets({
  edgeId,
  dataSent,
  dataReceived,
}: {
  edgeId: string
  dataSent: string[]
  dataReceived: string[]
}) {
  const dataAssets = useModelStore((s) => s.dataAssets)
  const addDataAsset = useModelStore((s) => s.addDataAsset)
  const updateEdgeData = useModelStore((s) => s.updateEdgeData)
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [classification, setClassification] = useState('confidential')

  const toggle = (list: string[], assetId: string, checked: boolean): string[] =>
    checked ? [...list, assetId] : list.filter((id) => id !== assetId)

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          Data assets
        </span>
        <button
          type="button"
          aria-label="New data asset"
          onClick={() => setCreating((v) => !v)}
          className="text-xs px-1.5 py-0.5 rounded"
          style={{ border: '1px solid var(--border)' }}
        >
          + New
        </button>
      </div>

      {creating && (
        <form
          className="flex flex-col gap-1.5 p-2 rounded"
          style={{ background: 'var(--surface-1)' }}
          onSubmit={(e) => {
            e.preventDefault()
            const trimmed = name.trim()
            if (!trimmed) return
            const asset = addDataAsset(trimmed, classification)
            updateEdgeData(edgeId, { dataSent: [...dataSent, asset.id] })
            setName('')
            setCreating(false)
          }}
        >
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Payment card data"
            aria-label="New data asset name"
            className="px-2 py-1 rounded text-sm"
            style={inputStyle}
          />
          <select
            aria-label="New data asset classification"
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="px-2 py-1 rounded text-sm"
            style={inputStyle}
          >
            {DATA_CLASSIFICATIONS.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
          <div className="flex gap-1.5">
            <button type="submit" className="text-xs px-2 py-1 rounded font-medium" style={{ background: 'var(--accent)', color: 'var(--accent-contrast)' }}>
              Add &amp; mark as sent
            </button>
            <button type="button" onClick={() => setCreating(false)} className="text-xs px-2 py-1 rounded" style={{ border: '1px solid var(--border)' }}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {dataAssets.length === 0 && !creating && (
        <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          No data assets defined yet — click "+ New" to describe what this flow carries (e.g. payment card data).
        </div>
      )}

      {dataAssets.length > 0 && (
        <table className="text-xs w-full">
          <thead>
            <tr style={{ color: 'var(--text-secondary)' }}>
              <th className="text-left font-normal pb-1">Asset</th>
              <th className="font-normal pb-1 w-14">Sent</th>
              <th className="font-normal pb-1 w-16">Received</th>
            </tr>
          </thead>
          <tbody>
            {dataAssets.map((asset) => (
              <tr key={asset.id}>
                <td className="py-0.5" style={{ color: 'var(--text-primary)' }}>
                  {asset.name}
                  {asset.classification && (
                    <span className="ml-1 text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                      ({asset.classification})
                    </span>
                  )}
                </td>
                <td className="text-center">
                  <input
                    type="checkbox"
                    aria-label={`${asset.name} sent`}
                    checked={dataSent.includes(asset.id)}
                    onChange={(e) => updateEdgeData(edgeId, { dataSent: toggle(dataSent, asset.id, e.target.checked) })}
                  />
                </td>
                <td className="text-center">
                  <input
                    type="checkbox"
                    aria-label={`${asset.name} received`}
                    checked={dataReceived.includes(asset.id)}
                    onChange={(e) =>
                      updateEdgeData(edgeId, { dataReceived: toggle(dataReceived, asset.id, e.target.checked) })
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

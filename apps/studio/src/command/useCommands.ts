import { useMemo } from 'react'
import { useReactFlow } from '@xyflow/react'
import { cascadeOffset, useModelStore, useTemporalStore } from '../store/model.store'
import { useElkLayout } from '../layout/useElkLayout'
import { useExportCanvas } from '../canvas/useExportCanvas'
import type { KbBundle } from '../api/types'

export interface Command {
  id: string
  label: string
  group: string
  run: () => void
}

/** Builds the full T-7.18 command list: static canvas/view actions plus one
 * "Add <component>" entry per KB component, so the count and coverage scale
 * with the KB rather than being hand-maintained. */
export function useCommands(kb: KbBundle | undefined, onRunAnalysis: () => void): Command[] {
  const addComponentFromKb = useModelStore((s) => s.addComponentFromKb)
  const addBoundary = useModelStore((s) => s.addBoundary)
  const setOverlayMode = useModelStore((s) => s.setOverlayMode)
  const setNodes = useModelStore((s) => s.setNodes)
  const setEdges = useModelStore((s) => s.setEdges)
  const { undo, redo } = useTemporalStore()
  const { runLayout } = useElkLayout()
  const { exportAs } = useExportCanvas()
  const { screenToFlowPosition } = useReactFlow()

  return useMemo(() => {
    const centerPosition = () => {
      const center = screenToFlowPosition({ x: window.innerWidth / 2, y: window.innerHeight / 2 })
      const offset = cascadeOffset(useModelStore.getState().nodes.length)
      return { x: center.x + offset.x, y: center.y + offset.y }
    }

    const commands: Command[] = [
      { id: 'undo', label: 'Undo', group: 'Edit', run: () => undo() },
      { id: 'redo', label: 'Redo', group: 'Edit', run: () => redo() },
      { id: 'auto-layout', label: 'Auto-layout canvas (ELK)', group: 'Canvas', run: () => void runLayout() },
      { id: 'add-boundary', label: 'Add trust boundary', group: 'Canvas', run: () => addBoundary(centerPosition()) },
      {
        id: 'clear-canvas',
        label: 'Clear canvas',
        group: 'Canvas',
        run: () => {
          setNodes(() => [])
          setEdges(() => [])
        },
      },
      { id: 'run-analysis', label: 'Run analysis', group: 'Analysis', run: onRunAnalysis },
      { id: 'export-png', label: 'Export canvas as PNG', group: 'Export', run: () => void exportAs('png') },
      { id: 'export-svg', label: 'Export canvas as SVG', group: 'Export', run: () => void exportAs('svg') },
      { id: 'overlay-risks', label: 'Overlay: Risks', group: 'View', run: () => setOverlayMode('risks') },
      { id: 'overlay-data', label: 'Overlay: Data', group: 'View', run: () => setOverlayMode('data') },
      { id: 'overlay-exposure', label: 'Overlay: Exposure', group: 'View', run: () => setOverlayMode('exposure') },
      { id: 'overlay-coverage', label: 'Overlay: Coverage', group: 'View', run: () => setOverlayMode('coverage') },
      {
        id: 'focus-search',
        label: 'Focus component search',
        group: 'View',
        run: () => document.getElementById('component-search')?.focus(),
      },
    ]

    if (kb) {
      for (const [id, component] of Object.entries(kb.components)) {
        commands.push({
          id: `add-${id}`,
          label: `Add ${component.metadata.name}`,
          group: 'Add component',
          run: () => addComponentFromKb(id, component, centerPosition()),
        })
      }
    }

    return commands
  }, [kb, onRunAnalysis, addComponentFromKb, addBoundary, setOverlayMode, setNodes, setEdges, undo, redo, runLayout, exportAs, screenToFlowPosition])
}

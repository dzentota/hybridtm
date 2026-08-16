import { useCallback } from 'react'
import { toPng, toSvg } from 'html-to-image'
import { getViewportForBounds, useReactFlow } from '@xyflow/react'

const EXPORT_PADDING = 40

/** Exports the canvas to PNG/SVG (T-7.19), preserving theme colors and
 * trust-boundary boxes since it rasterizes/serializes the real DOM rather
 * than redrawing the graph. */
export function useExportCanvas() {
  const { getNodes, getNodesBounds } = useReactFlow()

  const exportAs = useCallback(
    async (format: 'png' | 'svg') => {
      const nodes = getNodes()
      if (nodes.length === 0) return
      // `getNodesBounds` off the ReactFlow instance (not the standalone
      // export) so boundary-nested component positions resolve through its
      // nodeLookup instead of being read as if they were already absolute.
      const bounds = getNodesBounds(nodes)
      const width = Math.max(400, bounds.width + EXPORT_PADDING * 2)
      const height = Math.max(300, bounds.height + EXPORT_PADDING * 2)
      const viewport = getViewportForBounds(bounds, width, height, 0.1, 2, EXPORT_PADDING)

      const viewportEl = document.querySelector<HTMLElement>('.react-flow__viewport')
      if (!viewportEl) return

      const backgroundColor = getComputedStyle(document.body).getPropertyValue('--surface-0').trim() || '#ffffff'
      const options = {
        backgroundColor,
        width,
        height,
        style: {
          width: `${width}px`,
          height: `${height}px`,
          transform: `translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})`,
        },
      }

      const dataUrl = format === 'png' ? await toPng(viewportEl, options) : await toSvg(viewportEl, options)
      const link = document.createElement('a')
      link.href = dataUrl
      link.download = `hybridtm-model.${format}`
      link.click()
    },
    [getNodes, getNodesBounds],
  )

  return { exportAs }
}

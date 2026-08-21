import { useCallback } from 'react'
import { toPng, toSvg } from 'html-to-image'
import { getViewportForBounds, useReactFlow } from '@xyflow/react'

const EXPORT_PADDING = 40
// getViewportForBounds clamps zoom so the diagram just fits the (bounds-sized)
// export box, which lands close to 1x — same pixel size as it appears on
// screen, so exported PNGs looked blurry/too small to read. pixelRatio
// renders the raster at a multiple of that instead, independent of zoom.
const EXPORT_PNG_PIXEL_RATIO = 3

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
      // getViewportForBounds's padding arg is a fraction/CSS-length, not a bare
      // px number — passing the raw EXPORT_PADDING number here was read as a
      // ~4000% padding fraction, zooming out so far the model shrank to a
      // sliver of the exported canvas. The 'px' suffix picks the pixel branch.
      const viewport = getViewportForBounds(bounds, width, height, 0.1, 2, `${EXPORT_PADDING}px`)

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

      const dataUrl =
        format === 'png'
          ? await toPng(viewportEl, { ...options, pixelRatio: EXPORT_PNG_PIXEL_RATIO })
          : await toSvg(viewportEl, options)
      const link = document.createElement('a')
      link.href = dataUrl
      link.download = `hybridtm-model.${format}`
      link.click()
    },
    [getNodes, getNodesBounds],
  )

  return { exportAs }
}

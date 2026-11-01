import "uplot/dist/uPlot.min.css";

import { useEffect, useRef } from "react";
import uPlot from "uplot";

export interface Series {
  label: string;
  /** A CSS custom property such as `--rd-ok`. */
  color: string;
  values: number[];
}

function cssColor(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

/**
 * A time chart (uPlot): faint grid, 12 % area fill, a legend that toggles series
 * (docs/08-design-system.md §4).
 */
export function Chart({ times, series, height = 220, unit = "" }: {
  times: number[];
  series: Series[];
  height?: number;
  unit?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const theme = document.documentElement.dataset.theme;

  useEffect(() => {
    const element = box.current;
    if (!element) return;
    const grid = cssColor("--rd-border");
    const text = cssColor("--rd-text-3");
    const axis = { stroke: text, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid, width: 1 } };
    const options: uPlot.Options = {
      width: element.clientWidth,
      height,
      cursor: { drag: { x: false, y: false } },
      legend: { live: true },
      scales: { x: { time: true } },
      axes: [axis, { ...axis, values: (_u, ticks) => ticks.map((t) => `${t}${unit}`) }],
      series: [
        {},
        ...series.map((s) => {
          const color = cssColor(s.color);
          return { label: s.label, stroke: color, fill: `${color}1f`, width: 1.5, points: { show: false } };
        }),
      ],
    };
    plot.current = new uPlot(options, [times, ...series.map((s) => s.values)], element);
    const resize = new ResizeObserver(() => plot.current?.setSize({ width: element.clientWidth, height }));
    resize.observe(element);
    return () => {
      resize.disconnect();
      plot.current?.destroy();
      plot.current = null;
    };
    // Rebuild only when the shape or the theme changes; data updates go through setData.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [series.length, height, theme, unit]);

  useEffect(() => {
    plot.current?.setData([times, ...series.map((s) => s.values)]);
  }, [times, series]);

  return <div ref={box} className="w-full" />;
}

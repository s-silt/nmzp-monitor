import { useState } from "react";
import { ORIGIN, project } from "@/lib/monitor/geo";
import { formatBytes } from "@/lib/monitor/format";
import type { NetworkHop } from "@/lib/monitor/types";
import { cn } from "@/lib/utils";

const W = 920;
const H = 420;

function arc(x1: number, y1: number, x2: number, y2: number) {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - Math.max(28, Math.abs(x2 - x1) * 0.22);
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;
}

// Stylized world continent landmass outlines for 920x420 projection
const CONTINENTS = [
  // North America
  "M 120,60 L 260,50 L 320,80 L 290,130 L 260,180 L 220,230 L 190,200 L 160,170 L 130,130 L 100,90 Z",
  // Greenland
  "M 330,30 L 380,35 L 370,75 L 330,65 Z",
  // South America
  "M 240,240 L 300,260 L 330,310 L 310,380 L 270,395 L 250,330 L 230,270 Z",
  // Europe
  "M 450,70 L 530,65 L 540,115 L 490,140 L 445,120 L 440,85 Z",
  // Africa
  "M 450,150 L 530,155 L 565,220 L 530,320 L 490,345 L 450,270 L 435,190 Z",
  // Asia
  "M 545,65 L 750,55 L 820,100 L 780,180 L 720,210 L 670,220 L 620,170 L 560,150 L 545,110 Z",
  // Australia
  "M 740,270 L 820,275 L 830,335 L 760,345 L 730,305 Z",
];

export function WorldMap({ hops }: { hops: NetworkHop[] }) {
  const [hoveredHop, setHoveredHop] = useState<NetworkHop | null>(null);
  const origin = project(ORIGIN.lng, ORIGIN.lat, W, H);
  const latest = hops.slice(-24);

  return (
    <div className="overflow-hidden rounded-2xl bg-surface shadow-[var(--shadow-border)] border border-line">
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full bg-elevated/40" role="img" aria-label="Network destinations">
          <defs>
            <linearGradient id="arcGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--color-ok)" stopOpacity="0.8" />
              <stop offset="100%" stopColor="var(--color-danger)" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Background grid lines */}
          {Array.from({ length: 12 }, (_, i) => (
            <line
              key={`v${i}`}
              x1={(W / 12) * i}
              y1={0}
              x2={(W / 12) * i}
              y2={H}
              stroke="var(--color-line)"
              strokeWidth="0.8"
              strokeDasharray="3 3"
            />
          ))}
          {Array.from({ length: 6 }, (_, i) => (
            <line
              key={`h${i}`}
              x1={0}
              y1={(H / 6) * i}
              x2={W}
              y2={(H / 6) * i}
              stroke="var(--color-line)"
              strokeWidth="0.8"
              strokeDasharray="3 3"
            />
          ))}

          {/* Continents silhouette */}
          {CONTINENTS.map((d, idx) => (
            <path
              key={`c-${idx}`}
              d={d}
              fill="var(--color-line-strong)"
              opacity="0.35"
              stroke="var(--color-line)"
              strokeWidth="0.5"
            />
          ))}

          {/* Trajectory arcs */}
          {latest.map((hop) => {
            const p = project(hop.lng, hop.lat, W, H);
            const isHovered = hoveredHop?.id === hop.id;
            return (
              <g key={hop.id} onMouseEnter={() => setHoveredHop(hop)} onMouseLeave={() => setHoveredHop(null)} className="cursor-pointer">
                <path
                  d={arc(origin.x, origin.y, p.x, p.y)}
                  fill="none"
                  stroke={isHovered ? "var(--color-danger)" : "url(#arcGradient)"}
                  strokeOpacity={isHovered ? 1 : 0.45}
                  strokeWidth={isHovered ? 2.5 : 1.4}
                  strokeDasharray={hop.inferred ? "4 3" : undefined}
                />
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 5.5 : 3.5}
                  fill="var(--color-danger)"
                  className="transition-all"
                />
                {isHovered ? (
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={9}
                    fill="none"
                    stroke="var(--color-danger)"
                    strokeWidth="1.5"
                    opacity="0.6"
                    className="animate-ping"
                  />
                ) : null}
              </g>
            );
          })}

          {/* Origin: Tokyo CT */}
          <circle cx={origin.x} cy={origin.y} r="5" fill="var(--color-ok)" />
          <circle cx={origin.x} cy={origin.y} r="9" fill="none" stroke="var(--color-ok)" strokeWidth="1" opacity="0.5" className="animate-pulse" />
          <text
            x={origin.x + 10}
            y={origin.y + 4}
            fill="var(--color-fg)"
            fontSize="11"
            fontFamily="IBM Plex Mono, monospace"
            fontWeight="bold"
          >
            Tokyo CT (Local)
          </text>
        </svg>

        {/* Hovered node floating pill */}
        {hoveredHop ? (
          <div className="absolute top-3 right-3 rounded-xl bg-surface/95 p-3 shadow-lg border border-line backdrop-blur-sm font-mono text-xs max-w-xs">
            <p className="font-semibold text-fg">{hoveredHop.hostname}</p>
            <p className="text-subtle mt-0.5">
              {hoveredHop.city}, {hoveredHop.country} · IP: {hoveredHop.ip}:{hoveredHop.port}
            </p>
            <p className="text-danger mt-1">
              Transferred: {formatBytes(hoveredHop.bytes)} ({hoveredHop.inferred ? "Inferred" : "Observed"})
            </p>
          </div>
        ) : null}
      </div>

      {/* Quick recent connections bar */}
      <ul className="grid gap-px border-t border-line bg-line sm:grid-cols-2 lg:grid-cols-3">
        {latest
          .slice()
          .reverse()
          .slice(0, 6)
          .map((hop) => (
            <li
              key={hop.id}
              onMouseEnter={() => setHoveredHop(hop)}
              onMouseLeave={() => setHoveredHop(null)}
              className={cn(
                "flex items-center justify-between gap-3 bg-surface px-4 py-3 text-xs transition-colors cursor-pointer",
                hoveredHop?.id === hop.id ? "bg-elevated" : "hover:bg-elevated/60",
              )}
            >
              <span className="min-w-0 truncate font-mono text-fg font-medium">
                {hop.hostname}
                <span className="text-subtle font-normal">
                  {" "}
                  · {hop.city}/{hop.country}
                </span>
              </span>
              <span className="shrink-0 font-mono tabular-nums text-muted">{formatBytes(hop.bytes)}</span>
            </li>
          ))}
      </ul>
    </div>
  );
}


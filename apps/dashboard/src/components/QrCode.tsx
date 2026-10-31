import { encode } from "uqr";

/** A QR code drawn as one SVG path, so no image or inline markup is needed (CSP). */
export function QrCode({ text, size = 184 }: { text: string; size?: number }) {
  const { data } = encode(text, { ecc: "M", border: 2 });
  const path = data
    .flatMap((row, y) => row.map((dark, x) => (dark ? `M${x} ${y}h1v1h-1z` : "")))
    .join("");
  return (
    <svg
      viewBox={`0 0 ${data.length} ${data.length}`}
      width={size}
      height={size}
      role="img"
      aria-label="QR code for your authenticator app"
      shapeRendering="crispEdges"
      className="rounded-sm bg-white"
    >
      <path d={path} fill="#1C1917" />
    </svg>
  );
}

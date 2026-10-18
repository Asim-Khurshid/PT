export function ShieldLogo({ size = 48, showText = false }: { size?: number; showText?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      {/* Shield Logo SVG */}
      <svg
        width={size}
        height={size}
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0"
      >
        {/* Shield background with gradient */}
        <defs>
          <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style={{ stopColor: "#06b6d4", stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: "#0891b2", stopOpacity: 1 }} />
          </linearGradient>
          <filter id="shieldGlow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Outer shield shape */}
        <path
          d="M24 2L8 10V22C8 32 24 44 24 44C24 44 40 32 40 22V10L24 2Z"
          fill="url(#shieldGradient)"
          filter="url(#shieldGlow)"
          className="transition-all duration-300"
        />

        {/* Inner checkmark */}
        <path
          d="M18 25L22 29L32 17"
          stroke="white"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
      </svg>

      {/* Text - optional */}
      {showText && <span className="text-lg font-bold text-foreground">FalconScan</span>}
    </div>
  )
}

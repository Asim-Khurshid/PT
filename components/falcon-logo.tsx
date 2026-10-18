export function FalconLogo({ size = 128, showText = false }: { size?: number; showText?: boolean }) {
  return (
    <svg width={size} height={size * 0.7} viewBox="0 0 256 180" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="falconFeathers" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#1a1a1a" />
          <stop offset="100%" stopColor="#0a0a0a" />
        </linearGradient>
        <filter id="falconShadow">
          <feDropShadow dx="2" dy="2" stdDeviation="3" floodOpacity="0.4" />
        </filter>
      </defs>

      {/* Falcon Head - Profile view, serious and sharp */}
      <g filter="url(#falconShadow)">
        {/* Head shape - rounded profile */}
        <ellipse cx="85" cy="70" rx="32" ry="40" fill="url(#falconFeathers)" stroke="#2a2a2a" strokeWidth="1" />

        {/* Head feather texture - detail lines */}
        <path d="M 55 50 Q 65 60 58 75" stroke="#333333" strokeWidth="0.8" opacity="0.6" fill="none" />
        <path d="M 52 58 Q 62 68 55 82" stroke="#333333" strokeWidth="0.8" opacity="0.5" fill="none" />
        <path d="M 50 65 Q 60 75 53 90" stroke="#333333" strokeWidth="0.8" opacity="0.4" fill="none" />

        {/* Eye - sharp golden alert eye */}
        <circle cx="102" cy="55" r="9" fill="#d4a574" stroke="#0a0a0a" strokeWidth="1.2" />
        <circle cx="103" cy="54" r="5" fill="#1a1a1a" />
        <circle cx="104" cy="53" r="2" fill="#ffffff" opacity="0.8" />

        {/* Beak - sharp, hooked predator beak */}
        <path
          d="M 115 65 Q 155 58 170 72 Q 155 78 115 72 Z"
          fill="url(#falconFeathers)"
          stroke="#2a2a2a"
          strokeWidth="1.2"
        />
        <path d="M 115 72 Q 155 78 170 72" stroke="#1a1a1a" strokeWidth="0.8" fill="none" />
        <circle cx="145" cy="68" r="1.5" fill="#1a1a1a" opacity="0.7" />

        {/* Face markings - typical falcon stripe */}
        <path d="M 102 70 L 115 80" stroke="#2a2a2a" strokeWidth="1" opacity="0.6" />
      </g>

      {/* Left Wing - Sharp, detailed feathers */}
      <g>
        {/* Primary flight feathers - long and sharp */}
        <path
          d="M 60 85 Q 25 95 12 120 Q 20 105 35 95 Q 50 85 60 85"
          stroke="#0a0a0a"
          strokeWidth="2.2"
          fill="none"
          strokeLinecap="round"
        />
        <path
          d="M 58 92 Q 22 105 8 135 Q 18 115 33 102 Q 48 92 58 92"
          stroke="#1a1a1a"
          strokeWidth="2"
          fill="none"
          opacity="0.85"
          strokeLinecap="round"
        />
        <path
          d="M 56 100 Q 20 115 5 150 Q 15 125 32 110 Q 46 100 56 100"
          stroke="#2a2a2a"
          strokeWidth="1.8"
          fill="none"
          opacity="0.7"
          strokeLinecap="round"
        />
        <path
          d="M 54 108 Q 18 125 3 160 Q 12 132 30 118 Q 44 108 54 108"
          stroke="#333333"
          strokeWidth="1.5"
          fill="none"
          opacity="0.55"
          strokeLinecap="round"
        />

        {/* Wing covert feathers - detail texture */}
        <path d="M 62 90 Q 50 98 42 110" stroke="#1a1a1a" strokeWidth="0.7" fill="none" opacity="0.5" />
        <path d="M 60 96 Q 48 105 39 120" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.4" />
        <path d="M 58 102 Q 46 112 36 130" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.35" />
      </g>

      {/* Right Wing - Mirror with detail */}
      <g>
        {/* Primary flight feathers */}
        <path
          d="M 110 85 Q 145 95 158 120 Q 150 105 135 95 Q 120 85 110 85"
          stroke="#0a0a0a"
          strokeWidth="2.2"
          fill="none"
          strokeLinecap="round"
        />
        <path
          d="M 112 92 Q 148 105 162 135 Q 152 115 137 102 Q 122 92 112 92"
          stroke="#1a1a1a"
          strokeWidth="2"
          fill="none"
          opacity="0.85"
          strokeLinecap="round"
        />
        <path
          d="M 114 100 Q 150 115 165 150 Q 155 125 138 110 Q 124 100 114 100"
          stroke="#2a2a2a"
          strokeWidth="1.8"
          fill="none"
          opacity="0.7"
          strokeLinecap="round"
        />
        <path
          d="M 116 108 Q 152 125 167 160 Q 158 132 140 118 Q 126 108 116 108"
          stroke="#333333"
          strokeWidth="1.5"
          fill="none"
          opacity="0.55"
          strokeLinecap="round"
        />

        {/* Wing covert feathers */}
        <path d="M 108 90 Q 120 98 128 110" stroke="#1a1a1a" strokeWidth="0.7" fill="none" opacity="0.5" />
        <path d="M 110 96 Q 122 105 131 120" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.4" />
        <path d="M 112 102 Q 124 112 134 130" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.35" />
      </g>

      {/* Body - streamlined */}
      <path d="M 85 110 Q 88 130 85 160" stroke="#1a1a1a" strokeWidth="2" fill="none" opacity="0.6" />

      {/* Tail feathers - spread */}
      <path
        d="M 75 155 Q 50 170 35 175"
        stroke="#0a0a0a"
        strokeWidth="1.5"
        fill="none"
        opacity="0.7"
        strokeLinecap="round"
      />
      <path
        d="M 85 160 Q 85 175 85 180"
        stroke="#1a1a1a"
        strokeWidth="1.8"
        fill="none"
        opacity="0.8"
        strokeLinecap="round"
      />
      <path
        d="M 95 155 Q 120 170 145 175"
        stroke="#0a0a0a"
        strokeWidth="1.5"
        fill="none"
        opacity="0.7"
        strokeLinecap="round"
      />

      {/* Text - "FALCONSCAN" optional */}
      {showText && (
        <text x="8" y="175" fontSize="16" fontWeight="bold" fill="#1a1a1a" fontFamily="monospace" letterSpacing="2">
          FALCONSCAN
        </text>
      )}
    </svg>
  )
}

export const FalconLogoSVG = (size = 128): string => {
  const height = Math.round(size * 0.7)
  return `<svg width="${size}" height="${height}" viewBox="0 0 256 180" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="falconFeathers" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#1a1a1a" />
        <stop offset="100%" stopColor="#0a0a0a" />
      </linearGradient>
      <filter id="falconShadow">
        <feDropShadow dx="2" dy="2" stdDeviation="3" floodOpacity="0.4" />
      </filter>
    </defs>
    <g filter="url(#falconShadow)">
      <ellipse cx="85" cy="70" rx="32" ry="40" fill="url(#falconFeathers)" stroke="#2a2a2a" strokeWidth="1" />
      <path d="M 55 50 Q 65 60 58 75" stroke="#333333" strokeWidth="0.8" opacity="0.6" fill="none" />
      <path d="M 52 58 Q 62 68 55 82" stroke="#333333" strokeWidth="0.8" opacity="0.5" fill="none" />
      <path d="M 50 65 Q 60 75 53 90" stroke="#333333" strokeWidth="0.8" opacity="0.4" fill="none" />
      <circle cx="102" cy="55" r="9" fill="#d4a574" stroke="#0a0a0a" strokeWidth="1.2" />
      <circle cx="103" cy="54" r="5" fill="#1a1a1a" />
      <circle cx="104" cy="53" r="2" fill="#ffffff" opacity="0.8" />
      <path d="M 115 65 Q 155 58 170 72 Q 155 78 115 72 Z" fill="url(#falconFeathers)" stroke="#2a2a2a" strokeWidth="1.2" />
      <path d="M 115 72 Q 155 78 170 72" stroke="#1a1a1a" strokeWidth="0.8" fill="none" />
      <circle cx="145" cy="68" r="1.5" fill="#1a1a1a" opacity="0.7" />
      <path d="M 102 70 L 115 80" stroke="#2a2a2a" strokeWidth="1" opacity="0.6" />
    </g>
    <g>
      <path d="M 60 85 Q 25 95 12 120 Q 20 105 35 95 Q 50 85 60 85" stroke="#0a0a0a" strokeWidth="2.2" fill="none" strokeLinecap="round" />
      <path d="M 58 92 Q 22 105 8 135 Q 18 115 33 102 Q 48 92 58 92" stroke="#1a1a1a" strokeWidth="2" fill="none" opacity="0.85" strokeLinecap="round" />
      <path d="M 56 100 Q 20 115 5 150 Q 15 125 32 110 Q 46 100 56 100" stroke="#2a2a2a" strokeWidth="1.8" fill="none" opacity="0.7" strokeLinecap="round" />
      <path d="M 54 108 Q 18 125 3 160 Q 12 132 30 118 Q 44 108 54 108" stroke="#333333" strokeWidth="1.5" fill="none" opacity="0.55" strokeLinecap="round" />
      <path d="M 62 90 Q 50 98 42 110" stroke="#1a1a1a" strokeWidth="0.7" fill="none" opacity="0.5" />
      <path d="M 60 96 Q 48 105 39 120" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.4" />
      <path d="M 58 102 Q 46 112 36 130" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.35" />
    </g>
    <g>
      <path d="M 110 85 Q 145 95 158 120 Q 150 105 135 95 Q 120 85 110 85" stroke="#0a0a0a" strokeWidth="2.2" fill="none" strokeLinecap="round" />
      <path d="M 112 92 Q 148 105 162 135 Q 152 115 137 102 Q 122 92 112 92" stroke="#1a1a1a" strokeWidth="2" fill="none" opacity="0.85" strokeLinecap="round" />
      <path d="M 114 100 Q 150 115 165 150 Q 155 125 138 110 Q 124 100 114 100" stroke="#2a2a2a" strokeWidth="1.8" fill="none" opacity="0.7" strokeLinecap="round" />
      <path d="M 116 108 Q 152 125 167 160 Q 158 132 140 118 Q 126 108 116 108" stroke="#333333" strokeWidth="1.5" fill="none" opacity="0.55" strokeLinecap="round" />
      <path d="M 108 90 Q 120 98 128 110" stroke="#1a1a1a" strokeWidth="0.7" fill="none" opacity="0.5" />
      <path d="M 110 96 Q 122 105 131 120" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.4" />
      <path d="M 112 102 Q 124 112 134 130" stroke="#2a2a2a" strokeWidth="0.7" fill="none" opacity="0.35" />
    </g>
    <path d="M 85 110 Q 88 130 85 160" stroke="#1a1a1a" strokeWidth="2" fill="none" opacity="0.6" />
    <path d="M 75 155 Q 50 170 35 175" stroke="#0a0a0a" strokeWidth="1.5" fill="none" opacity="0.7" strokeLinecap="round" />
    <path d="M 85 160 Q 85 175 85 180" stroke="#1a1a1a" strokeWidth="1.8" fill="none" opacity="0.8" strokeLinecap="round" />
    <path d="M 95 155 Q 120 170 145 175" stroke="#0a0a0a" strokeWidth="1.5" fill="none" opacity="0.7" strokeLinecap="round" />
  </svg>`
}

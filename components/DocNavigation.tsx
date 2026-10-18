"use client"

import { useState } from "react"
import { ChevronRight, BookOpen, Code, Settings, Shield, FileText, Brain, HelpCircle } from "lucide-react"

interface DocSection {
  id: string
  title: string
  icon: React.ComponentType<{ className?: string }>
  subsections?: { id: string; title: string }[]
}

interface DocNavigationProps {
  onSectionClick: (sectionId: string, subsectionId?: string) => void
  activeSection?: string
  activeSubsection?: string
}

const docSections: DocSection[] = [
  {
    id: "overview",
    title: "Overview",
    icon: BookOpen,
    subsections: [
      { id: "intro", title: "Introduction" },
      { id: "features", title: "Key Features" },
      { id: "architecture", title: "Architecture" },
    ],
  },
  {
    id: "user-guide",
    title: "User Guide",
    icon: FileText,
    subsections: [
      { id: "getting-started", title: "Getting Started" },
      { id: "uploading", title: "Upload APK" },
      { id: "reports", title: "Understanding Reports" },
      { id: "managing", title: "Managing Scans" },
    ],
  },
  {
    id: "security-analysis",
    title: "Security Analysis",
    icon: Shield,
    subsections: [
      { id: "vuln-categories", title: "Vulnerability Categories" },
      { id: "manifest", title: "Manifest Security" },
      { id: "permissions", title: "Permissions" },
      { id: "secrets", title: "Hardcoded Secrets" },
      { id: "weak-crypto", title: "Weak Cryptography" },
      { id: "network", title: "Network Security" },
    ],
  },
  {
    id: "ai-analysis",
    title: "AI Analysis",
    icon: Brain,
    subsections: [
      { id: "ai-overview", title: "What It Generates" },
      { id: "ai-setup", title: "How to Enable" },
      { id: "ai-usage", title: "Usage" },
    ],
  },
  {
    id: "api-reference",
    title: "API Reference",
    icon: Code,
    subsections: [
      { id: "auth-endpoints", title: "Authentication" },
      { id: "scan-endpoints", title: "Scan Endpoints" },
    ],
  },
  {
    id: "installation",
    title: "Installation",
    icon: Settings,
    subsections: [
      { id: "prerequisites", title: "Prerequisites" },
      { id: "backend-setup", title: "Backend Setup" },
      { id: "frontend-setup", title: "Frontend Setup" },
    ],
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting",
    icon: HelpCircle,
    subsections: [
      { id: "backend-issues", title: "Backend Issues" },
      { id: "frontend-issues", title: "Frontend Issues" },
    ],
  },
]

export function DocNavigation({ onSectionClick, activeSection, activeSubsection }: DocNavigationProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set([activeSection || "overview"]))

  const toggleSection = (sectionId: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev)
      if (next.has(sectionId)) {
        next.delete(sectionId)
      } else {
        next.add(sectionId)
      }
      return next
    })
  }

  return (
    <nav className="space-y-2 h-full overflow-y-auto">
      {docSections.map((section) => {
        const Icon = section.icon
        const isExpanded = expandedSections.has(section.id)
        const isActive = activeSection === section.id

        return (
          <div key={section.id}>
            <button
              onClick={() => {
                toggleSection(section.id)
                onSectionClick(section.id)
              }}
              className={`
                w-full px-4 py-3 rounded-lg flex items-center gap-3 transition-all duration-200 cursor-pointer
                ${
                  isActive
                    ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 shadow-lg shadow-cyan-500/10"
                    : "text-slate-300 hover:bg-slate-800/50 hover:text-cyan-400"
                }
              `}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span className="flex-1 text-left font-medium text-sm">{section.title}</span>
              {section.subsections && (
                <ChevronRight
                  className={`w-4 h-4 transition-transform duration-200 flex-shrink-0 ${
                    isExpanded ? "rotate-90" : ""
                  }`}
                />
              )}
            </button>

            {isExpanded && section.subsections && (
              <div className="ml-4 mt-2 space-y-1 pl-2 border-l border-slate-700">
                {section.subsections.map((subsection) => {
                  const isSubActive = activeSection === section.id && activeSubsection === subsection.id

                  return (
                    <button
                      key={subsection.id}
                      onClick={() => onSectionClick(section.id, subsection.id)}
                      className={`
                        w-full px-4 py-2 rounded-lg text-sm transition-all duration-200 text-left cursor-pointer
                        ${
                          isSubActive
                            ? "bg-purple-500/20 text-purple-400 font-medium"
                            : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/30"
                        }
                      `}
                    >
                      • {subsection.title}
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
    </nav>
  )
}

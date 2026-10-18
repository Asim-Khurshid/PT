
import * as React from "react"
"use client"

import { useState, ReactNode } from "react"
import { ChevronDown, ChevronUp, AlertTriangle, CheckCircle, AlertCircle, Info } from "lucide-react"
import { Button } from "@/components/ui/button"

interface AnalysisSection {
  title: string
  icon: React.ComponentType<{ className?: string }>
  data: Record<string, any>
  color: "cyan" | "red" | "yellow" | "green" | "purple"
}

interface AnalysisDetailsProps {
  sections: AnalysisSection[]
  isLoading?: boolean
}

const colorMap = {
  cyan: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  red: "border-red-500/30 text-red-400 bg-red-500/10",
  yellow: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  green: "border-green-500/30 text-green-400 bg-green-500/10",
  purple: "border-purple-500/30 text-purple-400 bg-purple-500/10",
}

export function AnalysisDetails({ sections, isLoading = false }: AnalysisDetailsProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const toggleSection = (title: string) => {
    setExpanded((prev) => ({ ...prev, [title]: !prev[title] }))
  }

  const renderValue = (value: any, depth: number = 0): React.ReactNode => {
    // Prevent infinite recursion
    if (depth > 3 || value === null || value === undefined) {
      return String(value)
    }

    if (Array.isArray(value)) {
      return (
        <div className="space-y-2 mt-2">
          {value.slice(0, 10).map((item, idx) => (
            <div key={idx} className="text-sm text-slate-300 pl-4 border-l border-slate-700">
              {typeof item === "object" && item !== null ? JSON.stringify(item, null, 2) : String(item)}
            </div>
          ))}
          {value.length > 10 && (
            <div className="text-xs text-slate-400 pl-4">... and {value.length - 10} more</div>
          )}
        </div>
      )
    }

    if (typeof value === "object" && value !== null) {
      return (
        <div className="space-y-3 mt-3 pl-4">
          {Object.entries(value).slice(0, 10).map(([key, val]) => (
            <div key={key} className="space-y-1">
              <div className="text-sm text-slate-400">{key}:</div>
              <div className="text-slate-300">{renderValue(val, depth + 1)}</div>
            </div>
          ))}
        </div>
      )
    }

    return String(value)
  }

  return (
    <div className="space-y-4">
      {isLoading ? (
        <div className="glassmorphism p-8 rounded-lg cyber-border text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading analysis...</p>
        </div>
      ) : (
        sections.map((section) => {
          const Icon = section.icon
          const isExpanded = expanded[section.title]
          const colorsClass = colorMap[section.color]

          return (
            <div key={section.title} className={`glassmorphism rounded-lg cyber-border overflow-hidden border ${colorsClass}`}>
              <button
                onClick={() => toggleSection(section.title)}
                className="w-full px-6 py-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-5 h-5" />
                  <h3 className="font-semibold">{section.title}</h3>
                </div>
                {isExpanded ? (
                  <ChevronUp className="w-5 h-5" />
                ) : (
                  <ChevronDown className="w-5 h-5" />
                )}
              </button>

              {isExpanded && (
                <div className="px-6 py-4 border-t border-current/20 space-y-4 bg-slate-900/20">
                  {Object.entries(section.data).map(([key, value]) => (
                    <div key={key} className="space-y-2">
                      <label className="text-sm font-medium text-slate-300 capitalize">
                        {key.replace(/_/g, " ")}
                      </label>
                      <div className="text-slate-300">{renderValue(value)}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })
      )}
    </div>
  )
}

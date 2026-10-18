"use client"

import { CheckCircle, Clock, AlertCircle, Zap } from "lucide-react"

export interface StatusStep {
  label: string
  status: "pending" | "in-progress" | "completed" | "error"
  timestamp?: string
  details?: string
}

interface StatusTrackerProps {
  title: string
  steps: StatusStep[]
  currentStep?: number
  progress?: number
}

export function StatusTracker({ title, steps, currentStep = 0, progress = 0 }: StatusTrackerProps) {
  const getStepIcon = (status: StatusStep["status"]) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case "in-progress":
        return <Zap className="w-5 h-5 text-cyan-400 animate-pulse" />
      case "error":
        return <AlertCircle className="w-5 h-5 text-red-400" />
      default:
        return <Clock className="w-5 h-5 text-slate-400" />
    }
  }

  const getStepColor = (status: StatusStep["status"]) => {
    switch (status) {
      case "completed":
        return "bg-green-500/10 border-green-500/30"
      case "in-progress":
        return "bg-cyan-500/10 border-cyan-500/30"
      case "error":
        return "bg-red-500/10 border-red-500/30"
      default:
        return "bg-slate-700/50 border-slate-600/50"
    }
  }

  const getTextColor = (status: StatusStep["status"]) => {
    switch (status) {
      case "completed":
        return "text-green-400"
      case "in-progress":
        return "text-cyan-400"
      case "error":
        return "text-red-400"
      default:
        return "text-slate-400"
    }
  }

  return (
    <div className="glassmorphism p-6 rounded-lg cyber-border space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
        {progress > 0 && (
          <div className="w-full bg-slate-700/30 rounded-full h-2 border border-slate-600/50">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-500"
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>
        )}
      </div>

      <div className="space-y-4">
        {steps.map((step, index) => (
          <div key={index} className="space-y-2">
            <div className={`p-4 rounded-lg border ${getStepColor(step.status)} transition-all duration-300`}>
              <div className="flex items-start gap-4">
                <div className="pt-0.5 flex-shrink-0">{getStepIcon(step.status)}</div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline justify-between gap-4">
                    <p className={`font-medium ${getTextColor(step.status)}`}>{step.label}</p>
                    {step.timestamp && <span className="text-xs text-slate-400 flex-shrink-0">{step.timestamp}</span>}
                  </div>

                  {step.details && (
                    <p className="text-sm text-slate-300 mt-2 line-clamp-2">{step.details}</p>
                  )}

                  {step.status === "in-progress" && (
                    <div className="flex gap-1 mt-3">
                      <div className="w-1 h-1 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                      <div className="w-1 h-1 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                      <div className="w-1 h-1 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

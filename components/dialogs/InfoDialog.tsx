"use client"

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { AlertTriangle, CheckCircle, Info, XCircle, AlertCircle } from "lucide-react"

interface InfoDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  details?: string
  onClose?: () => void
  closeText?: string
  variant?: "success" | "error" | "warning" | "info"
}

const variantConfig = {
  success: {
    icon: CheckCircle,
    color: "text-green-400",
    bgColor: "bg-green-500/10",
    borderColor: "border-green-500/30",
    accentBg: "bg-green-500/20",
  },
  error: {
    icon: XCircle,
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/30",
    accentBg: "bg-red-500/20",
  },
  warning: {
    icon: AlertTriangle,
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/30",
    accentBg: "bg-yellow-500/20",
  },
  info: {
    icon: Info,
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/30",
    accentBg: "bg-blue-500/20",
  },
}

export function InfoDialog({
  open,
  onOpenChange,
  title,
  description,
  details,
  onClose,
  closeText = "Close",
  variant = "info",
}: InfoDialogProps) {
  const config = variantConfig[variant]
  const Icon = config.icon

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border border-slate-700 bg-slate-900/95 backdrop-blur-sm shadow-xl shadow-slate-900/50 max-w-md">
        <DialogHeader className="space-y-4">
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-lg ${config.bgColor} border ${config.borderColor} flex-shrink-0`}>
              <Icon className={`w-6 h-6 ${config.color}`} />
            </div>
            <div className="flex-1">
              <DialogTitle className="text-lg font-bold text-white">
                {title}
              </DialogTitle>
              <DialogDescription className="text-slate-300 mt-2 text-sm">
                {description}
              </DialogDescription>
            </div>
          </div>

          {details && (
            <div className={`p-4 rounded-lg ${config.accentBg} border ${config.borderColor} text-sm text-slate-200`}>
              {details}
            </div>
          )}
        </DialogHeader>

        <DialogFooter className="border-t border-slate-700 pt-4">
          <Button
            onClick={onClose}
            className="w-full bg-cyan-500 hover:bg-cyan-600 text-white border-0 transition-all"
          >
            {closeText}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

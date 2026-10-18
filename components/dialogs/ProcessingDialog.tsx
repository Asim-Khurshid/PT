"use client"

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Loader2 } from "lucide-react"

interface ProcessingDialogProps {
  open: boolean
  title: string
  description: string
  progress?: number
}

export function ProcessingDialog({
  open,
  title,
  description,
  progress,
}: ProcessingDialogProps) {
  return (
    <Dialog open={open}>
      <DialogContent className="border border-slate-700 bg-slate-900/95 backdrop-blur-sm shadow-xl shadow-slate-900/50 max-w-sm pointer-events-none">
        <DialogHeader className="space-y-4">
          <div className="flex flex-col items-center gap-4 py-6">
            <div className="relative">
              <div className="absolute inset-0 bg-cyan-500/20 rounded-full blur-xl animate-pulse" />
              <Loader2 className="w-12 h-12 text-cyan-400 animate-spin relative" />
            </div>
            
            <div className="text-center space-y-2">
              <DialogTitle className="text-lg font-bold text-white">
                {title}
              </DialogTitle>
              <DialogDescription className="text-slate-300 text-sm">
                {description}
              </DialogDescription>
            </div>

            {progress !== undefined && (
              <div className="w-full mt-4 space-y-2">
                <div className="w-full bg-slate-800 rounded-full h-2 border border-slate-700 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-400 to-cyan-600 transition-all duration-300"
                    style={{ width: `${Math.min(100, progress)}%` }}
                  />
                </div>
                <p className="text-center text-xs text-slate-400">{Math.round(progress)}%</p>
              </div>
            )}
          </div>
        </DialogHeader>
      </DialogContent>
    </Dialog>
  )
}

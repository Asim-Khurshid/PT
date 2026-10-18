"use client"

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { AlertTriangle, CheckCircle, Info, XCircle } from "lucide-react"

interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  onConfirm: () => void | Promise<void>
  onCancel?: () => void
  confirmText?: string
  cancelText?: string
  variant?: "default" | "destructive" | "success" | "warning" | "info"
  isLoading?: boolean
}

const variantConfig = {
  default: {
    icon: Info,
    color: "text-cyan-400",
    bgColor: "bg-cyan-500/10",
    borderColor: "border-cyan-500/30",
    buttonColor: "bg-cyan-500 hover:bg-cyan-600",
  },
  destructive: {
    icon: AlertTriangle,
    color: "text-red-400",
    bgColor: "bg-red-500/10",
    borderColor: "border-red-500/30",
    buttonColor: "bg-red-500 hover:bg-red-600",
  },
  success: {
    icon: CheckCircle,
    color: "text-green-400",
    bgColor: "bg-green-500/10",
    borderColor: "border-green-500/30",
    buttonColor: "bg-green-500 hover:bg-green-600",
  },
  warning: {
    icon: AlertTriangle,
    color: "text-yellow-400",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/30",
    buttonColor: "bg-yellow-500 hover:bg-yellow-600",
  },
  info: {
    icon: Info,
    color: "text-blue-400",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/30",
    buttonColor: "bg-blue-500 hover:bg-blue-600",
  },
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  onConfirm,
  onCancel,
  confirmText = "Confirm",
  cancelText = "Cancel",
  variant = "default",
  isLoading = false,
}: ConfirmDialogProps) {
  const config = variantConfig[variant]
  const Icon = config.icon

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="border border-slate-700 bg-slate-900/95 backdrop-blur-sm shadow-xl shadow-slate-900/50">
        <div className={`absolute -left-1 top-0 h-20 w-1 ${config.bgColor} rounded-r`} />
        
        <AlertDialogHeader className="space-y-4">
          <div className="flex items-start gap-4">
            <div className={`p-2 rounded-lg ${config.bgColor} border ${config.borderColor}`}>
              <Icon className={`w-5 h-5 ${config.color}`} />
            </div>
            <div className="flex-1">
              <AlertDialogTitle className="text-lg font-bold text-white">
                {title}
              </AlertDialogTitle>
              <AlertDialogDescription className="text-slate-300 mt-2">
                {description}
              </AlertDialogDescription>
            </div>
          </div>
        </AlertDialogHeader>

        <AlertDialogFooter className="gap-3 pt-4 border-t border-slate-700">
          <AlertDialogCancel 
            onClick={onCancel}
            disabled={isLoading}
            className="border border-slate-600 text-slate-300 hover:bg-slate-800 hover:text-slate-100 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {cancelText}
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={isLoading}
            className={`${config.buttonColor} text-white border-0 disabled:opacity-50 disabled:cursor-not-allowed transition-all`}
          >
            {isLoading ? (
              <>
                <span className="inline-block animate-spin mr-2">⟳</span>
                Loading...
              </>
            ) : (
              confirmText
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

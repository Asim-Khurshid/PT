"use client"

import { useState, useEffect } from "react"
import { useParams, useRouter } from "next/navigation"
import { Download, Share2, ChevronDown, ChevronUp, Copy, Check, Microscope, Zap, Bug, Brain, Sparkles, RefreshCw, AlertTriangle, Shield, Code2, ListChecks, Target, Cpu, Gauge, Map, Crosshair, Globe, TrendingUp, Building2, ShieldCheck } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend, Label } from "recharts"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { scansAPI } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import { ConfirmDialog } from "@/components/dialogs/ConfirmDialog"
import { ProcessingDialog } from "@/components/dialogs/ProcessingDialog"
import { InfoDialog } from "@/components/dialogs/InfoDialog"

type MemSegment = { label: string; value: number }

const MEM_COLORS: Record<string, string> = {
  Used: "#38bdf8",
  "Buffer/Cache": "#22c55e",
  Shared: "#fbbf24",
  Other: "#f472b6",
  Free: "#cbd5e1",
  Available: "#f97316",
  Total: "#60a5fa",
}

const parseMeminfoSegments = (meminfo?: any): { segments: MemSegment[]; total: number } => {
  const raw = meminfo?.raw as string | undefined
  const summary = meminfo?.summary as string | undefined

  const metrics: Record<string, number> = {}

  const capture = (label: string, val: number | undefined) => {
    if (val === undefined || Number.isNaN(val)) return
    if (val <= 0 && metrics[label] && metrics[label] > 0) return
    if (metrics[label] !== undefined) return
    if (val <= 0) return
    metrics[label] = val
  }

  const parseLineValue = (line: string, key: string) => {
    if (line.toLowerCase().includes(key.toLowerCase())) {
      const nums = line.match(/\d+/g)
      if (nums && nums.length > 0) {
        const v = parseInt(nums[0], 10)
        if (!Number.isNaN(v)) return v
      }
    }
    return undefined
  }

  if (raw) {
    const lines = raw.split(/\r?\n/)
    lines.forEach((line) => {
      // Heuristic: detect compact tokenized line like "46674 38732 504 0 46674 28941 19561 5721"
      const tokens = (line.match(/\d+/g) || []).map((n) => parseInt(n, 10)).filter((n) => !Number.isNaN(n))
      if (tokens.length >= 6) {
        const maybeTotal = tokens[0]
        const maybeUsed = tokens[1]
        const maybeFree = tokens[2]
        const maybeShared = tokens[3]
        let idx = 4
        let maybeBuffCache = tokens[idx]
        if (tokens.length >= 5 && maybeBuffCache === maybeTotal && tokens.length >= 6) {
          // Sometimes total is repeated; shift buff/cache forward
          idx += 1
          maybeBuffCache = tokens[idx]
        }
        const maybeAvailable = tokens[idx + 1] ?? tokens[idx]
        const maybeOther = tokens[idx + 2]

        capture("Total", maybeTotal)
        capture("Used", maybeUsed)
        capture("Free", maybeFree)
        capture("Shared", maybeShared)
        capture("Buffer/Cache", maybeBuffCache)
        capture("Available", maybeAvailable)
        capture("Other", maybeOther)
      }

      capture("Total", parseLineValue(line, "total"))
      capture("Used", parseLineValue(line, "used"))
      capture("Free", parseLineValue(line, "free"))
      capture("Shared", parseLineValue(line, "shared"))
      capture("Buffer/Cache", parseLineValue(line, "buffer") ?? parseLineValue(line, "cache"))
      capture("Available", parseLineValue(line, "available"))
      capture("Other", parseLineValue(line, "other"))
    })
  }

  if (Object.keys(metrics).length === 0 && summary) {
    const nums = summary.match(/\d+/g)
    if (nums && nums.length > 0) {
      capture("Total", parseInt(nums[0], 10))
    }
  }

  const total = metrics["Total"] || 0

  // Derive used if absent but total/free/available present
  if (!metrics["Used"] && total) {
    const free = metrics["Free"] || 0
    const available = metrics["Available"] || 0
    if (free) capture("Used", total - free)
    else if (available) capture("Used", total - available)
  }

  const order = ["Used", "Buffer/Cache", "Shared", "Other", "Available", "Free"]
  const segments: MemSegment[] = order
    .filter((k) => metrics[k] !== undefined)
    .map((k) => ({ label: k, value: metrics[k] }))
    .filter((s) => s.value > 0)

  // If nothing meaningful, return empty
  if (!total || segments.length === 0) {
    return { segments: [], total: 0 }
  }

  return { segments, total }
}

export default function ReportPage() {
  const params = useParams()
  const router = useRouter()
  const { toast } = useToast()
  const [scan, setScan] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [downloadingPDF, setDownloadingPDF] = useState(false)
  const [expandedSections, setExpandedSections] = useState<string[]>(["overview"])
  const [copiedHash, setCopiedHash] = useState<string | null>(null)
  const [viewingFile, setViewingFile] = useState<{path: string, content: string, type: string} | null>(null)
  const [loadingFile, setLoadingFile] = useState(false)
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState<string>("all")
  const [vulnCategoryFilter, setVulnCategoryFilter] = useState<string>("all")
  const [isRescanning, setIsRescanning] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [aiReport, setAiReport]     = useState<any>(null)
  const [aiLoading, setAiLoading]   = useState(false)
  const [aiError, setAiError]       = useState<string | null>(null)
  const [aiStep, setAiStep]         = useState(0)
  const [selectedSurface, setSelectedSurface] = useState<number | null>(null)
  const [showRescanConfirm, setShowRescanConfirm] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [showProcessing, setShowProcessing] = useState(false)
  const [processingTitle, setProcessingTitle] = useState("Processing...")
  const [processingMessage, setProcessingMessage] = useState("")
  const [showSuccessDialog, setShowSuccessDialog] = useState(false)
  const [successMessage, setSuccessMessage] = useState("")
  const [activeTab, setActiveTab] = useState("static")
  const mediaBase = (process.env.NEXT_PUBLIC_MEDIA_URL || process.env.NEXT_PUBLIC_API_URL?.replace(/\/api$/, "") || "").replace(/\/$/, "")

  const toMediaUrl = (path?: string) => {
    if (!path) return ""
    if (path.startsWith("http")) return path
    const normalized = path.replace(/\\/g, "/")
    const mediaIdx = normalized.toLowerCase().indexOf("/media/")
    const relative = mediaIdx >= 0 ? normalized.slice(mediaIdx) : normalized
    if (!mediaBase) return relative
    const needsSlash = relative.startsWith("/") ? "" : "/"
    return `${mediaBase}${needsSlash}${relative}`
  }

  // Initialize tab from URL hash for deep links (#static or #dynamic)
  useEffect(() => {
    if (typeof window === 'undefined') return
    const hash = window.location.hash?.toLowerCase()
    if (['#dynamic', '#static', '#fuzzing', '#ai'].includes(hash)) {
      setActiveTab(hash.slice(1))
    }
  }, [])

  useEffect(() => {
    const scanId = params.id as string
    if (scanId) {
      scansAPI.get(scanId)
        .then(res => {
          setScan(res.data)
          try {
            if (typeof window !== 'undefined' && !window.location.hash) {
              const da = res.data?.dynamic_analysis
              const indicatorsCount = ((da?.indicators?.urls?.length || 0) + (da?.indicators?.ips?.length || 0) + (da?.indicators?.keywords?.length || 0))
              const hasDynamic = !!(da && (da.success || indicatorsCount > 0))
              setActiveTab(hasDynamic ? 'dynamic' : 'static')
            }
          } catch {}
          // Auto-run AI analysis if not already available
          if (!res.data?.ai_report) {
            setAiLoading(true)
            setAiError(null)
            scansAPI.aiAnalysis(res.data.id, false)
              .then(aiRes => setAiReport(aiRes.data.report))
              .catch(err => {
                const raw = err?.response?.data?.error || 'Analysis failed'
                const clean = raw
                  .replace(/GEMINI_API_KEY|AI_API_KEY/gi, 'ANALYSIS_ENGINE')
                  .replace(/gemini/gi, 'engine')
                  .replace(/google/gi, 'service')
                setAiError(clean)
              })
              .finally(() => setAiLoading(false))
          }
          setLoading(false)
        })
        .catch(err => {
          console.error('Failed to fetch scan:', err)
          toast({ title: "Error", description: "Failed to load scan data", variant: "destructive" })
          setLoading(false)
        })
    }
  }, [params.id])

  // Keep URL hash in sync with active tab
  useEffect(() => {
    if (typeof window === 'undefined') return
    const targetHash = `#${activeTab}`
    if (window.location.hash !== targetHash) {
      window.history.replaceState(null, '', targetHash)
    }
  }, [activeTab])

  // Cycle AI loading step indicator
  useEffect(() => {
    if (!aiLoading) { setAiStep(0); return }
    const timer = setInterval(() => setAiStep(s => s + 1), 2200)
    return () => clearInterval(timer)
  }, [aiLoading])

  const networkServers = (scan?.dynamic_analysis?.network_capture?.servers ||
    scan?.dynamic_analysis?.network_capture?.analysis?.servers ||
    scan?.dynamic_analysis?.server_endpoints || []) as any[]

  const meminfoParsed = parseMeminfoSegments(scan?.dynamic_analysis?.meminfo)

  const renderMemBars = (prefix: string) => {
    if (!meminfoParsed.segments.length || !meminfoParsed.total) return null
    const maxValue = Math.max(...meminfoParsed.segments.map((s) => s.value), 1)
    return (
      <div className="space-y-2">
        <p className="text-slate-500 text-[11px]">Total: {meminfoParsed.total} KB · Bars scaled to largest segment</p>
        {meminfoParsed.segments.map((seg) => {
          const color = MEM_COLORS[seg.label] || "#38bdf8"
          const pctTotal = Math.min(100, Math.max(0, (seg.value / meminfoParsed.total) * 100))
          const pctOfMax = Math.min(100, Math.max(3, (seg.value / maxValue) * 100))
          const remaining = Math.max(0, 100 - pctOfMax)
          return (
            <div key={`${prefix}-${seg.label}`} className="space-y-1">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-slate-300">{seg.label}</span>
                <span className="text-slate-400 font-mono">{seg.value} KB ({pctTotal.toFixed(1)}%)</span>
              </div>
              <div className="w-full h-3 rounded bg-slate-900 border border-slate-800 overflow-hidden">
                <div className="flex h-full">
                  <div style={{ width: `${pctOfMax}%`, backgroundColor: color }} className="h-full" />
                  <div style={{ width: `${remaining}%` }} className="h-full bg-slate-700/50" />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  const downloadPDF = async () => {
    if (!scan || scan.status !== 'completed') {
      toast({
        title: "Cannot download PDF",
        description: "Scan is still in progress or failed",
        variant: "destructive"
      })
      return
    }

    setDownloadingPDF(true)
    try {
      const response = await scansAPI.downloadPDF(scan.id)
      
      // Create blob from response
      const blob = new Blob([response.data], { type: 'application/pdf' })
      const url = window.URL.createObjectURL(blob)
      
      // Create temporary link and trigger download
      const link = document.createElement('a')
      link.href = url
      link.download = `${scan.app_name}_security_report.pdf`
      document.body.appendChild(link)
      link.click()
      
      // Cleanup
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast({
        title: "Success",
        description: "PDF report downloaded successfully"
      })
    } catch (error: any) {
      console.error('PDF download error:', error)
      toast({
        title: "Download Failed",
        description: error.response?.data?.error || "Failed to download PDF report",
        variant: "destructive"
      })
    } finally {
      setDownloadingPDF(false)
    }
  }

  const handleRescan = async () => {
    if (!scan) return
    setShowRescanConfirm(true)
  }

  const performRescan = async () => {
    setShowRescanConfirm(false)
    setShowProcessing(true)
    setProcessingTitle("Rescanning APK")
    setProcessingMessage("Starting fresh security analysis...")
    setIsRescanning(true)

    try {
      await scansAPI.rescan(scan.id)
      setProcessingMessage("Analysis in progress, please wait...")
      setShowProcessing(false)
      
      setSuccessMessage(`Rescan started for ${scan.app_name}. Analysis results will update as they complete.`)
      setShowSuccessDialog(true)
      
      // Refresh scan data
      setTimeout(async () => {
        const updated = await scansAPI.get(scan.id)
        setScan(updated.data)
      }, 1500)
    } catch (error: any) {
      console.error('Rescan error:', error)
      setShowProcessing(false)
      toast({
        title: "Rescan Failed",
        description: error.response?.data?.error || "Failed to start rescan",
        variant: "destructive"
      })
    } finally {
      setIsRescanning(false)
    }
  }

  const handleDelete = async () => {
    if (!scan) return
    setShowDeleteConfirm(true)
  }

  const performDelete = async () => {
    setShowDeleteConfirm(false)
    setShowProcessing(true)
    setProcessingTitle("Deleting Scan")
    setProcessingMessage("Removing scan and APK file from server...")
    setIsDeleting(true)

    try {
      await scansAPI.deleteScan(scan.id)
      setProcessingMessage("Redirecting to dashboard...")
      
      setTimeout(() => {
        setShowProcessing(false)
        router.push('/dashboard/reports')
      }, 1000)
    } catch (error: any) {
      console.error('Delete error:', error)
      setShowProcessing(false)
      toast({
        title: "Delete Failed",
        description: error.response?.data?.error || "Failed to delete scan",
        variant: "destructive"
      })
    } finally {
      setIsDeleting(false)
    }
  }

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => (prev.includes(section) ? prev.filter((s) => s !== section) : [...prev, section]))
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(id)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const viewFile = async (filePath: string) => {
    setLoadingFile(true)
    try {
      const response = await scansAPI.viewFile(scan.id, filePath)
      setViewingFile({
        path: filePath,
        content: response.data.content,
        type: response.data.type
      })
    } catch (error: any) {
      console.error('File view error:', error)
      const errorMessage = error.response?.data?.error || 'Failed to load file'
      toast({
        title: "Cannot View File",
        description: errorMessage,
        variant: "destructive"
      })
    } finally {
      setLoadingFile(false)
    }
  }

  const riskData = [
    { name: "Critical", value: scan?.critical_issues || 0, color: "#dc2626" },  // Red-600
    { name: "High", value: scan?.high_issues || 0, color: "#ea580c" },       // Orange-600
    { name: "Medium", value: scan?.medium_issues || 0, color: "#ca8a04" },   // Yellow-600
    { name: "Low", value: scan?.low_issues || 0, color: "#16a34a" },         // Green-600
  ].filter(item => item.value > 0)  // Only show non-zero values

  if (loading) {
    return (
      <div className="max-w-5xl">
        <div className="glassmorphism p-8 rounded-lg cyber-border text-center">
          <p className="text-slate-400">Loading scan data...</p>
        </div>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="max-w-5xl">
        <div className="glassmorphism p-8 rounded-lg cyber-border text-center">
          <p className="text-red-400">Scan not found</p>
        </div>
      </div>
    )
  }

  const vulnerabilityList = scan.vulnerabilities || []
  const vulnerabilityCategories = Array.from(new Set(
    vulnerabilityList.map((v: any) => v.category).filter((c: string) => c && c.trim().length > 0)
  )).sort()

  const severityCounts = vulnerabilityList.reduce((acc: Record<string, number>, vuln: any) => {
    const sev = (vuln.severity || 'info').toLowerCase()
    acc[sev] = (acc[sev] || 0) + 1
    return acc
  }, {})

  const filteredVulnerabilities = vulnerabilityList.filter((vuln: any) => {
    const severityMatch = vulnSeverityFilter === 'all' || vuln.severity === vulnSeverityFilter
    const categoryMatch = vulnCategoryFilter === 'all' || vuln.category === vulnCategoryFilter
    return severityMatch && categoryMatch
  })

  const staticInfo = scan.static_analysis || {}
  const appInfo = staticInfo.app_info || {}
  const manifest = staticInfo.manifest || {}
  const certificate = staticInfo.certificate || {}
  const staticComponents = staticInfo.components || {}

  const flattenDictList = (value: any): any[] => {
    if (!value) return []
    if (Array.isArray(value)) return value
    if (typeof value === 'object') {
      return Object.values(value).flatMap((v: any) => Array.isArray(v) ? v : [v])
    }
    return []
  }

  const apiKeyEntries = flattenDictList(staticInfo.api_keys)
  const cryptoKeyEntries = flattenDictList(staticInfo.crypto_keys)
  const firebaseEntries = flattenDictList(staticInfo.firebase)
  const awsEntries = flattenDictList(staticInfo.aws)
  const codeSecretEntries = flattenDictList(staticInfo.code_secrets)

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400'
      case 'high': return 'text-orange-400'
      case 'medium': return 'text-yellow-400'
      case 'low': return 'text-lime-400'
      default: return 'text-green-400'
    }
  }

  const getThreatBg = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-red-500/20 text-red-400'
      case 'high': return 'bg-orange-500/20 text-orange-400'
      case 'medium': return 'bg-yellow-500/20 text-yellow-400'
      case 'low': return 'bg-lime-500/20 text-lime-400'
      default: return 'bg-green-500/20 text-green-400'
    }
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffHours / 24)
    
    if (diffHours < 1) return 'just now'
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`
    return date.toLocaleDateString()
  }

  return (
    <div className="max-w-5xl">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">APK Security Report</h1>
        <p className="text-slate-400 mt-2">{scan.app_name} • Analyzed {formatDate(scan.created_at)}</p>
      </div>

      {/* Risk Score */}
      <div className="glassmorphism p-8 rounded-lg cyber-border mb-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm">Overall Risk Score</p>
            <div className="flex items-end gap-4 mt-2">
              <div className={`text-6xl font-bold ${getThreatColor(scan.threat_level)}`}>{scan.threat_score || 0}</div>
              <div className="mb-2">
                <span className={`${getThreatBg(scan.threat_level)} px-3 py-1 rounded-full text-sm font-semibold capitalize`}>
                  {scan.threat_level}
                </span>
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <Button 
              onClick={downloadPDF}
              disabled={downloadingPDF || scan.status !== 'completed'}
              className="flex items-center gap-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Download className="w-4 h-4" />
              {downloadingPDF ? 'Generating...' : 'Download PDF'}
            </Button>
            <Button 
              onClick={handleRescan}
              disabled={isRescanning}
              className="flex items-center gap-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isRescanning ? '⟳ Rescanning...' : '⟳ Rescan'}
            </Button>
            <Button 
              onClick={handleDelete}
              disabled={isDeleting}
              className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isDeleting ? '⊘ Deleting...' : '⊘ Delete'}
            </Button>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Vulnerabilities", value: scan.total_issues || 0 },
          { label: "Permissions", value: scan.permissions?.length || 0 },
          { label: "Critical", value: scan.critical_issues || 0 },
          { label: "File Size", value: `${(scan.file_size / 1024 / 1024).toFixed(2)} MB` },
        ].map((stat, idx) => (
          <div key={idx} className="glassmorphism p-4 rounded-lg cyber-border text-center">
            <p className="text-slate-400 text-xs">{stat.label}</p>
            <p className="text-2xl font-bold text-cyan-400 mt-1">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Sections with Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <div className="glassmorphism rounded-lg cyber-border overflow-hidden mb-6">
          <div className="px-6 pt-4">
            <TabsList className="w-full bg-slate-800/50 border border-slate-700/50 rounded-lg p-1">
              <TabsTrigger 
                value="static"
                className="flex-1 gap-2 data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 data-[state=active]:border-cyan-500/50"
              >
                <Microscope className="w-4 h-4" />
                Static Analysis
                <span className="ml-2 inline-flex items-center rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 text-xs">
                  {(scan?.total_issues ?? 0)}
                </span>
              </TabsTrigger>
              <TabsTrigger 
                value="dynamic"
                className="flex-1 gap-2 data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400 data-[state=active]:border-purple-500/50"
              >
                <Zap className="w-4 h-4" />
                Dynamic Analysis
                <span className="ml-2 inline-flex items-center rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 text-xs">
                  {((scan?.dynamic_analysis?.indicators?.urls?.length ?? 0) + (scan?.dynamic_analysis?.indicators?.ips?.length ?? 0) + (scan?.dynamic_analysis?.indicators?.keywords?.length ?? 0))}
                </span>
              </TabsTrigger>
              <TabsTrigger 
                value="fuzzing"
                className="flex-1 gap-2 data-[state=active]:bg-orange-500/20 data-[state=active]:text-orange-400 data-[state=active]:border-orange-500/50"
              >
                <Bug className="w-4 h-4" />
                Component Fuzzing
                <span className="ml-2 inline-flex items-center rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/30 px-2 py-0.5 text-xs">
                  {scan?.fuzzing_analysis?.vulnerabilities_found ?? (scan?.fuzzing_enabled ? '...' : '—')}
                </span>
              </TabsTrigger>
              <TabsTrigger 
                value="ai"
                className="flex-1 gap-2 data-[state=active]:bg-violet-500/20 data-[state=active]:text-violet-400 data-[state=active]:border-violet-500/50"
              >
                <Brain className="w-4 h-4" />
                AI Analysis
                {(aiReport || scan?.ai_report) && (
                  <span className="ml-2 inline-flex items-center rounded-full bg-violet-500/20 text-violet-300 border border-violet-500/30 px-2 py-0.5 text-xs">
                    ✓
                  </span>
                )}
              </TabsTrigger>
            </TabsList>
          </div>
        </div>

        {/* Static Analysis Tab */}
        <TabsContent value="static" className="space-y-4 mt-4">
          {/* Overview */}
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("overview")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Overview</h3>
              {expandedSections.includes("overview") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("overview") && (
              <div className="p-6 border-t border-slate-700 space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Bar Chart */}
                <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                  <h4 className="text-white font-semibold mb-4 text-center">Vulnerability Distribution</h4>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={riskData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis 
                        dataKey="name" 
                        stroke="#94a3b8"
                        style={{ fontSize: '12px' }}
                      />
                      <YAxis 
                        stroke="#94a3b8"
                        style={{ fontSize: '12px' }}
                        label={{ value: 'Count', angle: -90, position: 'insideLeft', fill: '#94a3b8' }}
                      />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                        labelStyle={{ color: "#f1f5f9" }}
                        cursor={{ fill: 'rgba(100, 116, 139, 0.1)' }}
                      />
                      <Legend 
                        wrapperStyle={{ paddingTop: '20px' }}
                        iconType="circle"
                      />
                      <Bar dataKey="value" name="Vulnerabilities" radius={[8, 8, 0, 0]}>
                        {riskData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Pie Chart */}
                <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                  <h4 className="text-white font-semibold mb-4 text-center">Severity Breakdown</h4>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie 
                        data={riskData} 
                        cx="50%" 
                        cy="50%" 
                        labelLine={true}
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80} 
                        paddingAngle={3} 
                        dataKey="value"
                      >
                        {riskData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: "8px" }}
                        itemStyle={{ color: "#f1f5f9" }}
                      />
                      <Legend 
                        verticalAlign="bottom" 
                        height={36}
                        iconType="circle"
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}
          </div>

        {/* Application Info */}
        <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
          <button
            onClick={() => toggleSection("app_info")}
            className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
          >
            <h3 className="text-white font-semibold">Application Information</h3>
            {expandedSections.includes("app_info") ? (
              <ChevronUp className="w-5 h-5 text-cyan-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </button>

          {expandedSections.includes("app_info") && (
            <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
              <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                <h4 className="text-white font-semibold">App Metadata</h4>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Package</span>
                  <span className="text-slate-300 font-mono">{appInfo.package_name || manifest.package || scan.package_name}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Version</span>
                  <span className="text-slate-300">{appInfo.version || scan.version || "N/A"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">File Size</span>
                  <span className="text-slate-300">{(scan.file_size / 1024 / 1024).toFixed(2)} MB</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Min SDK</span>
                  <span className="text-slate-300">{manifest.min_sdk || "N/A"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Target SDK</span>
                  <span className="text-slate-300">{manifest.target_sdk || "N/A"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Debuggable</span>
                  <span className="text-slate-300">{manifest.debuggable ? "Yes" : "No"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Backup Allowed</span>
                  <span className="text-slate-300">{manifest.allow_backup ? "Yes" : "No"}</span>
                </div>
              </div>

              <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                <h4 className="text-white font-semibold">Hashes</h4>
                <div>
                  <p className="text-slate-400 text-xs">MD5</p>
                  <p className="text-slate-300 font-mono break-all">{appInfo.hash_md5 || scan.hash_md5 || "N/A"}</p>
                </div>
                <div>
                  <p className="text-slate-400 text-xs">SHA256</p>
                  <p className="text-slate-300 font-mono break-all">{appInfo.hash_sha256 || scan.hash_sha256 || "N/A"}</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Certificate */}
        {certificate && Object.keys(certificate).length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("certificate")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Certificate</h3>
              {expandedSections.includes("certificate") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("certificate") && (
              <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Issuer</span>
                    <span className="text-slate-300">{certificate.issuer || "N/A"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Algorithm</span>
                    <span className="text-slate-300">{certificate.algorithm || "N/A"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Valid From</span>
                    <span className="text-slate-300">{certificate.valid_from || "N/A"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Valid Until</span>
                    <span className="text-slate-300">{certificate.valid_until || "N/A"}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Signature Version</span>
                    <span className="text-slate-300">{certificate.signature_version || "N/A"}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Components */}
        {staticComponents && (staticComponents.activities?.length || staticComponents.services?.length || staticComponents.receivers?.length || staticComponents.providers?.length) > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("components")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Components</h3>
              {expandedSections.includes("components") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("components") && (
              <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                {(
                  [
                    { label: "Activities", items: staticComponents.activities || [] },
                    { label: "Services", items: staticComponents.services || [] },
                    { label: "Receivers", items: staticComponents.receivers || [] },
                    { label: "Providers", items: staticComponents.providers || [] },
                  ]
                ).map((section, idx) => (
                  <div key={idx} className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2">{section.label} ({section.items.length})</h4>
                    <div className="space-y-1 max-h-56 overflow-auto text-xs font-mono text-slate-300">
                      {section.items.slice(0, 50).map((item: any, i: number) => {
                        const name = typeof item === 'string' ? item : (item?.name ?? JSON.stringify(item))
                        const isExported = typeof item === 'object' && item?.exported === true
                        const hasPerm = typeof item === 'object' && !!item?.permission
                        return (
                          <div key={i} className="flex items-center gap-2 flex-wrap">
                            <span className="whitespace-pre-wrap break-all">{name}</span>
                            {isExported && <span className="px-1 rounded bg-orange-500/20 text-orange-400 text-[10px] font-semibold shrink-0">exported</span>}
                            {hasPerm && <span className="px-1 rounded bg-green-500/20 text-green-400 text-[10px] font-semibold shrink-0" title={item.permission}>🔒 protected</span>}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Vulnerabilities */}
        <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
          <button
            onClick={() => toggleSection("vulnerabilities")}
            className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
          >
            <h3 className="text-white font-semibold">Vulnerabilities Found</h3>
            {expandedSections.includes("vulnerabilities") ? (
              <ChevronUp className="w-5 h-5 text-cyan-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </button>

          {expandedSections.includes("vulnerabilities") && (
            <div className="p-6 border-t border-slate-700 space-y-3">
              {vulnerabilityList.length > 0 ? (
                <>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex flex-wrap gap-2">
                      {["all", "critical", "high", "medium", "low", "info"].map((sev) => (
                        <button
                          key={sev}
                          onClick={() => setVulnSeverityFilter(sev)}
                          className={`px-3 py-1 rounded-full text-xs font-semibold capitalize border transition cursor-pointer ${
                            vulnSeverityFilter === sev
                              ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                              : "bg-slate-800/40 text-slate-400 border-slate-700"
                          }`}
                        >
                          {sev} {sev !== "all" && severityCounts[sev] ? `(${severityCounts[sev]})` : ""}
                        </button>
                      ))}
                    </div>
                    <div className="ml-auto flex items-center gap-2">
                      <span className="text-slate-400 text-xs">Category</span>
                      <select
                        value={vulnCategoryFilter}
                        onChange={(e) => setVulnCategoryFilter(e.target.value)}
                        className="bg-slate-900/60 text-slate-300 text-xs border border-slate-700 rounded px-2 py-1"
                      >
                        <option value="all">All</option>
                        {vulnerabilityCategories.map((cat) => (
                          <option key={cat} value={cat}>{cat}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {filteredVulnerabilities.length > 0 ? (
                    filteredVulnerabilities.map((vuln: any, idx: number) => {
                  return (
                    <div key={idx} className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-1 rounded text-xs font-semibold capitalize ${
                              vuln.severity === "critical"
                                ? "bg-red-500/20 text-red-400 border border-red-500/30"
                                : vuln.severity === "high"
                                  ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                                  : vuln.severity === "medium"
                                    ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                                    : vuln.severity === "low"
                                      ? "bg-lime-500/20 text-lime-400 border border-lime-500/30"
                                      : "bg-slate-500/20 text-slate-400 border border-slate-500/30"
                            }`}
                          >
                            {vuln.severity}
                          </span>
                          {vuln.category && (
                            <span className="px-2 py-1 rounded text-xs bg-slate-700/50 text-slate-300 border border-slate-600">
                              {vuln.category}
                            </span>
                          )}
                        </div>
                      </div>
                      <h4 className="text-white font-semibold text-base mb-2">{vuln.title || vuln.type || 'Unknown Vulnerability'}</h4>
                      <p className="text-slate-300 text-sm leading-relaxed mb-3">{vuln.description}</p>
                      
                      <div className="flex flex-wrap items-center gap-3 text-xs">
                        {vuln.file_path && (
                          <div className="flex items-center gap-1 text-slate-400">
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            <span className="font-mono">{vuln.file_path}</span>
                          </div>
                        )}
                        {vuln.line_number && (
                          <div className="flex items-center gap-1 text-slate-400">
                            <span>Line:</span>
                            <span className="font-mono text-cyan-400">{vuln.line_number}</span>
                          </div>
                        )}
                      </div>
                      
                      {vuln.remediation && (
                        <div className="mt-3 pt-3 border-t border-slate-700">
                          <p className="text-xs text-slate-500 mb-1">Remediation:</p>
                          <p className="text-sm text-slate-300">{vuln.remediation}</p>
                        </div>
                      )}
                    </div>
                  );
                    })
                  ) : (
                    <div className="text-center py-6">
                      <p className="text-slate-400">No vulnerabilities match the selected filters</p>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-8">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-500/10 border border-green-500/30 mb-3">
                    <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-slate-400">No vulnerabilities detected</p>
                  <p className="text-slate-500 text-sm mt-1">This application appears to be secure</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Permissions */}
        <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
          <button
            onClick={() => toggleSection("permissions")}
            className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
          >
            <h3 className="text-white font-semibold">Permissions Requested</h3>
            {expandedSections.includes("permissions") ? (
              <ChevronUp className="w-5 h-5 text-cyan-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </button>

          {expandedSections.includes("permissions") && (
            <div className="p-6 border-t border-slate-700">
              {scan.permissions && scan.permissions.length > 0 ? (
                <div className="grid grid-cols-2 gap-3">
                  {scan.permissions.map((perm: any, idx: number) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between bg-slate-800/30 p-3 rounded-lg border border-slate-700"
                    >
                      <span className="text-slate-300">{perm.permission_name}</span>
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold ${
                          perm.is_dangerous
                            ? "bg-red-500/20 text-red-400"
                            : "bg-green-500/20 text-green-400"
                        }`}
                      >
                        {perm.is_dangerous ? 'Dangerous' : 'Safe'}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-400 text-center py-4">No permissions data available</p>
              )}
            </div>
          )}
        </div>
        </TabsContent>

        {/* Dynamic Analysis Tab */}
        <TabsContent value="dynamic" className="space-y-4 mt-4">
        {scan.dynamic_analysis ? (
          <div className="space-y-4">
            <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
              <button
                onClick={() => toggleSection("dynamic_overview")}
                className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
              >
                <h3 className="text-white font-semibold">Dynamic Execution Overview</h3>
                {expandedSections.includes("dynamic_overview") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
              </button>
              {expandedSections.includes("dynamic_overview") && (
                <div className="p-6 border-t border-slate-700 grid grid-cols-1 xl:grid-cols-3 gap-4 text-sm">
                  <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Status</span>
                      <span className={scan.dynamic_analysis.success ? "text-green-400" : "text-red-400"}>
                        {scan.dynamic_analysis.success ? "Completed" : "Failed"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Duration</span>
                      <span className="text-slate-300">{scan.dynamic_analysis.duration_seconds || 0}s</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Install</span>
                      <span className={scan.dynamic_analysis.install?.success ? "text-green-400" : "text-red-400"}>
                        {scan.dynamic_analysis.install?.success ? "OK" : "Failed"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Launch</span>
                      <span className={scan.dynamic_analysis.launch?.success ? "text-green-400" : "text-red-400"}>
                        {scan.dynamic_analysis.launch?.success ? "OK" : "Failed"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Monkey Events</span>
                      <span className="text-slate-300">{scan.dynamic_analysis.monkey?.events || 0}</span>
                    </div>
                    <div className="pt-2 border-t border-slate-700 space-y-1">
                      <p className="text-slate-400 text-xs">Device</p>
                      <p className="text-slate-300">{scan.dynamic_analysis.device?.model || "Unknown"} ({scan.dynamic_analysis.device?.serial || "N/A"})</p>
                      <p className="text-slate-500 text-xs">Android {scan.dynamic_analysis.device?.android_version || "N/A"} (SDK {scan.dynamic_analysis.device?.sdk || "N/A"})</p>
                    </div>
                  </div>

                  <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                    <h4 className="text-white font-semibold text-sm">Indicators</h4>
                    <div className="grid grid-cols-3 gap-3 text-center">
                      {[{label: "URLs", value: scan.dynamic_analysis.indicators?.urls?.length || 0}, {label: "IPs", value: scan.dynamic_analysis.indicators?.ips?.length || 0}, {label: "Keywords", value: scan.dynamic_analysis.indicators?.keywords?.length || 0}].map((item, idx) => (
                        <div key={idx} className="bg-slate-900/40 p-3 rounded">
                          <p className="text-slate-400 text-xs">{item.label}</p>
                          <p className="text-cyan-400 font-semibold">{item.value}</p>
                        </div>
                      ))}
                    </div>
                    {scan.dynamic_analysis.indicators?.keywords?.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {scan.dynamic_analysis.indicators.keywords.slice(0, 14).map((kw: string, idx: number) => (
                          <span key={idx} className="px-2 py-1 text-[11px] bg-slate-700/50 text-slate-200 rounded">{kw}</span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="bg-slate-800/30 p-4 rounded-lg border border-slate-700 space-y-2">
                    <h4 className="text-white font-semibold text-sm">Runtime Snapshot</h4>
                    <div className="space-y-1 text-xs text-slate-300">
                      <div className="flex items-center justify-between"><span className="text-slate-400">Emulator</span><span>{scan.dynamic_analysis.device_state?.is_emulator ? "Yes" : "No"}</span></div>
                      <div className="flex items-center justify-between"><span className="text-slate-400">Brand</span><span>{scan.dynamic_analysis.device_state?.props?.brand || "N/A"}</span></div>
                      <div className="flex items-center justify-between"><span className="text-slate-400">Manufacturer</span><span>{scan.dynamic_analysis.device_state?.props?.manufacturer || "N/A"}</span></div>
                      <div className="flex items-center justify-between"><span className="text-slate-400">Security Patch</span><span>{scan.dynamic_analysis.device_state?.props?.security_patch || "N/A"}</span></div>
                      <div className="flex items-center justify-between"><span className="text-slate-400">Debuggable</span><span>{scan.dynamic_analysis.device_state?.props?.debuggable || "N/A"}</span></div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {(scan.dynamic_analysis.package || scan.dynamic_analysis.components) && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_app")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Runtime Package & Components</h3>
                  {expandedSections.includes("dynamic_app") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_app") && (
                  <div className="p-6 border-t border-slate-700 space-y-4 text-sm">
                    {scan.dynamic_analysis.package && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {[{label: "Version", value: scan.dynamic_analysis.package?.version_name}, {label: "Version Code", value: scan.dynamic_analysis.package?.version_code}, {label: "Min SDK", value: scan.dynamic_analysis.package?.min_sdk}, {label: "Target SDK", value: scan.dynamic_analysis.package?.target_sdk}, {label: "Main Activity", value: scan.dynamic_analysis.main_activity}].map((row, idx) => (
                          <div key={idx} className="bg-slate-800/30 p-3 rounded border border-slate-700 flex items-center justify-between">
                            <span className="text-slate-400">{row.label}</span>
                            <span className="text-slate-200 font-mono text-xs break-all">{row.value || "N/A"}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {scan.dynamic_analysis.components && (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                        {[{label: "Activities", items: scan.dynamic_analysis.components.activities}, {label: "Services", items: scan.dynamic_analysis.components.services}, {label: "Receivers", items: scan.dynamic_analysis.components.receivers}, {label: "Providers", items: scan.dynamic_analysis.components.providers}].map((c, idx) => (
                          <div key={idx} className="bg-slate-900/40 p-3 rounded border border-slate-700">
                            <p className="text-slate-400 text-xs">{c.label}</p>
                            <p className="text-cyan-400 font-semibold">{c.items?.length || 0}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {(scan.dynamic_analysis.meminfo || scan.dynamic_analysis.netstats || scan.dynamic_analysis.network_capture) && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_runtime")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Runtime Diagnostics</h3>
                  {expandedSections.includes("dynamic_runtime") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_runtime") && (
                  <div className="p-6 border-t border-slate-700 space-y-4 text-sm">
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">Memory</p>
                        <p className="text-slate-300 font-mono text-xs">{scan.dynamic_analysis.meminfo?.summary || "N/A"}</p>
                        {renderMemBars("runtime")}
                        {meminfoParsed.segments.length === 0 && (
                          <p className="text-slate-500 text-[11px] mt-1">No detailed meminfo captured</p>
                        )}
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">Netstats</p>
                        <p className="text-slate-300 font-mono text-xs">{scan.dynamic_analysis.netstats?.summary || "N/A"}</p>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">Network Capture</p>
                        <p className="text-slate-300 text-xs">{scan.dynamic_analysis.network_capture?.enabled ? "Enabled" : "Disabled"}</p>
                        <p className="text-slate-500 text-[11px]">Packets: {scan.dynamic_analysis.network_capture?.packet_count || 0}</p>
                      </div>
                    </div>

                    {networkServers.length > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded border border-slate-700">
                        <div className="flex items-center justify-between mb-3">
                          <h4 className="text-white font-semibold">Network Capture (Server Fingerprints)</h4>
                          <span className="text-xs text-slate-400">{networkServers.length} endpoints</span>
                        </div>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-sm">
                          {networkServers.slice(0, 8).map((srv: any, idx: number) => (
                            <div key={idx} className="bg-slate-800/40 p-3 rounded border border-slate-700">
                              <div className="flex items-center justify-between">
                                <span className="text-cyan-400 font-mono text-sm">{srv.ip || "N/A"}</span>
                                <span className="px-2 py-1 text-xs rounded bg-slate-700/50 text-slate-200">{srv.os_guess || "unknown"}</span>
                              </div>
                              <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-300">
                                <div>
                                  <p className="text-slate-400 text-[11px]">Ports</p>
                                  <p className="font-mono break-all">{(srv.ports || []).slice(0, 6).join(", ") || "-"}</p>
                                </div>
                                <div>
                                  <p className="text-slate-400 text-[11px]">Protocols</p>
                                  <p className="font-mono break-all">{(srv.protocols || []).slice(0, 6).join(", ") || "-"}</p>
                                </div>
                              </div>
                              <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                                <span>TTL: {srv.ttl ?? "N/A"}</span>
                                <span>Packets: {srv.packet_count || 0}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(scan.dynamic_analysis.network_connections?.length || 0) > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded border border-slate-700">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-white font-semibold">Network Connections</h4>
                          <span className="text-xs text-slate-400">showing first 100</span>
                        </div>
                        <div className="max-h-56 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.network_connections.slice(0, 100).map((conn: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{conn}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {(scan.dynamic_analysis.logcat || scan.dynamic_analysis.indicators) && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_logs")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Logcat & Indicators</h3>
                  {expandedSections.includes("dynamic_logs") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_logs") && (
                  <div className="p-6 border-t border-slate-700 space-y-4 text-sm">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center text-xs">
                      {[{label: "Logcat Lines", value: scan.dynamic_analysis.logcat?.total_lines || 0}, {label: "Suspicious Lines", value: scan.dynamic_analysis.logcat?.suspicious_lines?.length || 0}, {label: "Matched (pkg)", value: scan.dynamic_analysis.logcat?.matched_lines || 0}, {label: "URLs Seen", value: scan.dynamic_analysis.indicators?.urls?.length || 0}].map((item, idx) => (
                        <div key={idx} className="bg-slate-900/40 p-3 rounded border border-slate-800">
                          <p className="text-slate-400 text-[11px]">{item.label}</p>
                          <p className="text-cyan-400 font-semibold text-sm">{item.value}</p>
                        </div>
                      ))}
                    </div>

                    {(scan.dynamic_analysis.indicators?.urls?.length || 0) > 0 && (
                      <div>
                        <h4 className="text-white font-semibold mb-2 text-sm">URLs Observed</h4>
                        <div className="max-h-40 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.indicators.urls.slice(0, 50).map((u: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{u}</div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(scan.dynamic_analysis.indicators?.ips?.length || 0) > 0 && (
                      <div>
                        <h4 className="text-white font-semibold mb-2 text-sm">IPs Observed</h4>
                        <div className="flex flex-wrap gap-2 text-xs font-mono text-slate-200">
                          {scan.dynamic_analysis.indicators.ips.slice(0, 30).map((ip: string, idx: number) => (
                            <span key={idx} className="px-2 py-1 rounded bg-slate-800/50 border border-slate-700">{ip}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {(scan.dynamic_analysis.logcat?.sample?.length || 0) > 0 && (
                      <div>
                        <h4 className="text-white font-semibold mb-2 text-sm">Logcat Sample</h4>
                        <div className="max-h-64 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.logcat.sample.slice(0, 80).map((line: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{line}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {!!(scan.dynamic_analysis.runtime_permissions?.length || scan.dynamic_analysis.running_processes?.length) && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_privs")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Runtime Permissions & Processes</h3>
                  {expandedSections.includes("dynamic_privs") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_privs") && (
                  <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                    {(scan.dynamic_analysis.runtime_permissions?.length || 0) > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded border border-slate-700">
                        <h4 className="text-white font-semibold mb-2">Runtime Permissions</h4>
                        <div className="max-h-56 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.runtime_permissions.slice(0, 120).map((perm: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{perm}</div>
                          ))}
                        </div>
                      </div>
                    )}

                    {(scan.dynamic_analysis.running_processes?.length || 0) > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded border border-slate-700">
                        <h4 className="text-white font-semibold mb-2">Running Processes</h4>
                        <div className="max-h-56 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.running_processes.slice(0, 120).map((proc: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{proc}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {(scan.dynamic_analysis.app_data?.listings?.length || scan.dynamic_analysis.meminfo) && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_storage")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">App Data & Storage</h3>
                  {expandedSections.includes("dynamic_storage") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_storage") && (
                  <div className="p-6 border-t border-slate-700 space-y-4 text-sm">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">App Data Accessible</p>
                        <p className="text-slate-200 text-sm">{scan.dynamic_analysis.app_data?.accessible ? "Yes" : "No"}</p>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">Listings</p>
                        <p className="text-slate-200 text-sm">{scan.dynamic_analysis.app_data?.listings?.length || 0}</p>
                      </div>
                      <div className="bg-slate-900/40 p-3 rounded">
                        <p className="text-slate-400 text-xs">Meminfo</p>
                        <p className="text-slate-200 text-sm font-mono">{scan.dynamic_analysis.meminfo?.summary || "N/A"}</p>
                      </div>
                    </div>

                    {meminfoParsed.segments.length > 0 && meminfoParsed.total > 0 && (
                      <div className="mt-3 space-y-2">
                        <p className="text-slate-400 text-xs">Memory Usage</p>
                        {renderMemBars("storage")}
                      </div>
                    )}

                    {(scan.dynamic_analysis.app_data?.listings?.length || 0) > 0 && (
                      <div className="bg-slate-900/40 p-4 rounded border border-slate-700">
                        <h4 className="text-white font-semibold mb-2">App Data Listing</h4>
                        <div className="max-h-56 overflow-auto text-xs font-mono text-slate-300 space-y-1">
                          {scan.dynamic_analysis.app_data.listings.slice(0, 120).map((line: string, idx: number) => (
                            <div key={idx} className="whitespace-pre-wrap">{line}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {(scan.dynamic_analysis.screenshots?.length || 0) > 0 && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_screens")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Captured Screenshots</h3>
                  {expandedSections.includes("dynamic_screens") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_screens") && (
                  <div className="p-6 border-t border-slate-700">
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                      {scan.dynamic_analysis.screenshots.slice(0, 6).map((shot: string, idx: number) => {
                        const src = toMediaUrl(shot)
                        return (
                          <div key={idx} className="space-y-2">
                            <div className="rounded-lg overflow-hidden border border-slate-700 bg-slate-800/50 aspect-[9/16] flex items-center justify-center">
                              {src ? (
                                <img src={src} alt={`screenshot-${idx}`} className="w-full h-full object-cover" loading="lazy" />
                              ) : (
                                <span className="text-slate-500 text-xs">Image unavailable</span>
                              )}
                            </div>
                            <p className="text-xs text-slate-400 break-all font-mono">{shot}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {(scan.dynamic_analysis.step_log?.length || 0) > 0 && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_steps")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Dynamic Analysis Steps</h3>
                  {expandedSections.includes("dynamic_steps") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_steps") && (
                  <div className="p-6 border-t border-slate-700 space-y-2 text-sm">
                    {scan.dynamic_analysis.step_log.map((step: any, idx: number) => (
                      <div key={idx} className="flex items-start justify-between gap-3 border-b border-slate-800/60 pb-2">
                        <div>
                          <p className="text-slate-300 font-medium">{step.step}</p>
                          {step.details && <p className="text-slate-500 text-xs">{step.details}</p>}
                        </div>
                        <div className="text-right">
                          <span className={`text-xs px-2 py-1 rounded ${step.status === 'success' ? 'bg-green-500/20 text-green-400' : step.status === 'failed' ? 'bg-red-500/20 text-red-400' : 'bg-slate-700/40 text-slate-300'}`}>
                            {step.status}
                          </span>
                          {step.timestamp && <p className="text-slate-500 text-xs mt-1">{step.timestamp}</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {scan.dynamic_analysis.errors?.length > 0 && (
              <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                <button onClick={() => toggleSection("dynamic_errors")}
                  className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer">
                  <h3 className="text-white font-semibold">Dynamic Errors</h3>
                  {expandedSections.includes("dynamic_errors") ? <ChevronUp className="w-5 h-5 text-cyan-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                </button>
                {expandedSections.includes("dynamic_errors") && (
                  <div className="p-6 border-t border-slate-700">
                    <ul className="text-red-200 text-sm list-disc list-inside space-y-1">
                      {scan.dynamic_analysis.errors.map((err: string, idx: number) => (
                        <li key={idx}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-slate-400 text-sm">Dynamic analysis was not run for this scan.</p>
        )}
        </TabsContent>

        {/* Return to Static Tab for remaining content */}
        <TabsContent value="static" className="space-y-4 mt-4">
        {/* APK Contents */}
        {scan.static_analysis?.important_files && scan.static_analysis.important_files.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("apk_contents")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">APK Contents ({scan.static_analysis.important_files.length} Important Files)</h3>
              {expandedSections.includes("apk_contents") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("apk_contents") && (
              <div className="p-6 border-t border-slate-700">
                <div className="space-y-2">
                  {scan.static_analysis.important_files.map((file: any, idx: number) => (
                    <div 
                      key={idx} 
                      className="flex items-center justify-between bg-slate-800/30 p-3 rounded-lg border border-slate-700 hover:border-cyan-500/50 transition group"
                    >
                      <div className="flex-1 min-w-0">
                        <button
                          onClick={() => viewFile(file.name)}
                          disabled={loadingFile || file.type.includes('Executable') || file.type.includes('Library') || file.type.includes('Image')}
                          className="text-left w-full cursor-pointer disabled:cursor-not-allowed"
                        >
                          <p className={`text-sm font-mono truncate ${
                            file.type.includes('Executable') || file.type.includes('Library') || file.type.includes('Image')
                              ? 'text-slate-500'
                              : 'text-cyan-400 group-hover:text-cyan-300'
                          }`}>
                            {file.name}
                          </p>
                          <div className="flex items-center gap-3 mt-1">
                            <span className="text-xs text-slate-400">{file.type}</span>
                            <span className="text-xs text-slate-500">{(file.size / 1024).toFixed(2)} KB</span>
                          </div>
                        </button>
                      </div>
                      {!file.type.includes('Executable') && !file.type.includes('Library') && !file.type.includes('Image') && (
                        <span className="text-xs text-slate-500 ml-2 opacity-0 group-hover:opacity-100 transition">
                          Click to view
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - URLs */}
        {scan.static_analysis?.urls && scan.static_analysis.urls.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("urls")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">URLs Found ({scan.static_analysis.urls.length})</h3>
              {expandedSections.includes("urls") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("urls") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {scan.static_analysis.urls.map((urlData: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 text-sm font-mono truncate flex-1">{urlData.url}</span>
                    <span className={`px-2 py-1 rounded text-xs font-semibold ml-2 ${urlData.is_secure ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                      {urlData.scheme.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Domains */}
        {scan.static_analysis?.domains && scan.static_analysis.domains.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("domains")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Domains ({scan.static_analysis.domains.length})</h3>
              {expandedSections.includes("domains") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("domains") && (
              <div className="p-6 border-t border-slate-700">
                <div className="grid grid-cols-2 gap-2 max-h-96 overflow-y-auto">
                  {scan.static_analysis.domains.map((domain: string, idx: number) => (
                    <div key={idx} className="bg-slate-800/30 p-2 rounded border border-slate-700">
                      <span className="text-slate-300 text-sm font-mono">{domain}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - IP Addresses */}
        {scan.static_analysis?.ip_addresses && scan.static_analysis.ip_addresses.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("ips")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">IP Addresses ({scan.static_analysis.ip_addresses.length})</h3>
              {expandedSections.includes("ips") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("ips") && (
              <div className="p-6 border-t border-slate-700">
                <div className="grid grid-cols-2 gap-2">
                  {scan.static_analysis.ip_addresses.map((ip: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                      <span className="text-slate-300 font-mono">{ip.address}</span>
                      <span className="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">{ip.type}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Emails */}
        {scan.static_analysis?.emails && scan.static_analysis.emails.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("emails")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Email Addresses ({scan.static_analysis.emails.length})</h3>
              {expandedSections.includes("emails") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("emails") && (
              <div className="p-6 border-t border-slate-700 space-y-2">
                {scan.static_analysis.emails.map((email: string, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono">{email}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - File Paths */}
        {scan.static_analysis?.file_paths && scan.static_analysis.file_paths.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("file_paths")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">File Paths ({scan.static_analysis.file_paths.length})</h3>
              {expandedSections.includes("file_paths") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("file_paths") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {scan.static_analysis.file_paths.map((path: string, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-sm break-all">{path}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Base64 Strings */}
        {scan.static_analysis?.base64_strings && scan.static_analysis.base64_strings.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("base64_strings")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Base64 Strings ({scan.static_analysis.base64_strings.length})</h3>
              {expandedSections.includes("base64_strings") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("base64_strings") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {scan.static_analysis.base64_strings.slice(0, 200).map((value: string, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - API Keys */}
        {apiKeyEntries.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("api_keys")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">API Keys ({apiKeyEntries.length})</h3>
              {expandedSections.includes("api_keys") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("api_keys") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {apiKeyEntries.slice(0, 200).map((key: any, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{typeof key === 'string' ? key : JSON.stringify(key)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Crypto Keys */}
        {cryptoKeyEntries.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("crypto_keys")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Crypto Keys ({cryptoKeyEntries.length})</h3>
              {expandedSections.includes("crypto_keys") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("crypto_keys") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {cryptoKeyEntries.slice(0, 200).map((key: any, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{typeof key === 'string' ? key : JSON.stringify(key)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Firebase */}
        {firebaseEntries.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("firebase")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Firebase ({firebaseEntries.length})</h3>
              {expandedSections.includes("firebase") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("firebase") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {firebaseEntries.slice(0, 200).map((entry: any, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{typeof entry === 'string' ? entry : JSON.stringify(entry)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - AWS */}
        {awsEntries.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("aws")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">AWS ({awsEntries.length})</h3>
              {expandedSections.includes("aws") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("aws") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {awsEntries.slice(0, 200).map((entry: any, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{typeof entry === 'string' ? entry : JSON.stringify(entry)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Code Secrets */}
        {codeSecretEntries.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("code_secrets")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Code Secrets ({codeSecretEntries.length})</h3>
              {expandedSections.includes("code_secrets") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("code_secrets") && (
              <div className="p-6 border-t border-slate-700 space-y-2 max-h-96 overflow-y-auto">
                {codeSecretEntries.slice(0, 200).map((entry: any, idx: number) => (
                  <div key={idx} className="bg-slate-800/30 p-3 rounded-lg border border-slate-700">
                    <span className="text-slate-300 font-mono text-xs break-all">{typeof entry === 'string' ? entry : JSON.stringify(entry)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Interesting Strings */}
        {staticInfo.interesting_strings && Object.keys(staticInfo.interesting_strings).length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("interesting_strings")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Interesting Strings</h3>
              {expandedSections.includes("interesting_strings") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("interesting_strings") && (
              <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4">
                {Object.entries(staticInfo.interesting_strings).map(([key, values]: any) => (
                  <div key={key} className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2 capitalize">{key} ({Array.isArray(values) ? values.length : 0})</h4>
                    <div className="space-y-1 max-h-56 overflow-auto text-xs font-mono text-slate-300">
                      {Array.isArray(values) && values.slice(0, 50).map((value: string, idx: number) => (
                        <div key={idx} className="whitespace-pre-wrap">{value}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - APK File Inventory */}
        {staticInfo.files_list && Object.keys(staticInfo.files_list).length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("files_list")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">APK File Inventory</h3>
              {expandedSections.includes("files_list") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("files_list") && (
              <div className="p-6 border-t border-slate-700 grid grid-cols-1 lg:grid-cols-2 gap-4">
                {Object.entries(staticInfo.files_list).filter(([key]) => key !== 'total_count').map(([key, values]: any) => (
                  <div key={key} className="bg-slate-800/30 p-4 rounded-lg border border-slate-700">
                    <h4 className="text-white font-semibold mb-2 capitalize">{key} ({Array.isArray(values) ? values.length : values?.total_count || 0})</h4>
                    <div className="space-y-1 max-h-56 overflow-auto text-xs font-mono text-slate-300">
                      {Array.isArray(values) && values.slice(0, 50).map((value: string, idx: number) => (
                        <div key={idx} className="whitespace-pre-wrap">{value}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Strings */}
        {scan.static_analysis?.strings && scan.static_analysis.strings.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("strings")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Extracted Strings ({scan.static_analysis.strings.length})</h3>
              {expandedSections.includes("strings") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("strings") && (
              <div className="p-6 border-t border-slate-700">
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-700 max-h-96 overflow-y-auto font-mono text-xs text-slate-300 space-y-1">
                  {scan.static_analysis.strings.slice(0, 500).map((str: string, idx: number) => (
                    <div key={idx} className="hover:bg-slate-800 px-2 py-1 rounded">{str}</div>
                  ))}
                  {scan.static_analysis.strings.length > 500 && (
                    <div className="text-slate-500 pt-2">... and {scan.static_analysis.strings.length - 500} more strings</div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - File Paths */}
        {scan.static_analysis?.file_paths && scan.static_analysis.file_paths.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("filePaths")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">File Paths ({scan.static_analysis.file_paths.length})</h3>
              {expandedSections.includes("filePaths") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("filePaths") && (
              <div className="p-6 border-t border-slate-700">
                <div className="bg-slate-900 p-4 rounded-lg border border-slate-700 max-h-96 overflow-y-auto font-mono text-xs text-slate-300 space-y-1">
                  {scan.static_analysis.file_paths.map((path: string, idx: number) => (
                    <div key={idx} className="hover:bg-slate-800 px-2 py-1 rounded">{path}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - APK Files */}
        {scan.static_analysis?.files_list && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("apkFiles")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">APK Contents ({scan.static_analysis.files_list.total_count} files)</h3>
              {expandedSections.includes("apkFiles") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("apkFiles") && (
              <div className="p-6 border-t border-slate-700 space-y-4">
                {scan.static_analysis.files_list.dex_files?.length > 0 && (
                  <div>
                    <h4 className="text-cyan-400 font-semibold mb-2">DEX Files ({scan.static_analysis.files_list.dex_files.length})</h4>
                    <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 font-mono text-xs text-slate-300 space-y-1">
                      {scan.static_analysis.files_list.dex_files.map((file: string, idx: number) => (
                        <div key={idx}>{file}</div>
                      ))}
                    </div>
                  </div>
                )}

                {scan.static_analysis.files_list.so_libraries?.length > 0 && (
                  <div>
                    <h4 className="text-cyan-400 font-semibold mb-2">Native Libraries ({scan.static_analysis.files_list.so_libraries.length})</h4>
                    <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 font-mono text-xs text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                      {scan.static_analysis.files_list.so_libraries.map((file: string, idx: number) => (
                        <div key={idx}>{file}</div>
                      ))}
                    </div>
                  </div>
                )}

                {scan.static_analysis.files_list.assets?.length > 0 && (
                  <div>
                    <h4 className="text-cyan-400 font-semibold mb-2">Assets ({scan.static_analysis.files_list.assets.length})</h4>
                    <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 font-mono text-xs text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                      {scan.static_analysis.files_list.assets.slice(0, 100).map((file: string, idx: number) => (
                        <div key={idx}>{file}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - API Keys & Secrets */}
        {(scan.static_analysis?.api_keys && scan.static_analysis.api_keys.length > 0) || 
         (scan.static_analysis?.code_secrets && scan.static_analysis.code_secrets.length > 0) && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden border-2 border-red-500/30">
            <button
              onClick={() => toggleSection("secrets")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">⚠️ Secrets & API Keys Found</h3>
              {expandedSections.includes("secrets") ? (
                <ChevronUp className="w-5 h-5 text-red-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-red-400" />
              )}
            </button>

            {expandedSections.includes("secrets") && (
              <div className="p-6 border-t border-slate-700 space-y-4">
                {scan.static_analysis?.api_keys && scan.static_analysis.api_keys.length > 0 && (
                  <div>
                    <h4 className="text-red-400 font-semibold mb-2">API Keys</h4>
                    {scan.static_analysis.api_keys.map((key: any, idx: number) => (
                      <div key={idx} className="bg-red-500/10 p-3 rounded-lg border border-red-500/30 mb-2">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-red-400 font-semibold text-sm">{key.type}</span>
                        </div>
                        <code className="text-xs text-slate-300 font-mono break-all">{key.value}</code>
                      </div>
                    ))}
                  </div>
                )}

                {scan.static_analysis?.code_secrets && scan.static_analysis.code_secrets.length > 0 && (
                  <div>
                    <h4 className="text-orange-400 font-semibold mb-2">Potential Secrets</h4>
                    {scan.static_analysis.code_secrets.map((secret: any, idx: number) => (
                      <div key={idx} className="bg-orange-500/10 p-3 rounded-lg border border-orange-500/30 mb-2">
                        <div className="text-orange-400 font-semibold text-sm mb-1">{secret.keyword}</div>
                        <code className="text-xs text-slate-300 font-mono">{secret.context}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Static Analysis - Firebase & AWS */}
        {(scan.static_analysis?.firebase || scan.static_analysis?.aws) && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("cloud")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
            >
              <h3 className="text-white font-semibold">Cloud Services Configuration</h3>
              {expandedSections.includes("cloud") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("cloud") && (
              <div className="p-6 border-t border-slate-700 space-y-4">
                {scan.static_analysis?.firebase && (
                  <div>
                    <h4 className="text-orange-400 font-semibold mb-2">🔥 Firebase</h4>
                    <div className="bg-orange-500/10 p-4 rounded-lg border border-orange-500/30 space-y-2">
                      {scan.static_analysis.firebase.urls?.map((url: string, idx: number) => (
                        <div key={idx} className="text-slate-300 font-mono text-sm">{url}</div>
                      ))}
                      {scan.static_analysis.firebase.config && Object.entries(scan.static_analysis.firebase.config).map(([key, value]: [string, any]) => (
                        <div key={key} className="flex items-center justify-between">
                          <span className="text-slate-400 text-sm">{key}:</span>
                          <span className="text-slate-300 font-mono text-sm">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {scan.static_analysis?.aws && (
                  <div>
                    <h4 className="text-yellow-400 font-semibold mb-2">☁️ AWS</h4>
                    <div className="bg-yellow-500/10 p-4 rounded-lg border border-yellow-500/30 space-y-2">
                      {scan.static_analysis.aws.s3_buckets?.length > 0 && (
                        <div>
                          <span className="text-slate-400 text-sm">S3 Buckets:</span>
                          <div className="mt-1 space-y-1">
                            {scan.static_analysis.aws.s3_buckets.map((bucket: string, idx: number) => (
                              <div key={idx} className="text-slate-300 font-mono text-sm">{bucket}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      {scan.static_analysis.aws.regions?.length > 0 && (
                        <div>
                          <span className="text-slate-400 text-sm">Regions:</span>
                          <div className="flex gap-2 mt-1 flex-wrap">
                            {scan.static_analysis.aws.regions.map((region: string, idx: number) => (
                              <span key={idx} className="px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-xs">{region}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* APK Contents */}
        {scan.static_analysis?.important_files && scan.static_analysis.important_files.length > 0 && (
          <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
            <button
              onClick={() => toggleSection("apkContents")}
              className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition"
            >
              <div className="flex items-center gap-3">
                <h3 className="text-white font-semibold">APK Contents</h3>
                <span className="text-xs text-slate-400 bg-slate-700/50 px-2 py-1 rounded">
                  {scan.static_analysis.file_count || scan.static_analysis.important_files.length} files
                </span>
              </div>
              {expandedSections.includes("apkContents") ? (
                <ChevronUp className="w-5 h-5 text-cyan-400" />
              ) : (
                <ChevronDown className="w-5 h-5 text-slate-400" />
              )}
            </button>

            {expandedSections.includes("apkContents") && (
              <div className="p-6 border-t border-slate-700">
                {/* Categorize files */}
                {(() => {
                  const categories: Record<string, any[]> = {
                    'Manifest': [],
                    'DEX': [],
                    'Library': [],
                    'XML': [],
                    'Resources': [],
                    'Other': []
                  };
                  
                  scan.static_analysis.important_files.forEach((file: any) => {
                    const category = file.type || 'Other';
                    if (categories[category]) {
                      categories[category].push(file);
                    } else {
                      categories['Other'].push(file);
                    }
                  });
                  
                  return (
                    <div className="space-y-6">
                      {Object.entries(categories).map(([categoryName, files]) => {
                        if (files.length === 0) return null;
                        
                        const categoryIcon = categoryName === 'Manifest' ? '📋' :
                                           categoryName === 'DEX' ? '⚙️' :
                                           categoryName === 'Library' ? '📚' :
                                           categoryName === 'XML' ? '📄' :
                                           categoryName === 'Resources' ? '🎨' : '📦';
                        
                        const categoryColor = categoryName === 'Manifest' ? 'text-cyan-400' :
                                            categoryName === 'DEX' ? 'text-orange-400' :
                                            categoryName === 'Library' ? 'text-purple-400' :
                                            categoryName === 'XML' ? 'text-blue-400' :
                                            categoryName === 'Resources' ? 'text-pink-400' : 'text-slate-400';
                        
                        return (
                          <div key={categoryName}>
                            <h4 className={`text-sm font-semibold ${categoryColor} mb-3 flex items-center gap-2`}>
                              <span className="text-lg">{categoryIcon}</span>
                              {categoryName} Files ({files.length})
                            </h4>
                            <div className="space-y-2">
                              {files.map((file: any, idx: number) => {
                                const isViewable = !['dex', 'so', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'ttf', 'otf', 'arsc'].includes(
                                  file.path.split('.').pop()?.toLowerCase() || ''
                                );
                                
                                return (
                                  <div
                                    key={idx}
                                    className={`flex items-center justify-between p-3 rounded-lg border border-slate-700 ${
                                      isViewable ? 'bg-slate-800/30 hover:bg-slate-800/70 cursor-pointer transition-all hover:border-cyan-500/50' : 'bg-slate-800/10'
                                    }`}
                                    onClick={() => isViewable && !loadingFile && viewFile(file.path)}
                                  >
                                    <div className="flex items-center gap-3 flex-1 min-w-0">
                                      <div className="flex-1 min-w-0">
                                        <p className="text-white text-sm font-mono truncate">{file.path}</p>
                                        <div className="flex items-center gap-3 mt-1">
                                          <span className="text-xs text-slate-500">{file.size}</span>
                                        </div>
                                      </div>
                                    </div>
                                    {isViewable && (
                                      <div className="shrink-0 ml-3">
                                        {loadingFile ? (
                                          <div className="w-4 h-4 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                                        ) : (
                                          <span className="text-cyan-400 text-xs font-medium hover:text-cyan-300">
                                            View →
                                          </span>
                                        )}
                                      </div>
                                    )}
                                    {!isViewable && (
                                      <span className="text-xs text-slate-500 shrink-0 ml-3">Binary</span>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  );
                })()}
                
                {scan.static_analysis.total_size && (
                  <div className="mt-6 pt-4 border-t border-slate-700">
                    <p className="text-slate-400 text-sm">
                      Total APK Size: <span className="text-white font-semibold">{scan.static_analysis.total_size}</span>
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* File Details */}
        <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
          <button
            onClick={() => toggleSection("fileDetails")}
            className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition"
          >
            <h3 className="text-white font-semibold">File Details</h3>
            {expandedSections.includes("fileDetails") ? (
              <ChevronUp className="w-5 h-5 text-cyan-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )}
          </button>

          {expandedSections.includes("fileDetails") && (
            <div className="p-6 border-t border-slate-700 space-y-3">
              {[
                { label: "Package Name", value: scan.package_name || 'N/A' },
                { label: "App Name", value: scan.app_name || 'N/A' },
                { label: "Version", value: scan.version || 'N/A' },
                { label: "File Name", value: scan.file_name || 'N/A' },
                { label: "File Size", value: `${(scan.file_size / 1024 / 1024).toFixed(2)} MB` },
                { label: "MD5 Hash", value: scan.hash_md5 || 'N/A' },
                { label: "SHA256", value: scan.hash_sha256 || 'N/A' },
                { label: "Status", value: scan.status || 'N/A' },
              ].map((detail, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between bg-slate-800/30 p-3 rounded-lg border border-slate-700"
                >
                  <span className="text-slate-400 text-sm">{detail.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-white text-sm font-mono truncate max-w-md">
                      {detail.value.length > 40 ? `${detail.value.substring(0, 40)}...` : detail.value}
                    </span>
                    <button
                      onClick={() => copyToClipboard(detail.value, detail.label)}
                      className="p-1.5 hover:bg-slate-700 rounded transition shrink-0"
                    >
                      {copiedHash === detail.label ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4 text-slate-400 hover:text-cyan-400" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        </TabsContent>

        {/* ── Fuzzing Tab ─────────────────────────────────────────────────── */}
        <TabsContent value="fuzzing" className="space-y-4 mt-4">

          {/* ── Not enabled ── */}
          {!scan.fuzzing_enabled && (
            <div className="glassmorphism rounded-lg cyber-border p-8 text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-slate-700/50 border border-slate-600 mb-4">
                <Bug className="w-8 h-8 text-slate-500" />
              </div>
              <h3 className="text-white font-semibold text-lg mb-2">Fuzzing Not Enabled for This Scan</h3>
              <p className="text-slate-400 text-sm max-w-md mx-auto mb-6">
                This scan was run without component fuzzing. Rescan the APK with
                <span className="text-orange-400 font-semibold"> Component Security Fuzzing</span> enabled to
                detect exported-component vulnerabilities — Intent injection, SQL injection in Content Providers,
                crash-inducing payloads, and missing permission guards.
              </p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center">
                <button
                  onClick={handleRescan}
                  className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 border border-orange-500/30 transition text-sm font-semibold cursor-pointer"
                >
                  <Bug className="w-4 h-4" />
                  Rescan with Fuzzing Enabled
                </button>
              </div>
            </div>
          )}

          {/* ── Enabled but no results yet ── */}
          {scan.fuzzing_enabled && !scan.fuzzing_analysis?.engine && (
            <div className="glassmorphism rounded-lg cyber-border p-8 text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-orange-500/10 border border-orange-500/20 mb-4 animate-pulse">
                <Bug className="w-8 h-8 text-orange-400" />
              </div>
              <h3 className="text-white font-semibold text-lg mb-2">Fuzzing In Progress…</h3>
              <p className="text-slate-400 text-sm">Component analysis is still running. Refresh the page in a moment.</p>
            </div>
          )}

          {/* ── Results ── */}
          {scan.fuzzing_analysis?.engine && (() => {
            const fa = scan.fuzzing_analysis
            const findings: any[] = fa.vulnerabilities || []
            const bySev = (sev: string) => findings.filter((f: any) => f.severity === sev).length
            const sourceBreakdown = fa.source_breakdown || {}
            const attackBreakdown = fa.attack_type_breakdown || {}
            const topRiskyComponents: any[] = fa.top_risky_components || []
            const recommendations: string[] = fa.recommendations || []
            const engineLabel: Record<string, string> = {
              "falcon-deep":    "Deep Analyzer",
              "falcon-runtime": "Runtime Engine",
              "falcon-static":  "Static Engine",
            }
            const engineColor: Record<string, string> = {
              "falcon-deep":    "text-orange-400 bg-orange-500/10 border-orange-500/30",
              "falcon-runtime": "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
              "falcon-static":  "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
            }

            return (
              <>
                {/* Engine + summary stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
                    <p className="text-slate-400 text-xs mb-1">Engine</p>
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${engineColor[fa.engine] ?? 'text-slate-300 bg-slate-700/40 border-slate-600'}`}>
                      FalconScan {engineLabel[fa.engine] ?? fa.engine}
                    </span>
                  </div>
                  <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
                    <p className="text-slate-400 text-xs mb-1">Components Scanned</p>
                    <p className="text-2xl font-bold text-orange-400">{fa.components_fuzzed ?? 0}</p>
                  </div>
                  <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
                    <p className="text-slate-400 text-xs mb-1">Findings</p>
                    <p className="text-2xl font-bold text-white">{fa.vulnerabilities_found ?? 0}</p>
                  </div>
                  <div className="glassmorphism p-4 rounded-lg cyber-border text-center">
                    <p className="text-slate-400 text-xs mb-1">Critical</p>
                    <p className="text-2xl font-bold text-red-400">{bySev('critical')}</p>
                  </div>
                </div>

                {/* Severity breakdown */}
                <div className="glassmorphism p-5 rounded-lg cyber-border">
                  <h3 className="text-white font-semibold mb-4">Severity Breakdown</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[
                      { sev: 'critical', label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
                      { sev: 'high',     label: 'High',     color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30' },
                      { sev: 'medium',   label: 'Medium',   color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30' },
                      { sev: 'low',      label: 'Low',      color: 'text-lime-400',   bg: 'bg-lime-500/10 border-lime-500/30' },
                    ].map(({ sev, label, color, bg }) => (
                      <div key={sev} className={`flex items-center justify-between p-3 rounded-lg border ${bg}`}>
                        <span className={`text-sm font-semibold ${color}`}>{label}</span>
                        <span className={`text-2xl font-bold ${color}`}>{bySev(sev)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Source and attack intelligence */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="glassmorphism p-5 rounded-lg cyber-border">
                    <h3 className="text-white font-semibold mb-4">Detection Source Coverage</h3>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Static', value: sourceBreakdown.static ?? findings.filter((f: any) => f.source === 'static').length, cls: 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10' },
                        { label: 'Code', value: sourceBreakdown.dynamic ?? findings.filter((f: any) => f.source === 'dynamic').length, cls: 'text-violet-300 border-violet-500/30 bg-violet-500/10' },
                        { label: 'Runtime', value: sourceBreakdown.runtime ?? findings.filter((f: any) => f.source === 'runtime').length, cls: 'text-orange-300 border-orange-500/30 bg-orange-500/10' },
                        { label: 'Fuzzing', value: sourceBreakdown.fuzzing ?? findings.filter((f: any) => (f.origin || f.analysis_origin) === 'fuzzing').length, cls: 'text-amber-300 border-amber-500/30 bg-amber-500/10' },
                        { label: 'Unknown', value: sourceBreakdown.unknown ?? 0, cls: 'text-slate-300 border-slate-600 bg-slate-700/40' },
                      ].map((item) => (
                        <div key={item.label} className={`p-3 rounded-lg border ${item.cls}`}>
                          <p className="text-xs uppercase tracking-wide opacity-80">{item.label}</p>
                          <p className="text-2xl font-bold mt-1">{item.value}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="glassmorphism p-5 rounded-lg cyber-border">
                    <h3 className="text-white font-semibold mb-4">Top Attack Vectors</h3>
                    <div className="space-y-2">
                      {Object.entries(attackBreakdown).slice(0, 6).map(([attack, count]: [string, any]) => (
                        <div key={attack} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-800/40 border border-slate-700">
                          <p className="text-sm text-slate-200">{attack}</p>
                          <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30">{count}</span>
                        </div>
                      ))}
                      {Object.keys(attackBreakdown).length === 0 && (
                        <p className="text-sm text-slate-500">No attack vectors classified yet.</p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Component breakdown (if summary present) */}
                {fa.component_summary && (
                  <div className="glassmorphism p-5 rounded-lg cyber-border">
                    <h3 className="text-white font-semibold mb-4">Component Breakdown</h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      {Object.entries(fa.component_summary as Record<string, any>).map(([ctype, data]: [string, any]) => (
                        <div key={ctype} className="bg-slate-800/40 p-4 rounded-lg border border-slate-700">
                          <p className="text-slate-300 text-sm font-semibold capitalize mb-2">{ctype}</p>
                          <div className="space-y-1 text-xs text-slate-400">
                            <div className="flex justify-between"><span>Total</span><span className="text-white font-bold">{data.total}</span></div>
                            <div className="flex justify-between"><span>Exported</span><span className="text-orange-300 font-bold">{data.exported}</span></div>
                            <div className="flex justify-between"><span>Flagged</span><span className="text-red-400 font-bold">{data.flagged}</span></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(topRiskyComponents.length > 0 || recommendations.length > 0) && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="glassmorphism p-5 rounded-lg cyber-border">
                      <h3 className="text-white font-semibold mb-4">Most Risky Components</h3>
                      <div className="space-y-2">
                        {topRiskyComponents.map((item: any, idx: number) => (
                          <div key={item.component || idx} className="p-3 rounded-lg bg-slate-800/40 border border-slate-700">
                            <div className="flex items-center justify-between gap-3">
                              <p className="text-sm text-cyan-300 font-mono break-all">{item.component}</p>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                item.max_severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                item.max_severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                                item.max_severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                'bg-lime-500/20 text-lime-400 border-lime-500/30'
                              }`}>
                                {item.max_severity}
                              </span>
                            </div>
                            <div className="mt-2 flex items-center justify-between text-xs">
                              <span className="text-slate-400">Findings: <span className="text-white font-semibold">{item.findings}</span></span>
                              <span className="text-slate-400">Top: <span className="text-orange-300">{item.top_attack_type}</span></span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="glassmorphism p-5 rounded-lg cyber-border">
                      <h3 className="text-white font-semibold mb-4">Prioritized Remediation</h3>
                      <div className="space-y-2.5">
                        {recommendations.map((rec, idx) => (
                          <div key={`${idx}-${rec.slice(0, 20)}`} className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                            <p className="text-sm text-emerald-200 leading-relaxed">{rec}</p>
                          </div>
                        ))}
                        {recommendations.length === 0 && (
                          <p className="text-sm text-slate-500">No automated recommendations were generated for this scan.</p>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Findings list */}
                <div className="glassmorphism rounded-lg cyber-border overflow-hidden">
                  <button
                    onClick={() => toggleSection("fuzzing_findings")}
                    className="w-full flex items-center justify-between p-6 hover:bg-slate-800/50 transition cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <h3 className="text-white font-semibold">Detailed Findings</h3>
                      <span className="px-2 py-0.5 text-xs rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/30">
                        {findings.length}
                      </span>
                    </div>
                    {expandedSections.includes("fuzzing_findings") ? (
                      <ChevronUp className="w-5 h-5 text-orange-400" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-slate-400" />
                    )}
                  </button>

                  {expandedSections.includes("fuzzing_findings") && (
                    <div className="p-6 border-t border-slate-700 space-y-6">
                      {/* Findings Summary by Component */}
                      {fa.findings_by_component && Object.keys(fa.findings_by_component).length > 0 && (
                        <div className="bg-slate-900/30 rounded-lg border border-slate-700/50 p-4">
                          <h4 className="text-white font-semibold text-sm mb-3">Findings by Component</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {Object.entries(fa.findings_by_component).map(([comp, findings_list]: [string, any]) => {
                              const findingsList = Array.isArray(findings_list) ? findings_list : []
                              const severities = findingsList.map((f: any) => f.severity)
                              const critCount = severities.filter((s: string) => s === 'critical').length
                              const highCount = severities.filter((s: string) => s === 'high').length
                              const maxSev = critCount > 0 ? 'critical' : highCount > 0 ? 'high' : 'medium'
                              return (
                                <div key={comp} className={`p-3 rounded-lg border ${
                                  maxSev === 'critical' ? 'bg-red-500/5 border-red-500/20' :
                                  maxSev === 'high' ? 'bg-orange-500/5 border-orange-500/20' :
                                  'bg-yellow-500/5 border-yellow-500/20'
                                }`}>
                                  <p className="text-sm text-slate-200 font-mono break-all mb-2">{comp}</p>
                                  <div className="flex items-center gap-2 text-xs">
                                    {critCount > 0 && <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300">Critical: {critCount}</span>}
                                    {highCount > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-300">High: {highCount}</span>}
                                    <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">Total: {findingsList.length}</span>
                                  </div>
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      )}

                      {findings.length === 0 ? (
                        <div className="text-center py-10">
                          <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-green-500/10 border border-green-500/30 mb-3">
                            <svg className="w-7 h-7 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          </div>
                          <p className="text-slate-300 font-semibold">No vulnerabilities found</p>
                          <p className="text-slate-500 text-sm mt-1">All scanned components appear to be properly guarded.</p>
                        </div>
                      ) : (
                        findings.map((finding: any, idx: number) => {
                          const src: string = finding.source ?? (
                            (!finding.payload || finding.payload.startsWith('N/A')) ? 'static' : 'runtime'
                          )
                          const origin: string = finding.origin ?? finding.analysis_origin ?? ''
                          const isStatic  = src === 'static'
                          const isDynamic = src === 'dynamic'
                          const isRuntime = src === 'runtime'
                          const isFuzzing = origin === 'fuzzing'

                          // Categorise runtime fuzz payloads so readers know what attack class triggered the finding
                          const payloadCategory = (() => {
                            if (!isRuntime && !isFuzzing) return null
                            const p: string = finding.payload || ''
                            if (/DROP TABLE|UNION SELECT|OR '1'='1|AND 1=/i.test(p))  return { label: 'SQL Injection',      cls: 'bg-red-500/20 text-red-300 border-red-500/30' }
                            if (/javascript:|<script/i.test(p))                       return { label: 'Script Injection',   cls: 'bg-purple-500/20 text-purple-300 border-purple-500/30' }
                            if (/\.\.[/\\]|file:\/\/\//.test(p))                      return { label: 'Path Traversal',     cls: 'bg-orange-500/20 text-orange-300 border-orange-500/30' }
                            if (/content:\/\/|intent:\/\//.test(p))                   return { label: 'URI Injection',      cls: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' }
                            if (p.length >= 80 || /^A+$/i.test(p.trim()))             return { label: 'Buffer Overflow',    cls: 'bg-pink-500/20 text-pink-300 border-pink-500/30' }
                            if (p === '' || p === 'null')                              return { label: 'Null / Empty',       cls: 'bg-slate-500/20 text-slate-300 border-slate-500/30' }
                            return { label: 'Intent Extra', cls: 'bg-blue-500/20 text-blue-300 border-blue-500/30' }
                          })()

                          return (
                            <div key={idx} className="bg-slate-800/30 p-5 rounded-lg border border-slate-700 hover:border-orange-500/30 transition">
                              {/* Header */}
                              <div className="flex items-start justify-between mb-3 gap-3">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className={`px-2 py-1 rounded text-xs font-bold uppercase border ${
                                    finding.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                    finding.severity === 'high'     ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                                    finding.severity === 'medium'   ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                                                      'bg-lime-500/20 text-lime-400 border-lime-500/30'
                                  }`}>
                                    {finding.severity}
                                  </span>
                                  <span className="px-2 py-1 rounded text-xs bg-slate-700/60 text-slate-300 border border-slate-600">
                                    {finding.type || finding.title}
                                  </span>
                                  {isFuzzing && (
                                    <span className="px-2 py-1 rounded text-[10px] font-semibold uppercase bg-amber-500/10 text-amber-300 border border-amber-500/30">
                                      Fuzzing Origin
                                    </span>
                                  )}
                                  {isStatic ? (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                                      Static Analysis
                                    </span>
                                  ) : isDynamic ? (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-violet-500/10 text-violet-400 border border-violet-500/30">
                                      Dynamic Code Analysis
                                    </span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">
                                      Runtime Fuzz
                                    </span>
                                  )}
                                </div>
                                <span className="text-xs text-slate-500 shrink-0"># {idx + 1}</span>
                              </div>

                              {/* Affected component */}
                              <div className="mb-3 p-3 rounded-lg bg-slate-900/40 border border-slate-700/60">
                                <span className="text-xs text-slate-500 uppercase tracking-wide">Affected Component</span>
                                <p className="text-cyan-300 font-mono text-sm mt-0.5 break-all">{finding.component}</p>
                              </div>

                              {/* Description */}
                              <p className="text-slate-300 text-sm leading-relaxed mb-3">{finding.description}</p>

                              {/* Evidence */}
                              {finding.evidence && (
                                <div className="mb-3 p-3 rounded bg-slate-900/60 border border-slate-700">
                                  <p className="text-xs text-slate-500 mb-1 uppercase tracking-wide">Evidence</p>
                                  <code className="text-xs text-red-300 font-mono break-all">{finding.evidence}</code>
                                </div>
                              )}

                              {/* Payload / Detection technique */}
                              {isStatic ? (
                                <div className="mb-3 p-3 rounded bg-slate-900/60 border border-cyan-500/20">
                                  <p className="text-xs text-cyan-500 uppercase tracking-wide mb-1">Detection Technique</p>
                                  <p className="text-xs text-cyan-200 font-mono">
                                    {finding.detection_technique || 'AndroidManifest.xml attribute inspection — no runtime payload required. Exported flag and permission attributes were cross-checked against Android security guidelines.'}
                                  </p>
                                </div>
                              ) : isDynamic ? (
                                <div className="mb-3 p-3 rounded bg-slate-900/60 border border-violet-500/20">
                                  <p className="text-xs text-violet-400 uppercase tracking-wide mb-1.5">DEX Code-Level Analysis — Data-Flow Pattern</p>
                                  <code className="text-xs text-violet-200 font-mono break-all block whitespace-pre-wrap">
                                    {finding.payload || '(code pattern match)'}
                                  </code>
                                  <p className="text-xs text-slate-500 mt-1.5">
                                    {finding.detection_technique || 'Identified by tracing dangerous data flows in the component\'s DEX bytecode — no device required.'}
                                  </p>
                                </div>
                              ) : (
                                <div className="mb-3 p-3 rounded bg-slate-900/60 border border-yellow-500/20">
                                  <div className="flex items-center justify-between mb-1.5">
                                    <p className="text-xs text-yellow-400 uppercase tracking-wide">Fuzz Payload Sent to Component</p>
                                    {payloadCategory && (
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${payloadCategory.cls}`}>
                                        {payloadCategory.label}
                                      </span>
                                    )}
                                  </div>
                                  <p className="text-xs text-slate-300 mb-2">
                                    <span className="text-slate-500 uppercase tracking-wide">Detection Technique:</span> {finding.detection_technique || 'Hybrid fuzzing with semantic payload mutation and crash monitoring.'}
                                  </p>
                                  {finding.attack_vector && (
                                    <p className="text-xs text-slate-400 mb-2">
                                      <span className="text-slate-500 uppercase tracking-wide">Attack Vector:</span> {finding.attack_vector}
                                    </p>
                                  )}
                                  <code className="text-xs text-yellow-200 font-mono break-all block whitespace-pre-wrap">
                                    {finding.payload || '(empty string)'}
                                  </code>
                                  {origin && (
                                    <p className="text-[11px] text-amber-300 mt-2 uppercase tracking-wide">
                                      Origin: {origin}
                                    </p>
                                  )}
                                </div>
                              )}

                              {/* Remediation */}
                              <div className="pt-3 border-t border-slate-700/60">
                                <p className="text-xs text-slate-500 mb-1 uppercase tracking-wide">Remediation</p>
                                <p className="text-sm text-green-300">{finding.remediation}</p>
                              </div>
                            </div>
                          )
                        })
                      )}
                    </div>
                  )}
                </div>

                {/* Scan metadata */}
                <div className="glassmorphism p-5 rounded-lg cyber-border">
                  <h3 className="text-white font-semibold mb-3 text-sm">Scan Metadata</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                    {[
                      { label: "Package", value: fa.package || scan.package_name || 'N/A' },
                      { label: "Started",  value: fa.start_time || 'N/A' },
                      { label: "Finished", value: fa.end_time   || 'N/A' },
                    ].map(({ label, value }) => (
                      <div key={label} className="bg-slate-800/40 p-3 rounded-lg border border-slate-700">
                        <p className="text-slate-500 uppercase tracking-wide mb-1">{label}</p>
                        <p className="text-slate-200 font-mono break-all">{value}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )
          })()}

        </TabsContent>

        {/* ── AI Analysis Tab ──────────────────────────────────────────────────── */}
        <TabsContent value="ai" className="space-y-5 mt-4">
          {(() => {
            const report = aiReport || scan?.ai_report

            const generateReport = async (force = false) => {
              setAiLoading(true)
              setAiError(null)
              try {
                const res = await scansAPI.aiAnalysis(scan.id, force)
                setAiReport(res.data.report)
              } catch (err: any) {
                const raw = err?.response?.data?.error || 'Analysis failed'
                const clean = raw
                  .replace(/GEMINI_API_KEY|AI_API_KEY/gi, 'ANALYSIS_ENGINE')
                  .replace(/gemini/gi, 'engine')
                  .replace(/google/gi, 'service')
                setAiError(clean)
              } finally {
                setAiLoading(false)
              }
            }

            const severityColor = (s: string) => {
              switch ((s || '').toLowerCase()) {
                case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
                case 'high':     return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
                case 'medium':   return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                case 'low':      return 'bg-lime-500/20 text-lime-400 border-lime-500/30'
                default:         return 'bg-slate-500/20 text-slate-400 border-slate-500/30'
              }
            }

            const likelihoodColor = (l: string) => {
              switch ((l || '').toLowerCase()) {
                case 'critical': return 'text-red-400'
                case 'high':     return 'text-orange-400'
                case 'medium':   return 'text-yellow-400'
                case 'low':      return 'text-green-400'
                default:         return 'text-slate-400'
              }
            }

            const effortColor = (e: string) => {
              switch ((e || '').toLowerCase()) {
                case 'low':    return 'bg-green-500/20 text-green-400 border-green-500/30'
                case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                case 'high':   return 'bg-red-500/20 text-red-400 border-red-500/30'
                default:       return 'bg-slate-500/20 text-slate-400 border-slate-500/30'
              }
            }

            const impactColor = (i: string) => {
              switch ((i || '').toLowerCase()) {
                case 'high':   return 'bg-red-500/20 text-red-400 border-red-500/30'
                case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                case 'low':    return 'bg-green-500/20 text-green-400 border-green-500/30'
                default:       return 'bg-slate-500/20 text-slate-400 border-slate-500/30'
              }
            }

            const riskBarColor = (v: number) => {
              if (v >= 75) return 'bg-red-500'
              if (v >= 50) return 'bg-orange-500'
              if (v >= 25) return 'bg-yellow-500'
              return 'bg-green-500'
            }

            const riskLabels: Record<string, string> = {
              network: 'Network',
              data_storage: 'Data Storage',
              authentication: 'Authentication',
              components: 'Components',
              cryptography: 'Cryptography',
            }

            const aiSteps = [
              'Parsing APK structure…',
              'Building vulnerability graph…',
              'Running threat model inference…',
              'Mapping MITRE ATT&CK techniques…',
              'Building attack surface map…',
              'Generating intelligence report…',
            ]

            const currentStep = Math.min(aiStep, aiSteps.length - 1)

            return (
              <>
                {/* Header */}
                <div className="glassmorphism p-5 rounded-lg cyber-border flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-violet-500/20 border border-violet-500/30 flex items-center justify-center shrink-0">
                      <Brain className="w-5 h-5 text-violet-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-white font-semibold">FalconScan Security Engine</h3>
                        <span className="flex items-center gap-1.5 text-xs bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 rounded-full">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                          LOCAL
                        </span>
                      </div>
                      <p className="text-slate-400 text-xs mt-0.5">Runs entirely on the FalconScan server · No data sent externally</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      onClick={() => generateReport(true)}
                      disabled={aiLoading}
                      className="flex items-center gap-2 bg-slate-700/50 hover:bg-slate-700 text-slate-300 border border-slate-600 text-xs"
                    >
                      <RefreshCw className={`w-3 h-3 ${aiLoading ? 'animate-spin' : ''}`} />
                      Regenerate
                    </Button>
                  </div>
                </div>

                {/* Loading state */}
                {aiLoading && !report && (
                  <div className="glassmorphism p-8 rounded-lg cyber-border space-y-6">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-violet-500/20 border border-violet-500/30 flex items-center justify-center shrink-0">
                        <Cpu className="w-6 h-6 text-violet-400 animate-pulse" />
                      </div>
                      <div>
                        <p className="text-white font-semibold">Security Engine Running</p>
                        <p className="text-slate-400 text-sm">Analysing {scan.app_name} locally…</p>
                      </div>
                    </div>
                    <div className="bg-slate-950 rounded-lg p-4 space-y-2 border border-slate-800 font-mono text-xs">
                      {aiSteps.map((step, i) => (
                        <div key={i} className={`flex items-center gap-2 transition-opacity duration-500 ${i <= currentStep ? 'opacity-100' : 'opacity-20'}`}>
                          <span className={`shrink-0 w-3 ${i < currentStep ? 'text-green-400' : i === currentStep ? 'text-violet-400' : 'text-slate-600'}`}>
                            {i < currentStep ? '✓' : i === currentStep ? '▶' : '○'}
                          </span>
                          <span className={i < currentStep ? 'text-slate-400' : i === currentStep ? 'text-violet-300' : 'text-slate-600'}>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Error state */}
                {aiError && (
                  <div className="glassmorphism p-5 rounded-lg border border-red-500/30 bg-red-500/5 flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
                    <div className="flex-1">
                      <p className="text-red-300 font-medium">Analysis Engine Error</p>
                      <p className="text-slate-400 text-sm mt-1">
                        {aiError.includes('quota') || aiError.includes('exhausted') || aiError.includes('429')
                          ? 'Analysis capacity is temporarily exhausted. Please try again later or contact your administrator.'
                          : aiError.includes('not set') || aiError.includes('ANALYSIS_ENGINE')
                          ? 'The AI analysis engine is not configured on this server. Contact your administrator to enable it.'
                          : aiError}
                      </p>
                    </div>
                  </div>
                )}

                {/* Empty state */}
                {!report && !aiLoading && !aiError && (
                  <div className="glassmorphism p-12 rounded-lg cyber-border text-center space-y-4">
                    <div className="w-16 h-16 rounded-2xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center mx-auto">
                      <Brain className="w-8 h-8 text-violet-400/60" />
                    </div>
                    <div>
                      <p className="text-white font-semibold">AI Security Analysis</p>
                      <p className="text-slate-400 text-sm mt-1">Analysis is generated automatically with every scan.</p>
                      <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 mt-4 text-xs text-slate-500">
                        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-500" /> MITRE ATT&CK Mapping</span>
                        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-500" /> Attack Surface Analysis</span>
                        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-500" /> Threat Intelligence Profile</span>
                        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-500" /> Remediation Roadmap</span>
                        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-500" /> Business Impact Assessment</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Report */}
                {report && !aiLoading && (
                  <div className="space-y-5">

                    {/* ── Risk Dashboard ── */}
                    <div className="glassmorphism p-6 rounded-lg cyber-border">
                      <div className="flex items-center gap-2 mb-5">
                        <Gauge className="w-4 h-4 text-violet-400" />
                        <h3 className="text-white font-semibold">Risk Dashboard</h3>
                      </div>
                      <div className="grid grid-cols-[auto_1fr] gap-6 items-center">
                        <div className="flex flex-col items-center gap-1">
                          <div className={`w-20 h-20 rounded-full border-4 flex items-center justify-center ${
                            (scan.threat_score || 0) >= 75 ? 'border-red-500 bg-red-500/10' :
                            (scan.threat_score || 0) >= 50 ? 'border-orange-500 bg-orange-500/10' :
                            (scan.threat_score || 0) >= 25 ? 'border-yellow-500 bg-yellow-500/10' :
                            'border-green-500 bg-green-500/10'
                          }`}>
                            <span className={`text-2xl font-bold ${
                              (scan.threat_score || 0) >= 75 ? 'text-red-400' :
                              (scan.threat_score || 0) >= 50 ? 'text-orange-400' :
                              (scan.threat_score || 0) >= 25 ? 'text-yellow-400' : 'text-green-400'
                            }`}>{scan.threat_score ?? '?'}</span>
                          </div>
                          <span className="text-xs text-slate-500">Risk Score</span>
                          <span className={`text-xs font-bold uppercase ${
                            scan.threat_level === 'critical' ? 'text-red-400' :
                            scan.threat_level === 'high' ? 'text-orange-400' :
                            scan.threat_level === 'medium' ? 'text-yellow-400' : 'text-green-400'
                          }`}>{scan.threat_level}</span>
                        </div>
                        {report.risk_breakdown && (
                          <div className="space-y-2.5">
                            {Object.entries(report.risk_breakdown as Record<string, number>).map(([key, val]) => (
                              <div key={key} className="flex items-center gap-3">
                                <span className="text-slate-400 text-xs w-28 shrink-0">{riskLabels[key] || key}</span>
                                <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                                  <div style={{ width: `${val}%` }} className={`h-full rounded-full transition-all ${riskBarColor(val as number)}`} />
                                </div>
                                <span className="text-xs text-slate-400 w-6 text-right">{val}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* ── Executive Summary + Business Impact ── */}
                    {report.executive_summary && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-3">
                          <Shield className="w-4 h-4 text-violet-400" />
                          <h3 className="text-white font-semibold">Executive Summary</h3>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{report.executive_summary}</p>
                        {report.overall_risk_assessment && (
                          <p className="text-slate-400 text-sm mt-3 leading-relaxed">{report.overall_risk_assessment}</p>
                        )}
                        {report.business_impact && (
                          <div className="mt-4 bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
                            <div className="flex items-center gap-2 mb-2">
                              <Building2 className="w-3.5 h-3.5 text-amber-400" />
                              <p className="text-xs text-amber-400 uppercase tracking-wide font-semibold">Business Impact</p>
                            </div>
                            <p className="text-slate-300 text-sm leading-relaxed">{report.business_impact}</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* ── Attack Surface Map (interactive SVG flowchart) ── */}
                    {report.attack_surface?.length > 0 && (() => {
                      const surfs = report.attack_surface as any[]

                      // Canvas dimensions
                      const W = 960, H = 540
                      const cx = W / 2, cy = H / 2

                      const sevHex = (s: string, exposed: boolean) => {
                        if (!exposed) return '#22c55e'
                        switch ((s || '').toLowerCase()) {
                          case 'critical': return '#ef4444'
                          case 'high':     return '#f97316'
                          case 'medium':   return '#eab308'
                          case 'low':      return '#84cc16'
                          default:         return '#6b7280'
                        }
                      }

                      const sevGlow = (s: string, exposed: boolean) => {
                        if (!exposed) return '#16a34a'
                        switch ((s || '').toLowerCase()) {
                          case 'critical': return '#dc2626'
                          case 'high':     return '#ea580c'
                          case 'medium':   return '#ca8a04'
                          case 'low':      return '#65a30d'
                          default:         return '#475569'
                        }
                      }

                      // Node layout: radial with variable orbit so nodes never overlap
                      const nW = 152, nH = 68
                      const orbR = 215
                      const nodes = surfs.map((surf, i) => {
                        const angle = (-Math.PI / 2) + (2 * Math.PI / surfs.length) * i
                        return {
                          ...surf,
                          nx: Math.round(cx + orbR * Math.cos(angle)),
                          ny: Math.round(cy + orbR * Math.sin(angle)),
                          angle,
                        }
                      })

                      const selNode = selectedSurface !== null ? nodes[selectedSurface] : null

                      // SVG path for curved connector (cubic bezier from center to node)
                      const curvePath = (n: any) => {
                        const dx = n.nx - cx, dy = n.ny - cy
                        const dist = Math.sqrt(dx * dx + dy * dy)
                        const ux = dx / dist, uy = dy / dist
                        const x1 = cx + 44 * ux, y1 = cy + 44 * uy // leave center circle
                        const x2 = n.nx - (nW / 2 + 4) * ux, y2 = n.ny - (nH / 2 + 4) * uy // stop at node edge

                        // Control points tangent to produce a gentle arc
                        const cpDist = dist * 0.45
                        const perpX = -uy * cpDist * 0.08
                        const perpY = ux * cpDist * 0.08
                        const cp1x = x1 + ux * cpDist + perpX
                        const cp1y = y1 + uy * cpDist + perpY
                        const cp2x = x2 - ux * cpDist - perpX
                        const cp2y = y2 - uy * cpDist - perpY
                        return { path: `M ${x1} ${y1} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${x2} ${y2}`, x2, y2, ux, uy }
                      }

                      // Arrowhead at end of path
                      const arrowPoints = (x2: number, y2: number, ux: number, uy: number) => {
                        const len = 9, w = 4
                        const ax1 = x2 - len * ux + w * uy
                        const ay1 = y2 - len * uy - w * ux
                        const ax2 = x2 - len * ux - w * uy
                        const ay2 = y2 - len * uy + w * ux
                        return `${x2},${y2} ${ax1},${ay1} ${ax2},${ay2}`
                      }

                      // Category icon paths (tiny inline SVG icons as path data)
                      const iconPath = (cat: string) => {
                        const c = (cat || '').toLowerCase()
                        if (c.includes('network')) return 'M3 12h3m0 0l3-3m-3 3l3 3M18 12h-3m0 0l-3-3m3 3l-3 3M12 3v3m0 0l-3 3m3-3l3 3M12 18v3m0 0l-3-3m3 3l3-3' // wifi-like
                        if (c.includes('inter') || c.includes('ipc')) return 'M8 4h8M8 8h8M8 12h8M4 4v12M20 4v12' // network
                        if (c.includes('data') || c.includes('storage')) return 'M12 3C7 3 3 5 3 7.5S7 12 12 12s9-2 9-4.5S17 3 12 3zM3 7.5v4C3 14 7 16 12 16s9-2 9-4.5v-4M3 11.5v4C3 18 7 20 12 20s9-2 9-4.5v-4' // database
                        if (c.includes('auth')) return 'M12 2C9.24 2 7 4.24 7 7c0 1.81 0.97 3.4 2.41 4.28L8 22h8l-1.41-10.72C15.03 10.4 16 8.81 16 7c0-2.76-2.24-5-4-5z' // fingerprint-ish
                        if (c.includes('crypto')) return 'M12 2a5 5 0 015 5v3H7V7a5 5 0 015-5zM5 10h14a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2v-8a2 2 0 012-2z' // lock
                        if (c.includes('code') || c.includes('integrity')) return 'M9 9l-7 3 7 3M15 9l7 3-7 3M11 2l2 20' // code
                        if (c.includes('perm') || c.includes('priv')) return 'M15 12a3 3 0 11-6 0 3 3 0 016 0zM2 12s4-8 10-8 10 8 10 8-4 8-10 8-10-8-10-8z' // eye
                        return 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z' // star
                      }

                      return (
                        <div className="glassmorphism rounded-xl cyber-border overflow-hidden">
                          {/* Header */}
                          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/60">
                            <div className="flex items-center gap-2">
                              <Map className="w-4 h-4 text-cyan-400" />
                              <h3 className="text-white font-semibold">Attack Surface Map</h3>
                            </div>
                            <div className="flex items-center gap-3 text-xs">
                              <span className="flex items-center gap-1.5 text-slate-500"><span className="w-3 h-0.5 bg-red-500 inline-block rounded" />Exposed</span>
                              <span className="flex items-center gap-1.5 text-slate-500"><span className="w-3 h-0.5 bg-green-500 inline-block rounded border-dashed" style={{borderTop:'1px dashed #22c55e',background:'none'}} />Protected</span>
                              <span className="text-slate-600">·</span>
                              <span className="text-slate-500">Click a node for details</span>
                            </div>
                          </div>

                          {/* SVG canvas */}
                          <div className="bg-[#070b14] relative">
                            <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" style={{ maxHeight: 520 }}>
                              <defs>
                                {/* Node glow filter */}
                                <filter id="glow" x="-40%" y="-40%" width="180%" height="180%">
                                  <feGaussianBlur stdDeviation="5" result="blur" />
                                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                                </filter>
                                {/* Center glow */}
                                <filter id="centerglow" x="-60%" y="-60%" width="220%" height="220%">
                                  <feGaussianBlur stdDeviation="10" result="blur" />
                                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                                </filter>
                                {/* Grid pattern */}
                                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" />
                                </pattern>
                                {/* Radial gradient for center */}
                                <radialGradient id="centerGrad" cx="50%" cy="50%" r="50%">
                                  <stop offset="0%" stopColor="#4c1d95" />
                                  <stop offset="100%" stopColor="#1e1b4b" />
                                </radialGradient>
                                {/* Node gradients per severity */}
                                {nodes.map((_n: any, i: number) => {
                                  const c = sevHex(_n.severity, _n.exposed)
                                  return (
                                    <radialGradient key={i} id={`ng${i}`} cx="50%" cy="0%" r="100%">
                                      <stop offset="0%" stopColor={c} stopOpacity="0.15" />
                                      <stop offset="100%" stopColor="#0f172a" stopOpacity="1" />
                                    </radialGradient>
                                  )
                                })}
                              </defs>

                              {/* Grid background */}
                              <rect width={W} height={H} fill="url(#grid)" />

                              {/* Soft radial vignette */}
                              <radialGradient id="vig" cx="50%" cy="50%" r="70%">
                                <stop offset="0%" stopColor="transparent" />
                                <stop offset="100%" stopColor="#070b14" stopOpacity="0.7" />
                              </radialGradient>
                              <rect width={W} height={H} fill="url(#vig)" />

                              {/* Orbit rings */}
                              <circle cx={cx} cy={cy} r={orbR - 2} fill="none" stroke="#1e3a5f" strokeWidth="1" strokeOpacity="0.3" strokeDasharray="3 7" />
                              <circle cx={cx} cy={cy} r={orbR + 20} fill="none" stroke="#1e2d40" strokeWidth="0.5" strokeOpacity="0.2" />

                              {/* Connection curves */}
                              {nodes.map((n: any, i: number) => {
                                const color = sevHex(n.severity, n.exposed)
                                const isHit = selectedSurface === i
                                const { path, x2, y2, ux, uy } = curvePath(n)
                                return (
                                  <g key={i}>
                                    {/* Glow copy */}
                                    <path d={path} fill="none"
                                      stroke={color} strokeWidth={isHit ? 6 : 3}
                                      strokeOpacity={isHit ? 0.25 : 0.1}
                                      strokeDasharray={n.exposed ? undefined : '6 5'}
                                    />
                                    {/* Main line */}
                                    <path d={path} fill="none"
                                      stroke={color} strokeWidth={isHit ? 2 : 1.2}
                                      strokeOpacity={isHit ? 0.9 : n.exposed ? 0.55 : 0.3}
                                      strokeDasharray={n.exposed ? undefined : '6 5'}
                                    />
                                    {/* Arrowhead */}
                                    <polygon points={arrowPoints(x2, y2, ux, uy)}
                                      fill={color}
                                      fillOpacity={isHit ? 0.9 : n.exposed ? 0.55 : 0.3}
                                    />
                                  </g>
                                )
                              })}

                              {/* Center node */}
                              <g filter="url(#centerglow)">
                                <circle cx={cx} cy={cy} r={52} fill="url(#centerGrad)" stroke="#7c3aed" strokeWidth="2" />
                                <circle cx={cx} cy={cy} r={44} fill="none" stroke="#a78bfa" strokeWidth="0.5" strokeOpacity="0.5" />
                              </g>
                              <text x={cx} y={cy - 7} textAnchor="middle" fill="#f1f5f9" fontSize="15" fontWeight="800" letterSpacing="0.02em">TARGET</text>
                              <text x={cx} y={cy + 13} textAnchor="middle" fill="#a78bfa" fontSize="11" fontWeight="500" letterSpacing="0.08em">APK</text>

                              {/* Category nodes */}
                              {nodes.map((n: any, i: number) => {
                                const color = sevHex(n.severity, n.exposed)
                                const glow = sevGlow(n.severity, n.exposed)
                                const isHit = selectedSurface === i
                                const label = n.category as string

                                // Smart word-wrap at natural break
                                let lines: string[]
                                const words = label.split(/[\s&]+/)
                                if (words.length <= 2) {
                                  lines = [label]
                                } else {
                                  const half = Math.ceil(words.length / 2)
                                  lines = [words.slice(0, half).join(' '), words.slice(half).join(' ')]
                                }
                                const two = lines.length === 2

                                return (
                                  <g key={i} style={{ cursor: 'pointer' }} onClick={() => setSelectedSurface(isHit ? null : i)}>
                                    {/* Outer glow halo when selected */}
                                    {isHit && (
                                      <rect
                                        x={n.nx - nW / 2 - 8} y={n.ny - nH / 2 - 8}
                                        width={nW + 16} height={nH + 16} rx={16}
                                        fill={glow} fillOpacity="0.12"
                                        stroke={color} strokeWidth="1" strokeOpacity="0.4"
                                      />
                                    )}
                                    {/* Node body */}
                                    <rect
                                      x={n.nx - nW / 2} y={n.ny - nH / 2}
                                      width={nW} height={nH} rx={10}
                                      fill={`url(#ng${i})`}
                                      stroke={color}
                                      strokeWidth={isHit ? 2 : 1.5}
                                      strokeOpacity={isHit ? 1 : 0.7}
                                    />
                                    {/* Top accent bar */}
                                    <rect
                                      x={n.nx - nW / 2 + 12} y={n.ny - nH / 2}
                                      width={nW - 24} height={2} rx={1}
                                      fill={color} fillOpacity={isHit ? 0.9 : 0.5}
                                    />
                                    {/* Category label */}
                                    {two ? (
                                      <>
                                        <text x={n.nx} y={n.ny - 18} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="700">{lines[0]}</text>
                                        <text x={n.nx} y={n.ny - 5} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="700">{lines[1]}</text>
                                      </>
                                    ) : (
                                      <text x={n.nx} y={n.ny - 10} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="700">{lines[0]}</text>
                                    )}
                                    {/* Severity pill */}
                                    <rect
                                      x={n.nx - 38} y={n.ny + (two ? 8 : 6)}
                                      width={76} height={18} rx={5}
                                      fill={color} fillOpacity="0.18"
                                      stroke={color} strokeWidth="1" strokeOpacity="0.7"
                                    />
                                    <text
                                      x={n.nx} y={n.ny + (two ? 21 : 19)}
                                      textAnchor="middle" fill={color}
                                      fontSize="9" fontWeight="800" letterSpacing="0.08em"
                                    >
                                      {n.exposed ? (n.severity || 'EXPOSED').toUpperCase() : 'SAFE'}
                                    </text>
                                    {/* Hover/select highlight ring */}
                                    <rect
                                      x={n.nx - nW / 2} y={n.ny - nH / 2}
                                      width={nW} height={nH} rx={10}
                                      fill="transparent"
                                      stroke="white"
                                      strokeWidth={isHit ? 1 : 0}
                                      strokeOpacity="0.06"
                                    />
                                  </g>
                                )
                              })}
                            </svg>
                          </div>

                          {/* Detail panel */}
                          <div className={`transition-all duration-300 overflow-hidden ${selNode ? 'max-h-40' : 'max-h-0'}`}>
                            {selNode && (
                              <div className={`px-6 py-4 border-t flex items-start gap-4 ${
                                !selNode.exposed
                                  ? 'border-green-500/20 bg-green-500/5'
                                  : selNode.severity === 'critical' ? 'border-red-500/20 bg-red-950/30'
                                  : selNode.severity === 'high'     ? 'border-orange-500/20 bg-orange-950/20'
                                  : selNode.severity === 'medium'   ? 'border-yellow-500/20 bg-yellow-950/20'
                                  : 'border-slate-600/30 bg-slate-800/20'
                              }`}>
                                <div className={`shrink-0 w-8 h-8 rounded-lg flex items-center justify-center border ${
                                  !selNode.exposed
                                    ? 'bg-green-500/15 border-green-500/30'
                                    : selNode.severity === 'critical' ? 'bg-red-500/15 border-red-500/30'
                                    : selNode.severity === 'high'     ? 'bg-orange-500/15 border-orange-500/30'
                                    : selNode.severity === 'medium'   ? 'bg-yellow-500/15 border-yellow-500/30'
                                    : 'bg-slate-700 border-slate-600'
                                }`}>
                                  <span className={`text-xs font-black ${
                                    !selNode.exposed ? 'text-green-400'
                                    : selNode.severity === 'critical' ? 'text-red-400'
                                    : selNode.severity === 'high'     ? 'text-orange-400'
                                    : selNode.severity === 'medium'   ? 'text-yellow-400'
                                    : 'text-slate-400'
                                  }`}>
                                    {!selNode.exposed ? '✓' : selNode.severity?.charAt(0).toUpperCase() || '!'}
                                  </span>
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-1">
                                    <h4 className="text-white font-semibold text-sm">{selNode.category}</h4>
                                    <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold ${
                                      !selNode.exposed
                                        ? 'bg-green-500/20 text-green-400 border-green-500/30'
                                        : severityColor(selNode.severity)
                                    }`}>
                                      {!selNode.exposed ? 'SAFE' : (selNode.severity || 'EXPOSED').toUpperCase()}
                                    </span>
                                  </div>
                                  <p className="text-slate-400 text-sm leading-relaxed">{selNode.description}</p>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )
                    })()}

                    {/* ── MITRE ATT&CK Mapping ── */}
                    {report.mitre_techniques?.length > 0 && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-4">
                          <Crosshair className="w-4 h-4 text-red-400" />
                          <h3 className="text-white font-semibold">MITRE ATT&CK Mapping</h3>
                          <span className="text-xs text-slate-500 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded-full">{report.mitre_techniques.length} techniques</span>
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          {report.mitre_techniques.map((t: any, i: number) => (
                            <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                              <div className="flex items-start justify-between gap-2 mb-2">
                                <code className="text-cyan-400 text-xs font-mono bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded shrink-0">{t.id}</code>
                                <span className="text-xs text-purple-400 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded-full text-right">{t.tactic}</span>
                              </div>
                              <p className="text-slate-200 text-sm font-medium mb-1">{t.name}</p>
                              <p className="text-slate-500 text-xs leading-relaxed">{t.relevance}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* ── Threat Intelligence Profile ── */}
                    {report.threat_intel && (
                      <div className="glassmorphism p-6 rounded-lg border border-orange-500/20 bg-orange-500/5">
                        <div className="flex items-center gap-2 mb-4">
                          <Globe className="w-4 h-4 text-orange-400" />
                          <h3 className="text-white font-semibold">Threat Intelligence Profile</h3>
                        </div>
                        <div className="grid grid-cols-3 gap-4 mb-4">
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Actor Profile</p>
                            <p className="text-slate-200 text-sm">{report.threat_intel.actor_profile}</p>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Attack Likelihood</p>
                            <p className={`text-sm font-bold uppercase ${likelihoodColor(report.threat_intel.attack_likelihood)}`}>{report.threat_intel.attack_likelihood}</p>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Motivation</p>
                            <p className="text-slate-200 text-sm">{report.threat_intel.motivation}</p>
                          </div>
                        </div>
                        {report.threat_intel.ioc_patterns?.length > 0 && (
                          <div>
                            <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">IoC Patterns</p>
                            <div className="flex flex-wrap gap-2">
                              {report.threat_intel.ioc_patterns.map((p: string, i: number) => (
                                <span key={i} className="bg-orange-500/10 border border-orange-500/20 text-orange-300 text-xs px-3 py-1.5 rounded-full">{p}</span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* ── Attack Scenario ── */}
                    {report.attack_scenario && (
                      <div className="glassmorphism p-6 rounded-lg border border-red-500/20 bg-red-500/5">
                        <div className="flex items-center gap-2 mb-3">
                          <Target className="w-4 h-4 text-red-400" />
                          <h3 className="text-white font-semibold">Attack Scenario</h3>
                          <span className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">Simulated exploitation chain</span>
                        </div>
                        <pre className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap font-sans">{report.attack_scenario}</pre>
                      </div>
                    )}

                    {/* ── AI Severity Adjustments ── */}
                    {report.re_scored_findings?.length > 0 && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-4">
                          <Sparkles className="w-4 h-4 text-amber-400" />
                          <h3 className="text-white font-semibold">AI Severity Adjustments</h3>
                          <span className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full">{report.re_scored_findings.length} re-scored</span>
                        </div>
                        <div className="space-y-3">
                          {report.re_scored_findings.map((f: any, i: number) => (
                            <div key={i} className="bg-slate-800/50 p-4 rounded-lg border border-slate-700 grid grid-cols-[1fr_auto_auto] gap-4 items-center">
                              <div>
                                <p className="text-slate-200 text-sm font-medium">{f.title}</p>
                                <p className="text-slate-500 text-xs mt-1">{f.reason}</p>
                              </div>
                              <span className={`px-2 py-0.5 rounded-full text-xs border line-through opacity-60 ${severityColor(f.original_severity)}`}>{(f.original_severity || '').toUpperCase()}</span>
                              <span className={`px-2 py-0.5 rounded-full text-xs border font-semibold ${severityColor(f.ai_severity)}`}>{(f.ai_severity || '').toUpperCase()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* ── Finding Deep-Dives ── */}
                    {report.finding_analyses?.length > 0 && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-4">
                          <Code2 className="w-4 h-4 text-cyan-400" />
                          <h3 className="text-white font-semibold">Finding Deep-Dives</h3>
                        </div>
                        <div className="space-y-3">
                          {report.finding_analyses.map((f: any, i: number) => (
                            <details key={i} className="group bg-slate-800/50 rounded-lg border border-slate-700 overflow-hidden">
                              <summary className="flex items-center gap-3 p-4 cursor-pointer hover:bg-slate-700/40 transition list-none">
                                <span className={`px-2 py-0.5 rounded-full text-xs border shrink-0 ${severityColor(f.severity)}`}>{(f.severity || '').toUpperCase()}</span>
                                <span className="text-slate-200 text-sm font-medium flex-1">{f.title}</span>
                                <ChevronDown className="w-4 h-4 text-slate-500 group-open:rotate-180 transition-transform shrink-0" />
                              </summary>
                              <div className="px-4 pb-4 space-y-3 border-t border-slate-700 pt-4">
                                {f.technical_analysis && (
                                  <div>
                                    <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Technical Analysis</p>
                                    <p className="text-slate-300 text-sm leading-relaxed">{f.technical_analysis}</p>
                                  </div>
                                )}
                                {f.attack_vector && (
                                  <div className="bg-red-500/5 border border-red-500/20 rounded p-3">
                                    <p className="text-xs text-red-400 uppercase tracking-wide mb-1">Attack Vector</p>
                                    <p className="text-slate-300 text-sm">{f.attack_vector}</p>
                                  </div>
                                )}
                                {f.code_fix && (
                                  <div>
                                    <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Recommended Fix</p>
                                    <pre className="text-sm text-cyan-300 bg-slate-900/60 p-3 rounded border border-slate-700 overflow-x-auto whitespace-pre-wrap font-mono">{f.code_fix}</pre>
                                  </div>
                                )}
                              </div>
                            </details>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* ── Remediation Roadmap ── */}
                    {report.remediation_roadmap?.length > 0 && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-4">
                          <TrendingUp className="w-4 h-4 text-emerald-400" />
                          <h3 className="text-white font-semibold">Remediation Roadmap</h3>
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="border-b border-slate-700 text-left">
                                <th className="pb-3 pr-3 text-xs text-slate-500 uppercase tracking-wide w-8">#</th>
                                <th className="pb-3 text-xs text-slate-500 uppercase tracking-wide">Action</th>
                                <th className="pb-3 px-3 text-xs text-slate-500 uppercase tracking-wide w-20">Effort</th>
                                <th className="pb-3 px-3 text-xs text-slate-500 uppercase tracking-wide w-20">Impact</th>
                                <th className="pb-3 pl-3 text-xs text-slate-500 uppercase tracking-wide w-28">Category</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/60">
                              {report.remediation_roadmap.map((item: any, i: number) => (
                                <tr key={i} className="hover:bg-slate-800/30 transition">
                                  <td className="py-3 pr-3">
                                    <span className={`w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${
                                      item.priority === 1 ? 'bg-red-500/20 text-red-400' :
                                      item.priority === 2 ? 'bg-orange-500/20 text-orange-400' :
                                      'bg-slate-700 text-slate-400'
                                    }`}>{item.priority}</span>
                                  </td>
                                  <td className="py-3 pr-4 text-slate-300 text-sm leading-snug">{item.action}</td>
                                  <td className="py-3 px-3"><span className={`text-xs px-2 py-0.5 rounded-full border ${effortColor(item.effort)}`}>{item.effort}</span></td>
                                  <td className="py-3 px-3"><span className={`text-xs px-2 py-0.5 rounded-full border ${impactColor(item.impact)}`}>{item.impact}</span></td>
                                  <td className="py-3 pl-3"><span className="text-xs text-slate-500 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded-full">{item.category}</span></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {/* ── Top Recommendations ── */}
                    {report.top_recommendations?.length > 0 && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-4">
                          <ListChecks className="w-4 h-4 text-green-400" />
                          <h3 className="text-white font-semibold">Top Recommendations</h3>
                        </div>
                        <ol className="space-y-2">
                          {report.top_recommendations.map((rec: string, i: number) => (
                            <li key={i} className="flex items-start gap-3 text-sm text-slate-300">
                              <span className="shrink-0 w-5 h-5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 flex items-center justify-center text-xs font-bold">{i + 1}</span>
                              <span className="leading-relaxed pt-0.5">{rec}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}

                    {/* ── Compliance Impact ── */}
                    {report.compliance_impact && (
                      <div className="glassmorphism p-6 rounded-lg cyber-border">
                        <div className="flex items-center gap-2 mb-3">
                          <ShieldCheck className="w-4 h-4 text-blue-400" />
                          <h3 className="text-white font-semibold">Compliance Impact</h3>
                        </div>
                        <p className="text-slate-300 text-sm leading-relaxed">{report.compliance_impact}</p>
                      </div>
                    )}

                  </div>
                )}
              </>
            )
          })()}
        </TabsContent>
        </Tabs>

      {/* File Viewer Modal */}
      {viewingFile && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setViewingFile(null)}>
          <div className="glassmorphism rounded-lg cyber-border max-w-5xl w-full max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-slate-700">
              <div className="flex-1 min-w-0">
                <h3 className="text-white font-semibold truncate">{viewingFile.path}</h3>
                <p className="text-slate-400 text-sm mt-1">
                  {viewingFile.type === 'java' ? 'Decompiled Java Source' : 
                   viewingFile.type === 'xml' ? 'XML Configuration' : 'Text File'}
                </p>
              </div>
              <button
                onClick={() => setViewingFile(null)}
                className="ml-4 p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            {/* Modal Content */}
            <div className="flex-1 overflow-auto p-4">
              <pre className="text-sm text-slate-300 font-mono bg-slate-900/50 p-4 rounded-lg overflow-x-auto">
                <code className={viewingFile.type === 'java' ? 'language-java' : viewingFile.type === 'xml' ? 'language-xml' : 'language-text'}>
                  {viewingFile.content}
                </code>
              </pre>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 p-4 border-t border-slate-700">
              <Button
                onClick={() => {
                  navigator.clipboard.writeText(viewingFile.content)
                  toast({ title: "Copied", description: "Content copied to clipboard" })
                }}
                className="bg-slate-700 hover:bg-slate-600"
              >
                <Copy className="w-4 h-4 mr-2" />
                Copy
              </Button>
              <Button
                onClick={() => setViewingFile(null)}
                className="bg-cyan-500 hover:bg-cyan-600 text-slate-950"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Rescan Confirmation Dialog */}
      <ConfirmDialog
        open={showRescanConfirm}
        onOpenChange={setShowRescanConfirm}
        title="Rescan Analysis?"
        description={`Are you sure you want to rescan ${scan?.app_name}? This will clear all previous analysis results and run a fresh security analysis.`}
        variant="warning"
        confirmText="Yes, Rescan"
        cancelText="Cancel"
        onConfirm={performRescan}
      />

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={showDeleteConfirm}
        onOpenChange={setShowDeleteConfirm}
        title="Delete Scan?"
        description={`Are you sure you want to delete the scan for ${scan?.app_name}? The APK file will also be permanently deleted from the server. This action cannot be undone.`}
        variant="destructive"
        confirmText="Yes, Delete"
        cancelText="Cancel"
        onConfirm={performDelete}
      />

      {/* Processing Dialog */}
      <ProcessingDialog
        open={showProcessing}
        title={processingTitle}
        description={processingMessage}
      />

      {/* Success Dialog */}
      <InfoDialog
        open={showSuccessDialog}
        onOpenChange={setShowSuccessDialog}
        title="Rescan Started"
        description={successMessage}
        variant="success"
      />
    </div>
  )
}
